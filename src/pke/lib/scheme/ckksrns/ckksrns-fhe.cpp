//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2025, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

#define PROFILE

#include "ciphertext.h"
#include "cryptocontext.h"
#include "key/privatekey.h"
#include "lattice/lat-hal.h"
#include "math/hal/basicint.h"
#include "math/dftransform.h"
#include "scheme/ckksrns/ckksrns-cryptoparameters.h"
#include "scheme/ckksrns/ckksrns-fhe.h"
#include "scheme/ckksrns/ckksrns-utils.h"
#include "schemebase/base-scheme.h"
#include "utils/exception.h"
#include "utils/parallel.h"
#include "utils/utilities.h"

#include <algorithm>
#include <cmath>
#ifdef BOOTSTRAPTIMING
    #include <iostream>
#endif
#include <limits>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <functional>
#include <set>

namespace {
// GetBigModulus() calculates the big modulus as the product of
// the "compositeDegree" number of parameter modulus
double GetBigModulus(const std::shared_ptr<lbcrypto::CryptoParametersCKKSRNS> cryptoParams) {
    double qDouble           = 1.0;
    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();
    for (uint32_t j = 0; j < compositeDegree; ++j) {
        qDouble *= cryptoParams->GetElementParams()->GetParams()[j]->GetModulus().ConvertToDouble();
    }

    return qDouble;
}
}  // namespace
namespace lbcrypto {

//------------------------------------------------------------------------------
// Bootstrap Wrapper
//------------------------------------------------------------------------------

void FHECKKSRNS::EvalBootstrapSetup(const CryptoContextImpl<DCRTPoly>& cc, std::vector<uint32_t> levelBudget,
                                    std::vector<uint32_t> dim1, uint32_t numSlots, uint32_t correctionFactor,
                                    bool precompute) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());

    if (cryptoParams->GetKeySwitchTechnique() != HYBRID)
        OPENFHE_THROW("CKKS Bootstrapping is only supported for the Hybrid key switching method.");
#if NATIVEINT == 128
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO || cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        OPENFHE_THROW("128-bit CKKS Bootstrapping is supported for FIXEDMANUAL and FIXEDAUTO methods only.");
#endif

    uint32_t M     = cc.GetCyclotomicOrder();
    uint32_t slots = (numSlots == 0) ? M / 4 : numSlots;

    // Set correction factor by default, if it is not already set.
    if (correctionFactor == 0) {
        if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO ||
            cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT ||
            cryptoParams->GetScalingTechnique() == COMPOSITESCALINGAUTO ||
            cryptoParams->GetScalingTechnique() == COMPOSITESCALINGMANUAL) {
            // The default correction factors chosen yielded the best precision in our experiments.
            // We chose the best fit line from our experiments by running ckks-bootstrapping-precision.cpp.
            // The spreadsheet with our experiments is here:
            // https://docs.google.com/spreadsheets/d/1WqmwBUMNGlX6Uvs9qLXt5yeddtCyWPP55BbJPu5iPAM/edit?usp=sharing
            auto tmp = std::round(-0.265 * (2 * std::log2(M / 2) + std::log2(slots)) + 19.1);
            if (tmp < 7)
                m_correctionFactor = 7;
            else if (tmp > 13)
                m_correctionFactor = 13;
            else
                m_correctionFactor = static_cast<uint32_t>(tmp);
        }
        else {
            m_correctionFactor = 9;
        }
    }
    else {
        m_correctionFactor = correctionFactor;
    }
    m_bootPrecomMap[slots]                      = std::make_shared<CKKSBootstrapPrecom>();
    std::shared_ptr<CKKSBootstrapPrecom> precom = m_bootPrecomMap[slots];

    precom->m_slots = slots;
    precom->m_dim1  = dim1[0];

    uint32_t logSlots = std::log2(slots);
    // even for the case of a single slot we need one level for rescaling
    if (logSlots == 0) {
        logSlots = 1;
    }

    // Perform some checks on the level budget and compute parameters
    std::vector<uint32_t> newBudget = levelBudget;

    if (newBudget[0] > logSlots) {
        std::cerr << "\nWarning, the level budget for encoding is too large. Setting it to " << logSlots << std::endl;
        newBudget[0] = logSlots;
    }
    if (newBudget[0] < 1) {
        std::cerr << "\nWarning, the level budget for encoding can not be zero. Setting it to 1" << std::endl;
        newBudget[0] = 1;
    }

    if (newBudget[1] > logSlots) {
        std::cerr << "\nWarning, the level budget for decoding is too large. Setting it to " << logSlots << std::endl;
        newBudget[1] = logSlots;
    }
    if (newBudget[1] < 1) {
        std::cerr << "\nWarning, the level budget for decoding can not be zero. Setting it to 1" << std::endl;
        newBudget[1] = 1;
    }

    precom->m_paramsEnc = GetCollapsedFFTParams(slots, newBudget[0], dim1[0]);
    precom->m_paramsDec = GetCollapsedFFTParams(slots, newBudget[1], dim1[1]);

    if (precompute) {
        uint32_t m    = 4 * slots;
        bool isSparse = (M != m) ? true : false;

        // computes indices for all primitive roots of unity
        std::vector<uint32_t> rotGroup(slots);
        uint32_t fivePows = 1;
        for (uint32_t i = 0; i < slots; ++i) {
            rotGroup[i] = fivePows;
            fivePows *= 5;
            fivePows %= m;
        }

        // computes all powers of a primitive root of unity exp(2 * M_PI/m)
        std::vector<std::complex<double>> ksiPows(m + 1);
        for (uint32_t j = 0; j < m; ++j) {
            double angle = 2.0 * M_PI * j / m;
            ksiPows[j].real(cos(angle));
            ksiPows[j].imag(sin(angle));
        }
        ksiPows[m] = ksiPows[0];

        uint32_t compositeDegree = cryptoParams->GetCompositeDegree();

        // Extract the modulus prior to bootstrapping
        double qDouble = GetBigModulus(cryptoParams);

        uint128_t factor = ((uint128_t)1 << (static_cast<uint32_t>(std::round(std::log2(qDouble)))));
        double pre       = (compositeDegree > 1) ? 1.0 : qDouble / factor;
        double k         = (cryptoParams->GetSecretKeyDist() == SPARSE_TERNARY) ? K_SPARSE : 1.0;
        double scaleEnc  = pre / k;
        // TODO: YSP Can be extended to FLEXIBLE* scaling techniques as well as the closeness of 2^p to moduli is no longer needed
        double scaleDec = (compositeDegree > 1) ? qDouble / cryptoParams->GetScalingFactorReal(0) : 1 / pre;

        uint32_t approxModDepth = GetModDepthInternal(cryptoParams->GetSecretKeyDist());
        uint32_t depthBT        = approxModDepth + precom->m_paramsEnc[CKKS_BOOT_PARAMS::LEVEL_BUDGET] +
                           precom->m_paramsDec[CKKS_BOOT_PARAMS::LEVEL_BUDGET];

        // compute # of levels to remain when encoding the coefficients
        uint32_t L0 = cryptoParams->GetElementParams()->GetParams().size();
        // for FLEXIBLEAUTOEXT we do not need extra modulus in auxiliary plaintexts
        if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
            L0 -= 1;
        uint32_t lEnc = L0 - compositeDegree * (precom->m_paramsEnc[CKKS_BOOT_PARAMS::LEVEL_BUDGET] + 1);
        uint32_t lDec = L0 - compositeDegree * depthBT;

        bool isLTBootstrap = (precom->m_paramsEnc[CKKS_BOOT_PARAMS::LEVEL_BUDGET] == 1) &&
                             (precom->m_paramsDec[CKKS_BOOT_PARAMS::LEVEL_BUDGET] == 1);

        if (isLTBootstrap) {
            // allocate all vectors
            std::vector<std::vector<std::complex<double>>> U0(slots, std::vector<std::complex<double>>(slots));
            std::vector<std::vector<std::complex<double>>> U1(slots, std::vector<std::complex<double>>(slots));
            std::vector<std::vector<std::complex<double>>> U0hatT(slots, std::vector<std::complex<double>>(slots));
            std::vector<std::vector<std::complex<double>>> U1hatT(slots, std::vector<std::complex<double>>(slots));

            for (size_t i = 0; i < slots; i++) {
                for (size_t j = 0; j < slots; j++) {
                    U0[i][j]     = ksiPows[(j * rotGroup[i]) % m];
                    U0hatT[j][i] = std::conj(U0[i][j]);
                    U1[i][j]     = std::complex<double>(0, 1) * U0[i][j];
                    U1hatT[j][i] = std::conj(U1[i][j]);
                }
            }

            if (!isSparse) {
                precom->m_U0hatTPre = EvalLinearTransformPrecompute(cc, U0hatT, scaleEnc, lEnc);
                precom->m_U0Pre     = EvalLinearTransformPrecompute(cc, U0, scaleDec, lDec);
            }
            else {
                precom->m_U0hatTPre = EvalLinearTransformPrecompute(cc, U0hatT, U1hatT, 0, scaleEnc, lEnc);
                precom->m_U0Pre     = EvalLinearTransformPrecompute(cc, U0, U1, 1, scaleDec, lDec);
            }
        }
        else {
            precom->m_U0hatTPreFFT = EvalCoeffsToSlotsPrecompute(cc, ksiPows, rotGroup, false, scaleEnc, lEnc);
            precom->m_U0PreFFT     = EvalSlotsToCoeffsPrecompute(cc, ksiPows, rotGroup, false, scaleDec, lDec);
        }
    }
}

std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>> FHECKKSRNS::EvalBootstrapKeyGen(
    const PrivateKey<DCRTPoly> privateKey, uint32_t slots) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(privateKey->GetCryptoParameters());

    if (cryptoParams->GetKeySwitchTechnique() != HYBRID)
        OPENFHE_THROW("CKKS Bootstrapping is only supported for the Hybrid key switching method.");
#if NATIVEINT == 128
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO || cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        OPENFHE_THROW("128-bit CKKS Bootstrapping is supported for FIXEDMANUAL and FIXEDAUTO methods only.");
#endif
    auto cc    = privateKey->GetCryptoContext();
    uint32_t M = cc->GetCyclotomicOrder();

    if (slots == 0)
        slots = M / 4;
    // computing all indices for baby-step giant-step procedure
    auto algo     = cc->GetScheme();
    auto evalKeys = algo->EvalAtIndexKeyGen(nullptr, privateKey, FindBootstrapRotationIndices(slots, M));

    auto conjKey       = ConjugateKeyGen(privateKey);
    (*evalKeys)[M - 1] = conjKey;

    return evalKeys;
}

void FHECKKSRNS::EvalBootstrapPrecompute(const CryptoContextImpl<DCRTPoly>& cc, uint32_t numSlots) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());

    if (cryptoParams->GetKeySwitchTechnique() != HYBRID)
        OPENFHE_THROW("CKKS Bootstrapping is only supported for the Hybrid key switching method.");
#if NATIVEINT == 128
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO || cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        OPENFHE_THROW("128-bit CKKS Bootstrapping is supported for FIXEDMANUAL and FIXEDAUTO methods only.");
#endif

    uint32_t M     = cc.GetCyclotomicOrder();
    uint32_t slots = (numSlots == 0) ? M / 4 : numSlots;

    std::shared_ptr<CKKSBootstrapPrecom> precom = m_bootPrecomMap[slots];

    std::vector<uint32_t> dim1(
        {precom->m_dim1, static_cast<uint32_t>(precom->m_paramsDec[CKKS_BOOT_PARAMS::GIANT_STEP])});
    std::vector<uint32_t> newBudget({static_cast<uint32_t>(precom->m_paramsEnc[CKKS_BOOT_PARAMS::LEVEL_BUDGET]),
                                     static_cast<uint32_t>(precom->m_paramsDec[CKKS_BOOT_PARAMS::LEVEL_BUDGET])});

    precom->m_paramsEnc = GetCollapsedFFTParams(slots, newBudget[0], dim1[0]);
    precom->m_paramsDec = GetCollapsedFFTParams(slots, newBudget[1], dim1[1]);

    uint32_t m    = 4 * slots;
    bool isSparse = (M != m) ? true : false;

    // computes indices for all primitive roots of unity
    std::vector<uint32_t> rotGroup(slots);
    uint32_t fivePows = 1;
    for (uint32_t i = 0; i < slots; ++i) {
        rotGroup[i] = fivePows;
        fivePows *= 5;
        fivePows %= m;
    }

    // computes all powers of a primitive root of unity exp(2 * M_PI/m)
    std::vector<std::complex<double>> ksiPows(m + 1);
    for (uint32_t j = 0; j < m; ++j) {
        double angle = 2.0 * M_PI * j / m;
        ksiPows[j].real(cos(angle));
        ksiPows[j].imag(sin(angle));
    }
    ksiPows[m] = ksiPows[0];

    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();

    // Extract the modulus prior to bootstrapping
    double qDouble = GetBigModulus(cryptoParams);

    uint128_t factor = ((uint128_t)1 << (static_cast<uint32_t>(std::round(std::log2(qDouble)))));
    double pre       = qDouble / factor;
    double k         = (cryptoParams->GetSecretKeyDist() == SPARSE_TERNARY) ? K_SPARSE : 1.0;
    double scaleEnc  = (compositeDegree > 1) ? 1.0 / k : pre / k;
    double scaleDec  = (compositeDegree > 1) ? k * qDouble / cryptoParams->GetScalingFactorReal(0) : 1 / pre;

    uint32_t approxModDepth = GetModDepthInternal(cryptoParams->GetSecretKeyDist());
    uint32_t depthBT        = approxModDepth + precom->m_paramsEnc[CKKS_BOOT_PARAMS::LEVEL_BUDGET] +
                       precom->m_paramsDec[CKKS_BOOT_PARAMS::LEVEL_BUDGET];

    // compute # of levels to remain when encoding the coefficients
    uint32_t L0 = cryptoParams->GetElementParams()->GetParams().size();
    // for FLEXIBLEAUTOEXT we do not need extra modulus in auxiliary plaintexts
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        L0 -= 1;
    uint32_t lEnc = L0 - compositeDegree * (precom->m_paramsEnc[CKKS_BOOT_PARAMS::LEVEL_BUDGET] + 1);
    uint32_t lDec = L0 - compositeDegree * depthBT;

    bool isLTBootstrap = (precom->m_paramsEnc[CKKS_BOOT_PARAMS::LEVEL_BUDGET] == 1) &&
                         (precom->m_paramsDec[CKKS_BOOT_PARAMS::LEVEL_BUDGET] == 1);

    if (isLTBootstrap) {
        // allocate all vectors
        std::vector<std::vector<std::complex<double>>> U0(slots, std::vector<std::complex<double>>(slots));
        std::vector<std::vector<std::complex<double>>> U1(slots, std::vector<std::complex<double>>(slots));
        std::vector<std::vector<std::complex<double>>> U0hatT(slots, std::vector<std::complex<double>>(slots));
        std::vector<std::vector<std::complex<double>>> U1hatT(slots, std::vector<std::complex<double>>(slots));

        for (size_t i = 0; i < slots; i++) {
            for (size_t j = 0; j < slots; j++) {
                U0[i][j]     = ksiPows[(j * rotGroup[i]) % m];
                U0hatT[j][i] = std::conj(U0[i][j]);
                U1[i][j]     = std::complex<double>(0, 1) * U0[i][j];
                U1hatT[j][i] = std::conj(U1[i][j]);
            }
        }

        if (!isSparse) {
            precom->m_U0hatTPre = EvalLinearTransformPrecompute(cc, U0hatT, scaleEnc, lEnc);
            precom->m_U0Pre     = EvalLinearTransformPrecompute(cc, U0, scaleDec, lDec);
        }
        else {
            precom->m_U0hatTPre = EvalLinearTransformPrecompute(cc, U0hatT, U1hatT, 0, scaleEnc, lEnc);
            precom->m_U0Pre     = EvalLinearTransformPrecompute(cc, U0, U1, 1, scaleDec, lDec);
        }
    }
    else {
        precom->m_U0hatTPreFFT = EvalCoeffsToSlotsPrecompute(cc, ksiPows, rotGroup, false, scaleEnc, lEnc);
        precom->m_U0PreFFT     = EvalSlotsToCoeffsPrecompute(cc, ksiPows, rotGroup, false, scaleDec, lDec);
    }
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalBootstrap(ConstCiphertext<DCRTPoly> ciphertext, uint32_t numIterations,
                                               uint32_t precision) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());

    if (cryptoParams->GetKeySwitchTechnique() != HYBRID)
        OPENFHE_THROW("CKKS Bootstrapping is only supported for the Hybrid key switching method.");
#if NATIVEINT == 128
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO || cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        OPENFHE_THROW("128-bit CKKS Bootstrapping is supported for FIXEDMANUAL and FIXEDAUTO methods only.");
#endif
    if (numIterations != 1 && numIterations != 2) {
        OPENFHE_THROW("CKKS Iterative Bootstrapping is only supported for 1 or 2 iterations.");
    }

#ifdef BOOTSTRAPTIMING
    TimeVar t;
    double timeEncode(0.0);
    double timeModReduce(0.0);
    double timeDecode(0.0);
#endif

    auto cc                  = ciphertext->GetCryptoContext();
    uint32_t M               = cc->GetCyclotomicOrder();
    uint32_t L0              = cryptoParams->GetElementParams()->GetParams().size();
    auto initSizeQ           = ciphertext->GetElements()[0].GetNumOfElements();
    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();

    if (numIterations > 1) {
        // Step 1: Get the input.
        uint32_t powerOfTwoModulus = 1 << precision;

        // Step 2: Scale up by powerOfTwoModulus, and extend the modulus to powerOfTwoModulus * q.
        // Note that we extend the modulus implicitly without any code calls because the value always stays 0.
        Ciphertext<DCRTPoly> ctScaledUp = ciphertext->Clone();
        // We multiply by powerOfTwoModulus, and leave the last CRT value to be 0 (mod powerOfTwoModulus).
        cc->GetScheme()->MultByIntegerInPlace(ctScaledUp, powerOfTwoModulus);
        ctScaledUp->SetLevel(L0 - ctScaledUp->GetElements()[0].GetNumOfElements());

        // Step 3: Bootstrap the initial ciphertext.
        auto ctInitialBootstrap = cc->EvalBootstrap(ciphertext, numIterations - 1, precision);
        cc->GetScheme()->ModReduceInternalInPlace(ctInitialBootstrap, compositeDegree);

        // Step 4: Scale up by powerOfTwoModulus.
        cc->GetScheme()->MultByIntegerInPlace(ctInitialBootstrap, powerOfTwoModulus);

        // Step 5: Mod-down to powerOfTwoModulus * q
        // We mod down, and leave the last CRT value to be 0 because it's divisible by powerOfTwoModulus.
        auto ctBootstrappedScaledDown = ctInitialBootstrap->Clone();
        auto bootstrappingSizeQ       = ctBootstrappedScaledDown->GetElements()[0].GetNumOfElements();

        // If we start with more towers, than we obtain from bootstrapping, return the original ciphertext.
        if (bootstrappingSizeQ <= initSizeQ) {
            return ciphertext->Clone();
        }

        // TODO: YSP Can be removed for FLEXIBLE* scaling techniques as well as the closeness of 2^p to moduli is no longer needed
        if (cryptoParams->GetScalingTechnique() != COMPOSITESCALINGAUTO &&
            cryptoParams->GetScalingTechnique() != COMPOSITESCALINGMANUAL) {
            for (auto& cv : ctBootstrappedScaledDown->GetElements()) {
                cv.DropLastElements(bootstrappingSizeQ - initSizeQ);
            }
            ctBootstrappedScaledDown->SetLevel(L0 - ctBootstrappedScaledDown->GetElements()[0].GetNumOfElements());
        }

        // Step 6 and 7: Calculate the bootstrapping error by subtracting the original ciphertext from the bootstrapped ciphertext. Mod down to q is done implicitly.
        auto ctBootstrappingError = cc->EvalSub(ctBootstrappedScaledDown, ctScaledUp);

        // Step 8: Bootstrap the error.
        auto ctBootstrappedError = cc->EvalBootstrap(ctBootstrappingError, 1, 0);
        cc->GetScheme()->ModReduceInternalInPlace(ctBootstrappedError, compositeDegree);

        // Step 9: Subtract the bootstrapped error from the initial bootstrap to get even lower error.
        auto finalCiphertext = cc->EvalSub(ctInitialBootstrap, ctBootstrappedError);

        // Step 10: Scale back down by powerOfTwoModulus to get the original message.
        cc->EvalMultInPlace(finalCiphertext, static_cast<double>(1) / powerOfTwoModulus);
        return finalCiphertext;
    }

    uint32_t slots = ciphertext->GetSlots();

    auto pair = m_bootPrecomMap.find(slots);
    if (pair == m_bootPrecomMap.end()) {
        std::string errorMsg(std::string("Precomputations for ") + std::to_string(slots) +
                             std::string(" slots were not generated") +
                             std::string(" Need to call EvalBootstrapSetup and then EvalBootstrapKeyGen to proceed"));
        OPENFHE_THROW(errorMsg);
    }
    const std::shared_ptr<CKKSBootstrapPrecom> precom = pair->second;
    size_t N                                          = cc->GetRingDimension();

    auto elementParamsRaised = *(cryptoParams->GetElementParams());

    // For FLEXIBLEAUTOEXT we raised ciphertext does not include extra modulus
    // as it is multiplied by auxiliary plaintext
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT) {
        elementParamsRaised.PopLastParam();
    }

    auto paramsQ   = elementParamsRaised.GetParams();
    uint32_t sizeQ = paramsQ.size();

    std::vector<NativeInteger> moduli(sizeQ);
    std::vector<NativeInteger> roots(sizeQ);
    for (size_t i = 0; i < sizeQ; i++) {
        moduli[i] = paramsQ[i]->GetModulus();
        roots[i]  = paramsQ[i]->GetRootOfUnity();
    }
    auto elementParamsRaisedPtr = std::make_shared<ILDCRTParams<DCRTPoly::Integer>>(M, moduli, roots);

    double qDouble = GetBigModulus(cryptoParams);

    const auto p = cryptoParams->GetPlaintextModulus();
    double powP  = pow(2, p);

    int32_t deg = std::round(std::log2(qDouble / powP));
#if NATIVEINT != 128
    if (deg > static_cast<int32_t>(m_correctionFactor) &&
        (cryptoParams->GetScalingTechnique() != COMPOSITESCALINGAUTO &&
         cryptoParams->GetScalingTechnique() != COMPOSITESCALINGMANUAL)) {
        OPENFHE_THROW("Degree [" + std::to_string(deg) + "] must be less than or equal to the correction factor [" +
                      std::to_string(m_correctionFactor) + "].");
    }
#endif
    uint32_t correction = m_correctionFactor - deg;
    double post         = std::pow(2, static_cast<double>(deg));

    // TODO: YSP Can be extended to FLEXIBLE* scaling techniques as well as the closeness of 2^p to moduli is no longer needed
    double pre      = (compositeDegree > 1) ? cryptoParams->GetScalingFactorReal(0) / qDouble : 1. / post;
    uint64_t scalar = std::llround(post);

    //------------------------------------------------------------------------------
    // RAISING THE MODULUS
    //------------------------------------------------------------------------------

    // In FLEXIBLEAUTO, raising the ciphertext to a larger number
    // of towers is a bit more complex, because we need to adjust
    // it's scaling factor to the one that corresponds to the level
    // it's being raised to.
    // Increasing the modulus

    Ciphertext<DCRTPoly> raised = ciphertext->Clone();
    auto algo                   = cc->GetScheme();
    algo->ModReduceInternalInPlace(raised, compositeDegree * (raised->GetNoiseScaleDeg() - 1));

    AdjustCiphertext(raised, correction);
    auto ctxtDCRT = raised->GetElements();

    if (compositeDegree > 1) {
        // RNS basis extension from level 0 RNS limbs to the raised RNS basis
        ExtendCiphertext(ctxtDCRT, *cc, elementParamsRaisedPtr);
    }
    else {
        // We only use the level 0 ciphertext here. All other towers are automatically ignored to make
        // CKKS bootstrapping faster.
        for (size_t i = 0; i < ctxtDCRT.size(); i++) {
            DCRTPoly temp(elementParamsRaisedPtr, COEFFICIENT);
            ctxtDCRT[i].SetFormat(COEFFICIENT);
            temp = ctxtDCRT[i].GetElementAtIndex(0);
            temp.SetFormat(EVALUATION);
            ctxtDCRT[i] = temp;
        }
    }

    raised->SetLevel(L0 - ctxtDCRT[0].GetNumOfElements());
    raised->SetElements(std::move(ctxtDCRT));

#ifdef BOOTSTRAPTIMING
    std::cerr << "\nNumber of levels at the beginning of bootstrapping: "
              << raised->GetElements()[0].GetNumOfElements() - 1 << std::endl;
#endif

    //------------------------------------------------------------------------------
    // SETTING PARAMETERS FOR APPROXIMATE MODULAR REDUCTION
    //------------------------------------------------------------------------------

    // Coefficients of the Chebyshev series interpolating 1/(2 Pi) Sin(2 Pi K x)
    std::vector<double> coefficients;
    double k = 0;

    if (cryptoParams->GetSecretKeyDist() == SPARSE_TERNARY) {
        coefficients = g_coefficientsSparse;
        // k = K_SPARSE;
        k = 1.0;  // do not divide by k as we already did it during precomputation
    }
    else {
        // For larger composite degrees, larger K needs to be used to achieve a reasonable probability of failure
        if ((compositeDegree == 1) || ((compositeDegree == 2) && (N < (1 << 17)))) {
            coefficients = g_coefficientsUniform;
            k            = K_UNIFORM;
        }
        else {
            coefficients = g_coefficientsUniformExt;
            k            = K_UNIFORMEXT;
        }
    }

    double constantEvalMult = pre * (1.0 / (k * N));

    cc->EvalMultInPlace(raised, constantEvalMult);

    // no linear transformations are needed for Chebyshev series as the range has been normalized to [-1,1]
    double coeffLowerBound = -1;
    double coeffUpperBound = 1;

    Ciphertext<DCRTPoly> ctxtDec;

    bool isLTBootstrap = (precom->m_paramsEnc[CKKS_BOOT_PARAMS::LEVEL_BUDGET] == 1) &&
                         (precom->m_paramsDec[CKKS_BOOT_PARAMS::LEVEL_BUDGET] == 1);
    if (slots == M / 4) {
        //------------------------------------------------------------------------------
        // FULLY PACKED CASE
        //------------------------------------------------------------------------------

#ifdef BOOTSTRAPTIMING
        TIC(t);
#endif

        //------------------------------------------------------------------------------
        // Running CoeffToSlot
        //------------------------------------------------------------------------------

        // need to call internal modular reduction so it also works for FLEXIBLEAUTO
        algo->ModReduceInternalInPlace(raised, compositeDegree);

        // only one linear transform is needed as the other one can be derived
        auto ctxtEnc = (isLTBootstrap) ? EvalLinearTransform(precom->m_U0hatTPre, raised) :
                                         EvalCoeffsToSlots(precom->m_U0hatTPreFFT, raised);

        auto evalKeyMap = cc->GetEvalAutomorphismKeyMap(ctxtEnc->GetKeyTag());
        auto conj       = Conjugate(ctxtEnc, evalKeyMap);
        auto ctxtEncI   = cc->EvalSub(ctxtEnc, conj);
        cc->EvalAddInPlace(ctxtEnc, conj);
        algo->MultByMonomialInPlace(ctxtEncI, 3 * M / 4);

        if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
            while (ctxtEnc->GetNoiseScaleDeg() > 1) {
                cc->ModReduceInPlace(ctxtEnc);
                cc->ModReduceInPlace(ctxtEncI);
            }
        }
        else {
            if (ctxtEnc->GetNoiseScaleDeg() == 2) {
                algo->ModReduceInternalInPlace(ctxtEnc, compositeDegree);
                algo->ModReduceInternalInPlace(ctxtEncI, compositeDegree);
            }
        }

        //------------------------------------------------------------------------------
        // Running Approximate Mod Reduction
        //------------------------------------------------------------------------------

        // Evaluate Chebyshev series for the sine wave
        ctxtEnc  = cc->EvalChebyshevSeries(ctxtEnc, coefficients, coeffLowerBound, coeffUpperBound);
        ctxtEncI = cc->EvalChebyshevSeries(ctxtEncI, coefficients, coeffLowerBound, coeffUpperBound);

        // Double-angle iterations
        if ((cryptoParams->GetSecretKeyDist() == UNIFORM_TERNARY) ||
            (cryptoParams->GetSecretKeyDist() == SPARSE_TERNARY)) {
            if (cryptoParams->GetScalingTechnique() != FIXEDMANUAL) {
                algo->ModReduceInternalInPlace(ctxtEnc, compositeDegree);
                algo->ModReduceInternalInPlace(ctxtEncI, compositeDegree);
            }
            uint32_t numIter;
            if (cryptoParams->GetSecretKeyDist() == UNIFORM_TERNARY)
                numIter = R_UNIFORM;
            else
                numIter = R_SPARSE;
            ApplyDoubleAngleIterations(ctxtEnc, numIter);
            ApplyDoubleAngleIterations(ctxtEncI, numIter);
        }

        algo->MultByMonomialInPlace(ctxtEncI, M / 4);
        cc->EvalAddInPlace(ctxtEnc, ctxtEncI);

        if (cryptoParams->GetScalingTechnique() != COMPOSITESCALINGAUTO &&
            cryptoParams->GetScalingTechnique() != COMPOSITESCALINGMANUAL) {
            // scale the message back up after Chebyshev interpolation
            algo->MultByIntegerInPlace(ctxtEnc, scalar);
        }

#ifdef BOOTSTRAPTIMING
        timeModReduce = TOC(t);

        std::cerr << "Approximate modular reduction time: " << timeModReduce / 1000.0 << " s" << std::endl;

        // Running SlotToCoeff

        TIC(t);
#endif

        //------------------------------------------------------------------------------
        // Running SlotToCoeff
        //------------------------------------------------------------------------------

        // In the case of FLEXIBLEAUTO, we need one extra tower
        // TODO: See if we can remove the extra level in FLEXIBLEAUTO
        if (cryptoParams->GetScalingTechnique() != FIXEDMANUAL) {
            algo->ModReduceInternalInPlace(ctxtEnc, compositeDegree);
        }

        // Only one linear transform is needed
        ctxtDec = (isLTBootstrap) ? EvalLinearTransform(precom->m_U0Pre, ctxtEnc) :
                                    EvalSlotsToCoeffs(precom->m_U0PreFFT, ctxtEnc);
    }
    else {
        //------------------------------------------------------------------------------
        // SPARSELY PACKED CASE
        //------------------------------------------------------------------------------

        //------------------------------------------------------------------------------
        // Running PartialSum
        //------------------------------------------------------------------------------

        for (uint32_t j = 1; j < N / (2 * slots); j <<= 1) {
            auto temp = cc->EvalRotate(raised, j * slots);
            cc->EvalAddInPlace(raised, temp);
        }

#ifdef BOOTSTRAPTIMING
        TIC(t);
#endif

        //------------------------------------------------------------------------------
        // Running CoeffsToSlots
        //------------------------------------------------------------------------------

        algo->ModReduceInternalInPlace(raised, compositeDegree);

        auto ctxtEnc = (isLTBootstrap) ? EvalLinearTransform(precom->m_U0hatTPre, raised) :
                                         EvalCoeffsToSlots(precom->m_U0hatTPreFFT, raised);

        auto evalKeyMap = cc->GetEvalAutomorphismKeyMap(ctxtEnc->GetKeyTag());
        auto conj       = Conjugate(ctxtEnc, evalKeyMap);
        cc->EvalAddInPlace(ctxtEnc, conj);

        if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
            while (ctxtEnc->GetNoiseScaleDeg() > 1) {
                cc->ModReduceInPlace(ctxtEnc);
            }
        }
        else {
            if (ctxtEnc->GetNoiseScaleDeg() == 2) {
                algo->ModReduceInternalInPlace(ctxtEnc, compositeDegree);
            }
        }

#ifdef BOOTSTRAPTIMING
        timeEncode = TOC(t);

        std::cerr << "\nEncoding time: " << timeEncode / 1000.0 << " s" << std::endl;

        // Running Approximate Mod Reduction

        TIC(t);
#endif

        //------------------------------------------------------------------------------
        // Running Approximate Mod Reduction
        //------------------------------------------------------------------------------

        // Evaluate Chebyshev series for the sine wave
        ctxtEnc = cc->EvalChebyshevSeries(ctxtEnc, coefficients, coeffLowerBound, coeffUpperBound);

        // Double-angle iterations
        if ((cryptoParams->GetSecretKeyDist() == UNIFORM_TERNARY) ||
            (cryptoParams->GetSecretKeyDist() == SPARSE_TERNARY)) {
            if (cryptoParams->GetScalingTechnique() != FIXEDMANUAL) {
                algo->ModReduceInternalInPlace(ctxtEnc, compositeDegree);
            }
            uint32_t numIter;
            if (cryptoParams->GetSecretKeyDist() == UNIFORM_TERNARY)
                numIter = R_UNIFORM;
            else
                numIter = R_SPARSE;
            ApplyDoubleAngleIterations(ctxtEnc, numIter);
        }

        // TODO: YSP Can be extended to FLEXIBLE* scaling techniques as well as the closeness of 2^p to moduli is no longer needed
        if (cryptoParams->GetScalingTechnique() != COMPOSITESCALINGAUTO &&
            cryptoParams->GetScalingTechnique() != COMPOSITESCALINGMANUAL) {
            // scale the message back up after Chebyshev interpolation
            algo->MultByIntegerInPlace(ctxtEnc, scalar);
        }

#ifdef BOOTSTRAPTIMING
        timeModReduce = TOC(t);

        std::cerr << "Approximate modular reduction time: " << timeModReduce / 1000.0 << " s" << std::endl;

        // Running SlotToCoeff

        TIC(t);
#endif

        //------------------------------------------------------------------------------
        // Running SlotsToCoeffs
        //------------------------------------------------------------------------------

        // In the case of FLEXIBLEAUTO, we need one extra tower
        // TODO: See if we can remove the extra level in FLEXIBLEAUTO
        if (cryptoParams->GetScalingTechnique() != FIXEDMANUAL) {
            algo->ModReduceInternalInPlace(ctxtEnc, compositeDegree);
        }

        // linear transform for decoding
        ctxtDec = (isLTBootstrap) ? EvalLinearTransform(precom->m_U0Pre, ctxtEnc) :
                                    EvalSlotsToCoeffs(precom->m_U0PreFFT, ctxtEnc);

        cc->EvalAddInPlace(ctxtDec, cc->EvalRotate(ctxtDec, slots));
    }

#if NATIVEINT != 128
    // 64-bit only: scale back the message to its original scale.
    uint64_t corFactor = static_cast<uint64_t>(1) << std::llround(correction);
    algo->MultByIntegerInPlace(ctxtDec, corFactor);
#endif

#ifdef BOOTSTRAPTIMING
    timeDecode = TOC(t);

    std::cout << "Decoding time: " << timeDecode / 1000.0 << " s" << std::endl;
#endif

    auto bootstrappingNumTowers = ctxtDec->GetElements()[0].GetNumOfElements();

    // If we start with more towers, than we obtain from bootstrapping, return the original ciphertext.
    if (bootstrappingNumTowers <= initSizeQ) {
        return ciphertext->Clone();
    }

    return ctxtDec;
}

//------------------------------------------------------------------------------
// Find Rotation Indices
//------------------------------------------------------------------------------

std::vector<int32_t> FHECKKSRNS::FindBootstrapRotationIndices(uint32_t slots, uint32_t M) {
    auto pair = m_bootPrecomMap.find(slots);
    if (pair == m_bootPrecomMap.end()) {
        std::string errorMsg(std::string("Precomputations for ") + std::to_string(slots) +
                             std::string(" slots were not generated.") +
                             std::string(" Need to call EvalBootstrapSetup to proceed"));
        OPENFHE_THROW(errorMsg);
    }
    const std::shared_ptr<CKKSBootstrapPrecom> precom = pair->second;

    std::vector<uint32_t> fullIndexList;

    bool isLTBootstrap = (precom->m_paramsEnc[CKKS_BOOT_PARAMS::LEVEL_BUDGET] == 1) &&
                         (precom->m_paramsDec[CKKS_BOOT_PARAMS::LEVEL_BUDGET] == 1);

    if (isLTBootstrap) {
        fullIndexList = FindLinearTransformRotationIndices(slots, M);
    }
    else {
        fullIndexList = FindCoeffsToSlotsRotationIndices(slots, M);

        std::vector<uint32_t> indexListStC{FindSlotsToCoeffsRotationIndices(slots, M)};
        fullIndexList.insert(fullIndexList.end(), std::make_move_iterator(indexListStC.begin()),
                             std::make_move_iterator(indexListStC.end()));
    }

    // Remove possible duplicates and remove automorphisms corresponding to 0 and M/4 by using std::set
    std::set<uint32_t> s(fullIndexList.begin(), fullIndexList.end());
    s.erase(0);
    s.erase(M / 4);

    return std::vector<int32_t>(s.begin(), s.end());
}

// ATTN: This function is a helper methods to be called in FindBootstrapRotationIndices() only.
// so it DOES NOT remove possible duplicates and automorphisms corresponding to 0 and M/4.
// This method completely depends on FindBootstrapRotationIndices() to do that.
std::vector<uint32_t> FHECKKSRNS::FindLinearTransformRotationIndices(uint32_t slots, uint32_t M) {
    auto pair = m_bootPrecomMap.find(slots);
    if (pair == m_bootPrecomMap.end()) {
        std::string errorMsg(std::string("Precomputations for ") + std::to_string(slots) +
                             std::string(" slots were not generated.") +
                             std::string(" Need to call EvalBootstrapSetup to proceed"));
        OPENFHE_THROW(errorMsg);
    }
    const std::shared_ptr<CKKSBootstrapPrecom> precom = pair->second;

    // Computing the baby-step g and the giant-step h.
    uint32_t g = (precom->m_dim1 == 0) ? static_cast<uint32_t>(std::ceil(std::sqrt(slots))) : precom->m_dim1;
    uint32_t h = static_cast<uint32_t>(std::ceil(static_cast<double>(slots) / g));

    std::vector<uint32_t> indexList;
    // To avoid overflowing uint32_t variables, we do some math operations below in a specific order
    // computing all indices for baby-step giant-step procedure
    int32_t indexListSz = static_cast<int32_t>(g) + h + M - 2;
    if (indexListSz < 0) {
        OPENFHE_THROW("indexListSz can not be negative");
    }
    indexList.reserve(indexListSz);
    for (size_t i = 1; i <= g; ++i) {
        indexList.emplace_back(i);
    }
    for (size_t i = 2; i < h; ++i) {
        indexList.emplace_back(g * i);
    }

    uint32_t m = slots * 4;
    // additional automorphisms are needed for sparse bootstrapping
    if (m != M) {
        for (size_t j = 1; j < M / m; j <<= 1) {
            indexList.emplace_back(j * slots);
        }
    }

    return indexList;
}

// ATTN: This function is a helper methods to be called in FindBootstrapRotationIndices() only.
// so it DOES NOT remove possible duplicates and automorphisms corresponding to 0 and M/4.
// This method completely depends on FindBootstrapRotationIndices() to do that.
std::vector<uint32_t> FHECKKSRNS::FindCoeffsToSlotsRotationIndices(uint32_t slots, uint32_t M) {
    auto pair = m_bootPrecomMap.find(slots);
    if (pair == m_bootPrecomMap.end()) {
        std::string errorMsg(std::string("Precomputations for ") + std::to_string(slots) +
                             std::string(" slots were not generated.") +
                             std::string(" Need to call EvalBootstrapSetup to proceed"));
        OPENFHE_THROW(errorMsg);
    }
    const std::shared_ptr<CKKSBootstrapPrecom> precom = pair->second;

    uint32_t levelBudget     = precom->m_paramsEnc[CKKS_BOOT_PARAMS::LEVEL_BUDGET];
    uint32_t layersCollapse  = precom->m_paramsEnc[CKKS_BOOT_PARAMS::LAYERS_COLL];
    uint32_t remCollapse     = precom->m_paramsEnc[CKKS_BOOT_PARAMS::LAYERS_REM];
    uint32_t numRotations    = precom->m_paramsEnc[CKKS_BOOT_PARAMS::NUM_ROTATIONS];
    uint32_t b               = precom->m_paramsEnc[CKKS_BOOT_PARAMS::BABY_STEP];
    uint32_t g               = precom->m_paramsEnc[CKKS_BOOT_PARAMS::GIANT_STEP];
    uint32_t numRotationsRem = precom->m_paramsEnc[CKKS_BOOT_PARAMS::NUM_ROTATIONS_REM];
    uint32_t bRem            = precom->m_paramsEnc[CKKS_BOOT_PARAMS::BABY_STEP_REM];
    uint32_t gRem            = precom->m_paramsEnc[CKKS_BOOT_PARAMS::GIANT_STEP_REM];

    uint32_t flagRem = (remCollapse == 0) ? 0 : 1;

    std::vector<uint32_t> indexList;
    // To avoid overflowing uint32_t variables, we do some math operations below in a specific order
    // Computing all indices for baby-step giant-step procedure for encoding and decoding
    int32_t indexListSz = static_cast<int32_t>(b) + g - 2 + bRem + gRem - 2 + 1 + M;
    if (indexListSz < 0) {
        OPENFHE_THROW("indexListSz can not be negative");
    }
    indexList.reserve(indexListSz);

    for (int32_t s = static_cast<int32_t>(levelBudget) - 1; s >= static_cast<int32_t>(flagRem); --s) {
        const uint32_t scalingFactor = 1U << ((s - flagRem) * layersCollapse + remCollapse);
        const int32_t halfRots       = (1 - (numRotations + 1) / 2);
        for (int32_t j = halfRots; j < static_cast<int32_t>(g + halfRots); ++j) {
            indexList.emplace_back(ReduceRotation(j * scalingFactor, slots));
        }
        for (size_t i = 0; i < b; i++) {
            indexList.emplace_back(ReduceRotation((g * i) * scalingFactor, M / 4));
        }
    }

    if (flagRem) {
        const int32_t halfRots = (1 - (numRotationsRem + 1) / 2);
        for (int32_t j = halfRots; j < static_cast<int32_t>(gRem + halfRots); ++j) {
            indexList.emplace_back(ReduceRotation(j, slots));
        }
        for (size_t i = 0; i < bRem; i++) {
            indexList.emplace_back(ReduceRotation(gRem * i, M / 4));
        }
    }

    uint32_t m = slots * 4;
    // additional automorphisms are needed for sparse bootstrapping
    if (m != M) {
        for (size_t j = 1; j < M / m; j <<= 1) {
            indexList.emplace_back(j * slots);
        }
    }

    return indexList;
}

std::vector<uint32_t> FHECKKSRNS::FindSlotsToCoeffsRotationIndices(uint32_t slots, uint32_t M) {
    auto pair = m_bootPrecomMap.find(slots);
    if (pair == m_bootPrecomMap.end()) {
        std::string errorMsg(std::string("Precomputations for ") + std::to_string(slots) +
                             std::string(" slots were not generated.") +
                             std::string(" Need to call EvalBootstrapSetup to proceed"));
        OPENFHE_THROW(errorMsg);
    }
    const std::shared_ptr<CKKSBootstrapPrecom> precom = pair->second;
    uint32_t levelBudget                              = precom->m_paramsDec[CKKS_BOOT_PARAMS::LEVEL_BUDGET];
    uint32_t layersCollapse                           = precom->m_paramsDec[CKKS_BOOT_PARAMS::LAYERS_COLL];
    uint32_t remCollapse                              = precom->m_paramsDec[CKKS_BOOT_PARAMS::LAYERS_REM];
    uint32_t numRotations                             = precom->m_paramsDec[CKKS_BOOT_PARAMS::NUM_ROTATIONS];
    uint32_t b                                        = precom->m_paramsDec[CKKS_BOOT_PARAMS::BABY_STEP];
    uint32_t g                                        = precom->m_paramsDec[CKKS_BOOT_PARAMS::GIANT_STEP];
    uint32_t numRotationsRem                          = precom->m_paramsDec[CKKS_BOOT_PARAMS::NUM_ROTATIONS_REM];
    uint32_t bRem                                     = precom->m_paramsDec[CKKS_BOOT_PARAMS::BABY_STEP_REM];
    uint32_t gRem                                     = precom->m_paramsDec[CKKS_BOOT_PARAMS::GIANT_STEP_REM];

    uint32_t flagRem = (remCollapse == 0) ? 0 : 1;
    if (levelBudget < flagRem) {
        OPENFHE_THROW("levelBudget can not be less than flagRem");
    }

    std::vector<uint32_t> indexList;
    // To avoid overflowing uint32_t variables, we do some math operations below in a specific order
    // Computing all indices for baby-step giant-step procedure for encoding and decoding
    int32_t indexListSz = static_cast<int32_t>(b) + g - 2 + bRem + gRem - 2 + 1 + M;
    if (indexListSz < 0) {
        OPENFHE_THROW("indexListSz can not be negative");
    }
    indexList.reserve(indexListSz);

    for (size_t s = 0; s < (levelBudget - flagRem); ++s) {
        const uint32_t scalingFactor = 1U << (s * layersCollapse);
        const int32_t halfRots       = (1 - (numRotations + 1) / 2);
        for (int32_t j = halfRots; j < static_cast<int32_t>(g + halfRots); ++j) {
            indexList.emplace_back(ReduceRotation(j * scalingFactor, M / 4));
        }
        for (size_t i = 0; i < b; ++i) {
            indexList.emplace_back(ReduceRotation((g * i) * scalingFactor, M / 4));
        }
    }

    if (flagRem) {
        uint32_t s                   = levelBudget - flagRem;
        const uint32_t scalingFactor = 1U << (s * layersCollapse);
        const int32_t halfRots       = (1 - (numRotationsRem + 1) / 2);
        for (int32_t j = halfRots; j < static_cast<int32_t>(gRem + halfRots); ++j) {
            indexList.emplace_back(ReduceRotation(j * scalingFactor, M / 4));
        }
        for (size_t i = 0; i < bRem; ++i) {
            indexList.emplace_back(ReduceRotation((gRem * i) * scalingFactor, M / 4));
        }
    }

    uint32_t m = slots * 4;
    // additional automorphisms are needed for sparse bootstrapping
    if (m != M) {
        for (size_t j = 1; j < M / m; j <<= 1) {
            indexList.emplace_back(j * slots);
        }
    }

    return indexList;
}

//------------------------------------------------------------------------------
// Precomputations for CoeffsToSlots and SlotsToCoeffs
//------------------------------------------------------------------------------

std::vector<ReadOnlyPlaintext> FHECKKSRNS::EvalLinearTransformPrecompute(
    const CryptoContextImpl<DCRTPoly>& cc, const std::vector<std::vector<std::complex<double>>>& A, double scale,
    uint32_t L) const {
    if (A[0].size() != A.size()) {
        OPENFHE_THROW("The matrix passed to EvalLTPrecompute is not square");
    }

    uint32_t slots = A.size();

    auto pair = m_bootPrecomMap.find(slots);
    if (pair == m_bootPrecomMap.end()) {
        std::string errorMsg(std::string("Precomputations for ") + std::to_string(slots) +
                             std::string(" slots were not generated") +
                             std::string(" Need to call EvalBootstrapSetup to proceed"));
        OPENFHE_THROW(errorMsg);
    }
    const std::shared_ptr<CKKSBootstrapPrecom> precom = pair->second;

    uint32_t M = cc.GetCyclotomicOrder();

    // Computing the baby-step bStep and the giant-step gStep.
    int bStep = (precom->m_dim1 == 0) ? ceil(sqrt(slots)) : precom->m_dim1;
    int gStep = ceil(static_cast<double>(slots) / bStep);

    // make sure the plaintext is created only with the necessary amount of moduli

    const auto cryptoParams  = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());
    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();

    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParams->GetElementParams());

    uint32_t towersToDrop = 0;
    if (L != 0) {
        towersToDrop = elementParams.GetParams().size() - L - compositeDegree;
    }

    for (uint32_t i = 0; i < towersToDrop; i++) {
        elementParams.PopLastParam();
    }

    auto paramsQ   = elementParams.GetParams();
    uint32_t sizeQ = paramsQ.size();
    auto paramsP   = cryptoParams->GetParamsP()->GetParams();
    uint32_t sizeP = paramsP.size();

    std::vector<NativeInteger> moduli(sizeQ + sizeP);
    std::vector<NativeInteger> roots(sizeQ + sizeP);

    for (size_t i = 0; i < sizeQ; i++) {
        moduli[i] = paramsQ[i]->GetModulus();
        roots[i]  = paramsQ[i]->GetRootOfUnity();
    }

    for (size_t i = 0; i < sizeP; i++) {
        moduli[sizeQ + i] = paramsP[i]->GetModulus();
        roots[sizeQ + i]  = paramsP[i]->GetRootOfUnity();
    }

    auto elementParamsPtr = std::make_shared<ILDCRTParams<DCRTPoly::Integer>>(M, moduli, roots);
    //  auto elementParamsPtr2 = std::dynamic_pointer_cast<typename DCRTPoly::Params>(elementParamsPtr);

    std::vector<ReadOnlyPlaintext> result(slots);
// parallelizing the loop (below) with OMP causes a segfault on MinGW
// see https://github.com/openfheorg/openfhe-development/issues/176
#if !defined(__MINGW32__) && !defined(__MINGW64__)
    #pragma omp parallel for
#endif
    for (int j = 0; j < gStep; j++) {
        int offset = -bStep * j;
        for (int i = 0; i < bStep; i++) {
            if (bStep * j + i < static_cast<int>(slots)) {
                auto diag = ExtractShiftedDiagonal(A, bStep * j + i);
                for (uint32_t k = 0; k < diag.size(); k++)
                    diag[k] *= scale;

                result[bStep * j + i] =
                    MakeAuxPlaintext(cc, elementParamsPtr, Rotate(diag, offset), 1, towersToDrop, diag.size());
            }
        }
    }
    return result;
}

std::vector<ReadOnlyPlaintext> FHECKKSRNS::EvalLinearTransformPrecompute(
    const CryptoContextImpl<DCRTPoly>& cc, const std::vector<std::vector<std::complex<double>>>& A,
    const std::vector<std::vector<std::complex<double>>>& B, uint32_t orientation, double scale, uint32_t L) const {
    uint32_t slots = A.size();

    auto pair = m_bootPrecomMap.find(slots);
    if (pair == m_bootPrecomMap.end()) {
        std::string errorMsg(std::string("Precomputations for ") + std::to_string(slots) +
                             std::string(" slots were not generated") +
                             std::string(" Need to call EvalBootstrapSetup to proceed"));
        OPENFHE_THROW(errorMsg);
    }
    const std::shared_ptr<CKKSBootstrapPrecom> precom = pair->second;

    uint32_t M = cc.GetCyclotomicOrder();

    // Computing the baby-step bStep and the giant-step gStep.
    int bStep = (precom->m_dim1 == 0) ? ceil(sqrt(slots)) : precom->m_dim1;
    int gStep = ceil(static_cast<double>(slots) / bStep);

    // make sure the plaintext is created only with the necessary amount of moduli

    const auto cryptoParams  = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());
    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();

    auto elementParams = *(cryptoParams->GetElementParams());

    uint32_t towersToDrop = 0;
    if (L != 0) {
        towersToDrop = elementParams.GetParams().size() - L - compositeDegree;
    }

    for (uint32_t i = 0; i < towersToDrop; i++) {
        elementParams.PopLastParam();
    }

    auto paramsQ   = elementParams.GetParams();
    uint32_t sizeQ = paramsQ.size();
    auto paramsP   = cryptoParams->GetParamsP()->GetParams();
    uint32_t sizeP = paramsP.size();

    std::vector<NativeInteger> moduli(sizeQ + sizeP);
    std::vector<NativeInteger> roots(sizeQ + sizeP);
    for (size_t i = 0; i < sizeQ; i++) {
        moduli[i] = paramsQ[i]->GetModulus();
        roots[i]  = paramsQ[i]->GetRootOfUnity();
    }

    for (size_t i = 0; i < sizeP; i++) {
        moduli[sizeQ + i] = paramsP[i]->GetModulus();
        roots[sizeQ + i]  = paramsP[i]->GetRootOfUnity();
    }

    auto elementParamsPtr = std::make_shared<ILDCRTParams<DCRTPoly::Integer>>(M, moduli, roots);
    //  auto elementParamsPtr2 = std::dynamic_pointer_cast<typename DCRTPoly::Params>(elementParamsPtr);

    std::vector<ReadOnlyPlaintext> result(slots);

    if (orientation == 0) {
        // vertical concatenation - used during homomorphic encoding
        // #pragma omp parallel for
        for (int j = 0; j < gStep; j++) {
            int offset = -bStep * j;
            for (int i = 0; i < bStep; i++) {
                if (bStep * j + i < static_cast<int>(slots)) {
                    auto vecA = ExtractShiftedDiagonal(A, bStep * j + i);
                    auto vecB = ExtractShiftedDiagonal(B, bStep * j + i);

                    vecA.insert(vecA.end(), vecB.begin(), vecB.end());
                    for (uint32_t k = 0; k < vecA.size(); k++)
                        vecA[k] *= scale;

                    result[bStep * j + i] =
                        MakeAuxPlaintext(cc, elementParamsPtr, Rotate(vecA, offset), 1, towersToDrop, vecA.size());
                }
            }
        }
    }
    else {
        // horizontal concatenation - used during homomorphic decoding
        std::vector<std::vector<std::complex<double>>> newA(slots);

        //  A and B are concatenated horizontally
        for (uint32_t i = 0; i < slots; ++i) {
            newA[i].reserve(A[i].size() + B[i].size());
            newA[i].insert(newA[i].end(), A[i].begin(), A[i].end());
            newA[i].insert(newA[i].end(), B[i].begin(), B[i].end());
        }

#pragma omp parallel for
        for (int j = 0; j < gStep; j++) {
            int offset = -bStep * j;
            for (int i = 0; i < bStep; i++) {
                if (bStep * j + i < static_cast<int>(slots)) {
                    // shifted diagonal is computed for rectangular map newA of dimension
                    // slots x 2*slots
                    auto vec = ExtractShiftedDiagonal(newA, bStep * j + i);
                    for (uint32_t k = 0; k < vec.size(); k++)
                        vec[k] *= scale;

                    result[bStep * j + i] =
                        MakeAuxPlaintext(cc, elementParamsPtr, Rotate(vec, offset), 1, towersToDrop, vec.size());
                }
            }
        }
    }

    return result;
}

std::vector<std::vector<ReadOnlyPlaintext>> FHECKKSRNS::EvalCoeffsToSlotsPrecompute(
    const CryptoContextImpl<DCRTPoly>& cc, const std::vector<std::complex<double>>& A,
    const std::vector<uint32_t>& rotGroup, bool flag_i, double scale, uint32_t L) const {
    uint32_t slots = rotGroup.size();

    auto pair = m_bootPrecomMap.find(slots);
    if (pair == m_bootPrecomMap.end()) {
        std::string errorMsg(std::string("Precomputations for ") + std::to_string(slots) +
                             std::string(" slots were not generated") +
                             std::string(" Need to call EvalBootstrapSetup to proceed"));
        OPENFHE_THROW(errorMsg);
    }
    const std::shared_ptr<CKKSBootstrapPrecom> precom = pair->second;

    uint32_t M = cc.GetCyclotomicOrder();

    int32_t levelBudget     = precom->m_paramsEnc[CKKS_BOOT_PARAMS::LEVEL_BUDGET];
    int32_t layersCollapse  = precom->m_paramsEnc[CKKS_BOOT_PARAMS::LAYERS_COLL];
    int32_t remCollapse     = precom->m_paramsEnc[CKKS_BOOT_PARAMS::LAYERS_REM];
    int32_t numRotations    = precom->m_paramsEnc[CKKS_BOOT_PARAMS::NUM_ROTATIONS];
    int32_t b               = precom->m_paramsEnc[CKKS_BOOT_PARAMS::BABY_STEP];
    int32_t g               = precom->m_paramsEnc[CKKS_BOOT_PARAMS::GIANT_STEP];
    int32_t numRotationsRem = precom->m_paramsEnc[CKKS_BOOT_PARAMS::NUM_ROTATIONS_REM];
    int32_t bRem            = precom->m_paramsEnc[CKKS_BOOT_PARAMS::BABY_STEP_REM];
    int32_t gRem            = precom->m_paramsEnc[CKKS_BOOT_PARAMS::GIANT_STEP_REM];

    int32_t stop    = -1;
    int32_t flagRem = 0;

    if (remCollapse != 0) {
        stop    = 0;
        flagRem = 1;
    }

    // result is the rotated plaintext version of the coefficients
    std::vector<std::vector<ReadOnlyPlaintext>> result(levelBudget);
    for (uint32_t i = 0; i < static_cast<uint32_t>(levelBudget); i++) {
        if (flagRem == 1 && i == 0) {
            // remainder corresponds to index 0 in encoding and to last index in decoding
            result[i] = std::vector<ReadOnlyPlaintext>(numRotationsRem);
        }
        else {
            result[i] = std::vector<ReadOnlyPlaintext>(numRotations);
        }
    }

    // make sure the plaintext is created only with the necessary amount of moduli

    const auto cryptoParams  = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());
    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();

    auto elementParams = *(cryptoParams->GetElementParams());

    uint32_t towersToDrop = 0;

    if (L != 0) {
        towersToDrop = elementParams.GetParams().size() - L - compositeDegree * levelBudget;
    }

    for (uint32_t i = 0; i < towersToDrop; i++) {
        elementParams.PopLastParam();
    }

    uint32_t level0 = towersToDrop + compositeDegree * (levelBudget - 1);

    auto paramsQ   = elementParams.GetParams();
    uint32_t sizeQ = paramsQ.size();
    auto paramsP   = cryptoParams->GetParamsP()->GetParams();
    uint32_t sizeP = paramsP.size();

    std::vector<NativeInteger> moduli(sizeQ + sizeP);
    std::vector<NativeInteger> roots(sizeQ + sizeP);
    for (size_t i = 0; i < sizeQ; i++) {
        moduli[i] = paramsQ[i]->GetModulus();
        roots[i]  = paramsQ[i]->GetRootOfUnity();
    }

    for (size_t i = 0; i < sizeP; i++) {
        moduli[sizeQ + i] = paramsP[i]->GetModulus();
        roots[sizeQ + i]  = paramsP[i]->GetRootOfUnity();
    }

    // we need to pre-compute the plaintexts in the extended basis P*Q
    std::vector<std::shared_ptr<ILDCRTParams<BigInteger>>> paramsVector(levelBudget - stop);
    for (int32_t s = levelBudget - 1; s >= stop; s--) {
        paramsVector[s - stop] = std::make_shared<ILDCRTParams<BigInteger>>(M, moduli, roots);
        for (uint32_t j = 0; j < compositeDegree; ++j) {
            moduli.erase(moduli.begin() + sizeQ - 1);
            roots.erase(roots.begin() + sizeQ - 1);
            sizeQ--;
        }
    }

    if (slots == M / 4) {
        //------------------------------------------------------------------------------
        // fully-packed mode
        //------------------------------------------------------------------------------

        auto coeff = CoeffEncodingCollapse(A, rotGroup, levelBudget, flag_i);

        for (int32_t s = levelBudget - 1; s > stop; s--) {
            for (int32_t i = 0; i < b; i++) {
#if !defined(__MINGW32__) && !defined(__MINGW64__)
    #pragma omp parallel for
#endif
                for (int32_t j = 0; j < g; j++) {
                    if (g * i + j != static_cast<int32_t>(numRotations)) {
                        uint32_t rot =
                            ReduceRotation(-g * i * (1 << ((s - flagRem) * layersCollapse + remCollapse)), slots);
                        if ((flagRem == 0) && (s == stop + 1)) {
                            // do the scaling only at the last set of coefficients
                            for (uint32_t k = 0; k < slots; k++) {
                                coeff[s][g * i + j][k] *= scale;
                            }
                        }

                        auto rotateTemp = Rotate(coeff[s][g * i + j], rot);

                        result[s][g * i + j] = MakeAuxPlaintext(cc, paramsVector[s - stop], rotateTemp, 1,
                                                                level0 - compositeDegree * s, rotateTemp.size());
                    }
                }
            }
        }

        if (flagRem) {
            for (int32_t i = 0; i < bRem; i++) {
#pragma omp parallel for
                for (int32_t j = 0; j < gRem; j++) {
                    if (gRem * i + j != static_cast<int32_t>(numRotationsRem)) {
                        uint32_t rot = ReduceRotation(-gRem * i, slots);
                        for (uint32_t k = 0; k < slots; k++) {
                            coeff[stop][gRem * i + j][k] *= scale;
                        }

                        auto rotateTemp = Rotate(coeff[stop][gRem * i + j], rot);
                        result[stop][gRem * i + j] =
                            MakeAuxPlaintext(cc, paramsVector[0], rotateTemp, 1, level0, rotateTemp.size());
                    }
                }
            }
        }
    }
    else {
        //------------------------------------------------------------------------------
        // sparsely-packed mode
        //------------------------------------------------------------------------------

        auto coeff  = CoeffEncodingCollapse(A, rotGroup, levelBudget, false);
        auto coeffi = CoeffEncodingCollapse(A, rotGroup, levelBudget, true);

        for (int32_t s = levelBudget - 1; s > stop; s--) {
            for (int32_t i = 0; i < b; i++) {
#if !defined(__MINGW32__) && !defined(__MINGW64__)
    #pragma omp parallel for
#endif
                for (int32_t j = 0; j < g; j++) {
                    if (g * i + j != static_cast<int32_t>(numRotations)) {
                        uint32_t rot =
                            ReduceRotation(-g * i * (1 << ((s - flagRem) * layersCollapse + remCollapse)), M / 4);
                        // concatenate the coefficients horizontally on their third dimension, which corresponds to the # of slots
                        auto clearTemp  = coeff[s][g * i + j];
                        auto clearTempi = coeffi[s][g * i + j];
                        clearTemp.insert(clearTemp.end(), clearTempi.begin(), clearTempi.end());
                        if ((flagRem == 0) && (s == stop + 1)) {
                            // do the scaling only at the last set of coefficients
                            for (uint32_t k = 0; k < clearTemp.size(); k++) {
                                clearTemp[k] *= scale;
                            }
                        }

                        auto rotateTemp      = Rotate(clearTemp, rot);
                        result[s][g * i + j] = MakeAuxPlaintext(cc, paramsVector[s - stop], rotateTemp, 1,
                                                                level0 - compositeDegree * s, rotateTemp.size());
                    }
                }
            }
        }

        if (flagRem) {
            for (int32_t i = 0; i < bRem; i++) {
#pragma omp parallel for
                for (int32_t j = 0; j < gRem; j++) {
                    if (gRem * i + j != static_cast<int32_t>(numRotationsRem)) {
                        uint32_t rot = ReduceRotation(-gRem * i, M / 4);
                        // concatenate the coefficients on their third dimension, which corresponds to the # of slots
                        auto clearTemp  = coeff[stop][gRem * i + j];
                        auto clearTempi = coeffi[stop][gRem * i + j];
                        clearTemp.insert(clearTemp.end(), clearTempi.begin(), clearTempi.end());
                        for (uint32_t k = 0; k < clearTemp.size(); k++) {
                            clearTemp[k] *= scale;
                        }

                        auto rotateTemp = Rotate(clearTemp, rot);
                        result[stop][gRem * i + j] =
                            MakeAuxPlaintext(cc, paramsVector[0], rotateTemp, 1, level0, rotateTemp.size());
                    }
                }
            }
        }
    }
    return result;
}

std::vector<std::vector<ReadOnlyPlaintext>> FHECKKSRNS::EvalSlotsToCoeffsPrecompute(
    const CryptoContextImpl<DCRTPoly>& cc, const std::vector<std::complex<double>>& A,
    const std::vector<uint32_t>& rotGroup, bool flag_i, double scale, uint32_t L) const {
    uint32_t slots = rotGroup.size();

    auto pair = m_bootPrecomMap.find(slots);
    if (pair == m_bootPrecomMap.end()) {
        std::string errorMsg(std::string("Precomputations for ") + std::to_string(slots) +
                             std::string(" slots were not generated") +
                             std::string(" Need to call EvalBootstrapSetup to proceed"));
        OPENFHE_THROW(errorMsg);
    }
    const std::shared_ptr<CKKSBootstrapPrecom> precom = pair->second;

    uint32_t M = cc.GetCyclotomicOrder();

    int32_t levelBudget     = precom->m_paramsDec[CKKS_BOOT_PARAMS::LEVEL_BUDGET];
    int32_t layersCollapse  = precom->m_paramsDec[CKKS_BOOT_PARAMS::LAYERS_COLL];
    int32_t remCollapse     = precom->m_paramsDec[CKKS_BOOT_PARAMS::LAYERS_REM];
    int32_t numRotations    = precom->m_paramsDec[CKKS_BOOT_PARAMS::NUM_ROTATIONS];
    int32_t b               = precom->m_paramsDec[CKKS_BOOT_PARAMS::BABY_STEP];
    int32_t g               = precom->m_paramsDec[CKKS_BOOT_PARAMS::GIANT_STEP];
    int32_t numRotationsRem = precom->m_paramsDec[CKKS_BOOT_PARAMS::NUM_ROTATIONS_REM];
    int32_t bRem            = precom->m_paramsDec[CKKS_BOOT_PARAMS::BABY_STEP_REM];
    int32_t gRem            = precom->m_paramsDec[CKKS_BOOT_PARAMS::GIANT_STEP_REM];

    int32_t flagRem = 0;

    if (remCollapse != 0) {
        flagRem = 1;
    }

    // result is the rotated plaintext version of coeff
    std::vector<std::vector<ReadOnlyPlaintext>> result(levelBudget);
    for (uint32_t i = 0; i < static_cast<uint32_t>(levelBudget); i++) {
        if (flagRem == 1 && i == static_cast<uint32_t>(levelBudget - 1)) {
            // remainder corresponds to index 0 in encoding and to last index in decoding
            result[i] = std::vector<ReadOnlyPlaintext>(numRotationsRem);
        }
        else {
            result[i] = std::vector<ReadOnlyPlaintext>(numRotations);
        }
    }

    // make sure the plaintext is created only with the necessary amount of moduli

    const auto cryptoParams  = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());
    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();

    auto elementParams = *(cryptoParams->GetElementParams());

    uint32_t towersToDrop = 0;

    if (L != 0) {
        towersToDrop = elementParams.GetParams().size() - L - compositeDegree * levelBudget;
    }

    for (uint32_t i = 0; i < towersToDrop; i++) {
        elementParams.PopLastParam();
    }

    uint32_t level0 = towersToDrop;

    auto paramsQ   = elementParams.GetParams();
    uint32_t sizeQ = paramsQ.size();
    auto paramsP   = cryptoParams->GetParamsP()->GetParams();
    uint32_t sizeP = paramsP.size();

    std::vector<NativeInteger> moduli(sizeQ + sizeP);
    std::vector<NativeInteger> roots(sizeQ + sizeP);
    for (size_t i = 0; i < sizeQ; i++) {
        moduli[i] = paramsQ[i]->GetModulus();
        roots[i]  = paramsQ[i]->GetRootOfUnity();
    }

    for (size_t i = 0; i < sizeP; i++) {
        moduli[sizeQ + i] = paramsP[i]->GetModulus();
        roots[sizeQ + i]  = paramsP[i]->GetRootOfUnity();
    }

    // we need to pre-compute the plaintexts in the extended basis P*Q
    std::vector<std::shared_ptr<ILDCRTParams<BigInteger>>> paramsVector(levelBudget - flagRem + 1);
    for (int32_t s = 0; s < levelBudget - flagRem + 1; s++) {
        paramsVector[s] = std::make_shared<ILDCRTParams<BigInteger>>(M, moduli, roots);
        for (uint32_t i = 0; i < compositeDegree; ++i) {
            moduli.erase(moduli.begin() + sizeQ - 1);
            roots.erase(roots.begin() + sizeQ - 1);
            sizeQ--;
        }
    }

    if (slots == M / 4) {
        // fully-packed
        auto coeff = CoeffDecodingCollapse(A, rotGroup, levelBudget, flag_i);

        for (int32_t s = 0; s < levelBudget - flagRem; s++) {
            for (int32_t i = 0; i < b; i++) {
#pragma omp parallel for
                for (int32_t j = 0; j < g; j++) {
                    if (g * i + j != static_cast<int32_t>(numRotations)) {
                        uint32_t rot = ReduceRotation(-g * i * (1 << (s * layersCollapse)), slots);
                        if ((flagRem == 0) && (s == levelBudget - flagRem - 1)) {
                            // do the scaling only at the last set of coefficients
                            for (uint32_t k = 0; k < slots; k++) {
                                coeff[s][g * i + j][k] *= scale;
                            }
                        }

                        auto rotateTemp      = Rotate(coeff[s][g * i + j], rot);
                        result[s][g * i + j] = MakeAuxPlaintext(cc, paramsVector[s], rotateTemp, 1,
                                                                level0 + compositeDegree * s, rotateTemp.size());
                    }
                }
            }
        }

        if (flagRem) {
            int32_t s = levelBudget - flagRem;
            for (int32_t i = 0; i < bRem; i++) {
#pragma omp parallel for
                for (int32_t j = 0; j < gRem; j++) {
                    if (gRem * i + j != static_cast<int32_t>(numRotationsRem)) {
                        uint32_t rot = ReduceRotation(-gRem * i * (1 << (s * layersCollapse)), slots);
                        for (uint32_t k = 0; k < slots; k++) {
                            coeff[s][gRem * i + j][k] *= scale;
                        }

                        auto rotateTemp         = Rotate(coeff[s][gRem * i + j], rot);
                        result[s][gRem * i + j] = MakeAuxPlaintext(cc, paramsVector[s], rotateTemp, 1,
                                                                   level0 + compositeDegree * s, rotateTemp.size());
                    }
                }
            }
        }
    }
    else {
        //------------------------------------------------------------------------------
        // sparsely-packed mode
        //------------------------------------------------------------------------------

        auto coeff  = CoeffDecodingCollapse(A, rotGroup, levelBudget, false);
        auto coeffi = CoeffDecodingCollapse(A, rotGroup, levelBudget, true);

        for (int32_t s = 0; s < levelBudget - flagRem; s++) {
            for (int32_t i = 0; i < b; i++) {
#pragma omp parallel for
                for (int32_t j = 0; j < g; j++) {
                    if (g * i + j != static_cast<int32_t>(numRotations)) {
                        uint32_t rot = ReduceRotation(-g * i * (1 << (s * layersCollapse)), M / 4);
                        // concatenate the coefficients horizontally on their third dimension, which corresponds to the # of slots
                        auto clearTemp  = coeff[s][g * i + j];
                        auto clearTempi = coeffi[s][g * i + j];
                        clearTemp.insert(clearTemp.end(), clearTempi.begin(), clearTempi.end());
                        if ((flagRem == 0) && (s == levelBudget - flagRem - 1)) {
                            // do the scaling only at the last set of coefficients
                            for (uint32_t k = 0; k < clearTemp.size(); k++) {
                                clearTemp[k] *= scale;
                            }
                        }

                        auto rotateTemp      = Rotate(clearTemp, rot);
                        result[s][g * i + j] = MakeAuxPlaintext(cc, paramsVector[s], rotateTemp, 1,
                                                                level0 + compositeDegree * s, rotateTemp.size());
                    }
                }
            }
        }

        if (flagRem) {
            int32_t s = levelBudget - flagRem;
            for (int32_t i = 0; i < bRem; i++) {
#pragma omp parallel for
                for (int32_t j = 0; j < gRem; j++) {
                    if (gRem * i + j != static_cast<int32_t>(numRotationsRem)) {
                        uint32_t rot = ReduceRotation(-gRem * i * (1 << (s * layersCollapse)), M / 4);
                        // concatenate the coefficients horizontally on their third dimension, which corresponds to the # of slots
                        auto clearTemp  = coeff[s][gRem * i + j];
                        auto clearTempi = coeffi[s][gRem * i + j];
                        clearTemp.insert(clearTemp.end(), clearTempi.begin(), clearTempi.end());
                        for (uint32_t k = 0; k < clearTemp.size(); k++) {
                            clearTemp[k] *= scale;
                        }

                        auto rotateTemp         = Rotate(clearTemp, rot);
                        result[s][gRem * i + j] = MakeAuxPlaintext(cc, paramsVector[s], rotateTemp, 1,
                                                                   level0 + compositeDegree * s, rotateTemp.size());
                    }
                }
            }
        }
    }
    return result;
}

//------------------------------------------------------------------------------
// EVALUATION: CoeffsToSlots and SlotsToCoeffs
//------------------------------------------------------------------------------

Ciphertext<DCRTPoly> FHECKKSRNS::EvalLinearTransform(const std::vector<ReadOnlyPlaintext>& A,
                                                     ConstCiphertext<DCRTPoly> ct) const {
    uint32_t slots = A.size();

    auto pair = m_bootPrecomMap.find(slots);
    if (pair == m_bootPrecomMap.end()) {
        std::string errorMsg(std::string("Precomputations for ") + std::to_string(slots) +
                             std::string(" slots were not generated") +
                             std::string(" Need to call EvalBootstrapSetup and EvalBootstrapKeyGen to proceed"));
        OPENFHE_THROW(errorMsg);
    }
    const std::shared_ptr<CKKSBootstrapPrecom> precom = pair->second;

    auto cc = ct->GetCryptoContext();
    // Computing the baby-step bStep and the giant-step gStep.
    uint32_t bStep = (precom->m_dim1 == 0) ? ceil(sqrt(slots)) : precom->m_dim1;
    uint32_t gStep = ceil(static_cast<double>(slots) / bStep);

    uint32_t M = cc->GetCyclotomicOrder();
    uint32_t N = cc->GetRingDimension();

    // computes the NTTs for each CRT limb (for the hoisted automorphisms used
    // later on)
    auto digits = cc->EvalFastRotationPrecompute(ct);

    std::vector<Ciphertext<DCRTPoly>> fastRotation(bStep - 1);

    // hoisted automorphisms
#pragma omp parallel for
    for (uint32_t j = 1; j < bStep; j++) {
        fastRotation[j - 1] = cc->EvalFastRotationExt(ct, j, digits, true);
    }

    Ciphertext<DCRTPoly> result;
    DCRTPoly first;

    for (uint32_t j = 0; j < gStep; j++) {
        Ciphertext<DCRTPoly> inner = EvalMultExt(cc->KeySwitchExt(ct, true), A[bStep * j]);
        for (uint32_t i = 1; i < bStep; i++) {
            if (bStep * j + i < slots) {
                EvalAddExtInPlace(inner, EvalMultExt(fastRotation[i - 1], A[bStep * j + i]));
            }
        }

        if (j == 0) {
            first         = cc->KeySwitchDownFirstElement(inner);
            auto elements = inner->GetElements();
            elements[0].SetValuesToZero();
            inner->SetElements(std::move(elements));
            result = inner;
        }
        else {
            inner = cc->KeySwitchDown(inner);
            // Find the automorphism index that corresponds to rotation index index.
            uint32_t autoIndex = FindAutomorphismIndex2nComplex(bStep * j, M);
            std::vector<uint32_t> map(N);
            PrecomputeAutoMap(N, autoIndex, &map);
            DCRTPoly firstCurrent = inner->GetElements()[0].AutomorphismTransform(autoIndex, map);
            first += firstCurrent;

            auto innerDigits = cc->EvalFastRotationPrecompute(inner);
            EvalAddExtInPlace(result, cc->EvalFastRotationExt(inner, bStep * j, innerDigits, false));
        }
    }

    result        = cc->KeySwitchDown(result);
    auto elements = result->GetElements();
    elements[0] += first;
    result->SetElements(std::move(elements));

    return result;
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalCoeffsToSlots(const std::vector<std::vector<ReadOnlyPlaintext>>& A,
                                                   ConstCiphertext<DCRTPoly> ctxt) const {
    uint32_t slots = ctxt->GetSlots();

    auto pair = m_bootPrecomMap.find(slots);
    if (pair == m_bootPrecomMap.end()) {
        std::string errorMsg(std::string("Precomputations for ") + std::to_string(slots) +
                             std::string(" slots were not generated") +
                             std::string(" Need to call EvalBootstrapSetup and EvalBootstrapKeyGen to proceed"));
        OPENFHE_THROW(errorMsg);
    }
    const std::shared_ptr<CKKSBootstrapPrecom> precom = pair->second;

    auto cc    = ctxt->GetCryptoContext();
    uint32_t M = cc->GetCyclotomicOrder();
    uint32_t N = cc->GetRingDimension();

    int32_t levelBudget     = precom->m_paramsEnc[CKKS_BOOT_PARAMS::LEVEL_BUDGET];
    int32_t layersCollapse  = precom->m_paramsEnc[CKKS_BOOT_PARAMS::LAYERS_COLL];
    int32_t remCollapse     = precom->m_paramsEnc[CKKS_BOOT_PARAMS::LAYERS_REM];
    int32_t numRotations    = precom->m_paramsEnc[CKKS_BOOT_PARAMS::NUM_ROTATIONS];
    int32_t b               = precom->m_paramsEnc[CKKS_BOOT_PARAMS::BABY_STEP];
    int32_t g               = precom->m_paramsEnc[CKKS_BOOT_PARAMS::GIANT_STEP];
    int32_t numRotationsRem = precom->m_paramsEnc[CKKS_BOOT_PARAMS::NUM_ROTATIONS_REM];
    int32_t bRem            = precom->m_paramsEnc[CKKS_BOOT_PARAMS::BABY_STEP_REM];
    int32_t gRem            = precom->m_paramsEnc[CKKS_BOOT_PARAMS::GIANT_STEP_REM];

    int32_t stop    = -1;
    int32_t flagRem = 0;

    auto algo                = cc->GetScheme();
    const auto cryptoParams  = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();

    if (remCollapse != 0) {
        stop    = 0;
        flagRem = 1;
    }

    // precompute the inner and outer rotations
    std::vector<std::vector<int32_t>> rot_in(levelBudget);
    for (uint32_t i = 0; i < static_cast<uint32_t>(levelBudget); i++) {
        if (flagRem == 1 && i == 0) {
            // remainder corresponds to index 0 in encoding and to last index in decoding
            rot_in[i] = std::vector<int32_t>(numRotationsRem + 1);
        }
        else {
            rot_in[i] = std::vector<int32_t>(numRotations + 1);
        }
    }

    std::vector<std::vector<int32_t>> rot_out(levelBudget);
    for (uint32_t i = 0; i < static_cast<uint32_t>(levelBudget); i++) {
        rot_out[i] = std::vector<int32_t>(b + bRem);
    }

    for (int32_t s = levelBudget - 1; s > stop; s--) {
        for (int32_t j = 0; j < g; j++) {
            rot_in[s][j] = ReduceRotation((j - static_cast<int32_t>((numRotations + 1) / 2) + 1) *
                                              (1 << ((s - flagRem) * layersCollapse + remCollapse)),
                                          slots);
        }

        for (int32_t i = 0; i < b; i++) {
            rot_out[s][i] = ReduceRotation((g * i) * (1 << ((s - flagRem) * layersCollapse + remCollapse)), M / 4);
        }
    }

    if (flagRem) {
        for (int32_t j = 0; j < gRem; j++) {
            rot_in[stop][j] = ReduceRotation((j - static_cast<int32_t>((numRotationsRem + 1) / 2) + 1), slots);
        }

        for (int32_t i = 0; i < bRem; i++) {
            rot_out[stop][i] = ReduceRotation((gRem * i), M / 4);
        }
    }

    Ciphertext<DCRTPoly> result = ctxt->Clone();

    // hoisted automorphisms
    for (int32_t s = levelBudget - 1; s > stop; s--) {
        if (s != levelBudget - 1) {
            algo->ModReduceInternalInPlace(result, compositeDegree);
        }

        // computes the NTTs for each CRT limb (for the hoisted automorphisms used later on)
        auto digits = cc->EvalFastRotationPrecompute(result);

        std::vector<Ciphertext<DCRTPoly>> fastRotation(g);
#pragma omp parallel for
        for (int32_t j = 0; j < g; j++) {
            if (rot_in[s][j] != 0) {
                fastRotation[j] = cc->EvalFastRotationExt(result, rot_in[s][j], digits, true);
            }
            else {
                fastRotation[j] = cc->KeySwitchExt(result, true);
            }
        }

        Ciphertext<DCRTPoly> outer;
        DCRTPoly first;
        for (int32_t i = 0; i < b; i++) {
            // for the first iteration with j=0:
            int32_t G                  = g * i;
            Ciphertext<DCRTPoly> inner = EvalMultExt(fastRotation[0], A[s][G]);
            // continue the loop
            for (int32_t j = 1; j < g; j++) {
                if ((G + j) != static_cast<int32_t>(numRotations)) {
                    EvalAddExtInPlace(inner, EvalMultExt(fastRotation[j], A[s][G + j]));
                }
            }

            if (i == 0) {
                first         = cc->KeySwitchDownFirstElement(inner);
                auto elements = inner->GetElements();
                elements[0].SetValuesToZero();
                inner->SetElements(std::move(elements));
                outer = inner;
            }
            else {
                if (rot_out[s][i] != 0) {
                    inner = cc->KeySwitchDown(inner);
                    // Find the automorphism index that corresponds to rotation index index.
                    uint32_t autoIndex = FindAutomorphismIndex2nComplex(rot_out[s][i], M);
                    std::vector<uint32_t> map(N);
                    PrecomputeAutoMap(N, autoIndex, &map);
                    first += inner->GetElements()[0].AutomorphismTransform(autoIndex, map);
                    auto innerDigits = cc->EvalFastRotationPrecompute(inner);
                    EvalAddExtInPlace(outer, cc->EvalFastRotationExt(inner, rot_out[s][i], innerDigits, false));
                }
                else {
                    first += cc->KeySwitchDownFirstElement(inner);
                    auto elements = inner->GetElements();
                    elements[0].SetValuesToZero();
                    inner->SetElements(std::move(elements));
                    EvalAddExtInPlace(outer, inner);
                }
            }
        }
        result                          = cc->KeySwitchDown(outer);
        std::vector<DCRTPoly>& elements = result->GetElements();
        elements[0] += first;
    }

    if (flagRem) {
        algo->ModReduceInternalInPlace(result, compositeDegree);

        // computes the NTTs for each CRT limb (for the hoisted automorphisms used later on)
        auto digits = cc->EvalFastRotationPrecompute(result);
        std::vector<Ciphertext<DCRTPoly>> fastRotation(gRem);

#pragma omp parallel for
        for (int32_t j = 0; j < gRem; j++) {
            if (rot_in[stop][j] != 0) {
                fastRotation[j] = cc->EvalFastRotationExt(result, rot_in[stop][j], digits, true);
            }
            else {
                fastRotation[j] = cc->KeySwitchExt(result, true);
            }
        }

        Ciphertext<DCRTPoly> outer;
        DCRTPoly first;
        for (int32_t i = 0; i < bRem; i++) {
            Ciphertext<DCRTPoly> inner;
            // for the first iteration with j=0:
            int32_t GRem = gRem * i;
            inner        = EvalMultExt(fastRotation[0], A[stop][GRem]);
            // continue the loop
            for (int32_t j = 1; j < gRem; j++) {
                if ((GRem + j) != static_cast<int32_t>(numRotationsRem)) {
                    EvalAddExtInPlace(inner, EvalMultExt(fastRotation[j], A[stop][GRem + j]));
                }
            }

            if (i == 0) {
                first         = cc->KeySwitchDownFirstElement(inner);
                auto elements = inner->GetElements();
                elements[0].SetValuesToZero();
                inner->SetElements(std::move(elements));
                outer = inner;
            }
            else {
                if (rot_out[stop][i] != 0) {
                    inner = cc->KeySwitchDown(inner);
                    // Find the automorphism index that corresponds to rotation index index.
                    uint32_t autoIndex = FindAutomorphismIndex2nComplex(rot_out[stop][i], M);
                    std::vector<uint32_t> map(N);
                    PrecomputeAutoMap(N, autoIndex, &map);
                    first += inner->GetElements()[0].AutomorphismTransform(autoIndex, map);
                    auto innerDigits = cc->EvalFastRotationPrecompute(inner);
                    EvalAddExtInPlace(outer, cc->EvalFastRotationExt(inner, rot_out[stop][i], innerDigits, false));
                }
                else {
                    first += cc->KeySwitchDownFirstElement(inner);
                    auto elements = inner->GetElements();
                    elements[0].SetValuesToZero();
                    inner->SetElements(std::move(elements));
                    EvalAddExtInPlace(outer, inner);
                }
            }
        }

        result                          = cc->KeySwitchDown(outer);
        std::vector<DCRTPoly>& elements = result->GetElements();
        elements[0] += first;
    }

    return result;
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalSlotsToCoeffs(const std::vector<std::vector<ReadOnlyPlaintext>>& A,
                                                   ConstCiphertext<DCRTPoly> ctxt) const {
    uint32_t slots = ctxt->GetSlots();

    auto pair = m_bootPrecomMap.find(slots);
    if (pair == m_bootPrecomMap.end()) {
        std::string errorMsg(std::string("Precomputations for ") + std::to_string(slots) +
                             std::string(" slots were not generated") +
                             std::string(" Need to call EvalBootstrapSetup and EvalBootstrapKeyGen to proceed"));
        OPENFHE_THROW(errorMsg);
    }

    const std::shared_ptr<CKKSBootstrapPrecom> precom = pair->second;

    auto cc = ctxt->GetCryptoContext();

    uint32_t M = cc->GetCyclotomicOrder();
    uint32_t N = cc->GetRingDimension();

    int32_t levelBudget     = precom->m_paramsDec[CKKS_BOOT_PARAMS::LEVEL_BUDGET];
    int32_t layersCollapse  = precom->m_paramsDec[CKKS_BOOT_PARAMS::LAYERS_COLL];
    int32_t remCollapse     = precom->m_paramsDec[CKKS_BOOT_PARAMS::LAYERS_REM];
    int32_t numRotations    = precom->m_paramsDec[CKKS_BOOT_PARAMS::NUM_ROTATIONS];
    int32_t b               = precom->m_paramsDec[CKKS_BOOT_PARAMS::BABY_STEP];
    int32_t g               = precom->m_paramsDec[CKKS_BOOT_PARAMS::GIANT_STEP];
    int32_t numRotationsRem = precom->m_paramsDec[CKKS_BOOT_PARAMS::NUM_ROTATIONS_REM];
    int32_t bRem            = precom->m_paramsDec[CKKS_BOOT_PARAMS::BABY_STEP_REM];
    int32_t gRem            = precom->m_paramsDec[CKKS_BOOT_PARAMS::GIANT_STEP_REM];

    auto algo                = cc->GetScheme();
    const auto cryptoParams  = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();

    int32_t flagRem = 0;

    if (remCollapse != 0) {
        flagRem = 1;
    }

    // precompute the inner and outer rotations

    std::vector<std::vector<int32_t>> rot_in(levelBudget);
    for (uint32_t i = 0; i < static_cast<uint32_t>(levelBudget); i++) {
        if (flagRem == 1 && i == static_cast<uint32_t>(levelBudget - 1)) {
            // remainder corresponds to index 0 in encoding and to last index in decoding
            rot_in[i] = std::vector<int32_t>(numRotationsRem + 1);
        }
        else {
            rot_in[i] = std::vector<int32_t>(numRotations + 1);
        }
    }

    std::vector<std::vector<int32_t>> rot_out(levelBudget);
    for (uint32_t i = 0; i < static_cast<uint32_t>(levelBudget); i++) {
        rot_out[i] = std::vector<int32_t>(b + bRem);
    }

    for (int32_t s = 0; s < levelBudget - flagRem; s++) {
        for (int32_t j = 0; j < g; j++) {
            rot_in[s][j] = ReduceRotation(
                (j - static_cast<int32_t>((numRotations + 1) / 2) + 1) * (1 << (s * layersCollapse)), M / 4);
        }

        for (int32_t i = 0; i < b; i++) {
            rot_out[s][i] = ReduceRotation((g * i) * (1 << (s * layersCollapse)), M / 4);
        }
    }

    if (flagRem) {
        int32_t s = levelBudget - flagRem;
        for (int32_t j = 0; j < gRem; j++) {
            rot_in[s][j] = ReduceRotation(
                (j - static_cast<int32_t>((numRotationsRem + 1) / 2) + 1) * (1 << (s * layersCollapse)), M / 4);
        }

        for (int32_t i = 0; i < bRem; i++) {
            rot_out[s][i] = ReduceRotation((gRem * i) * (1 << (s * layersCollapse)), M / 4);
        }
    }

    //  No need for Encrypted Bit Reverse
    Ciphertext<DCRTPoly> result = ctxt->Clone();

    // hoisted automorphisms
    for (int32_t s = 0; s < levelBudget - flagRem; s++) {
        if (s != 0) {
            algo->ModReduceInternalInPlace(result, compositeDegree);
        }
        // computes the NTTs for each CRT limb (for the hoisted automorphisms used later on)
        auto digits = cc->EvalFastRotationPrecompute(result);

        std::vector<Ciphertext<DCRTPoly>> fastRotation(g);
#pragma omp parallel for
        for (int32_t j = 0; j < g; j++) {
            if (rot_in[s][j] != 0) {
                fastRotation[j] = cc->EvalFastRotationExt(result, rot_in[s][j], digits, true);
            }
            else {
                fastRotation[j] = cc->KeySwitchExt(result, true);
            }
        }

        Ciphertext<DCRTPoly> outer;
        DCRTPoly first;
        for (int32_t i = 0; i < b; i++) {
            Ciphertext<DCRTPoly> inner;
            // for the first iteration with j=0:
            int32_t G = g * i;
            inner     = EvalMultExt(fastRotation[0], A[s][G]);
            // continue the loop
            for (int32_t j = 1; j < g; j++) {
                if ((G + j) != static_cast<int32_t>(numRotations)) {
                    EvalAddExtInPlace(inner, EvalMultExt(fastRotation[j], A[s][G + j]));
                }
            }

            if (i == 0) {
                first         = cc->KeySwitchDownFirstElement(inner);
                auto elements = inner->GetElements();
                elements[0].SetValuesToZero();
                inner->SetElements(std::move(elements));
                outer = inner;
            }
            else {
                if (rot_out[s][i] != 0) {
                    inner = cc->KeySwitchDown(inner);
                    // Find the automorphism index that corresponds to rotation index index.
                    uint32_t autoIndex = FindAutomorphismIndex2nComplex(rot_out[s][i], M);
                    std::vector<uint32_t> map(N);
                    PrecomputeAutoMap(N, autoIndex, &map);
                    first += inner->GetElements()[0].AutomorphismTransform(autoIndex, map);
                    auto innerDigits = cc->EvalFastRotationPrecompute(inner);
                    EvalAddExtInPlace(outer, cc->EvalFastRotationExt(inner, rot_out[s][i], innerDigits, false));
                }
                else {
                    first += cc->KeySwitchDownFirstElement(inner);
                    auto elements = inner->GetElements();
                    elements[0].SetValuesToZero();
                    inner->SetElements(std::move(elements));
                    EvalAddExtInPlace(outer, inner);
                }
            }
        }

        result                          = cc->KeySwitchDown(outer);
        std::vector<DCRTPoly>& elements = result->GetElements();
        elements[0] += first;
    }

    if (flagRem) {
        algo->ModReduceInternalInPlace(result, compositeDegree);
        // computes the NTTs for each CRT limb (for the hoisted automorphisms used later on)
        auto digits = cc->EvalFastRotationPrecompute(result);
        std::vector<Ciphertext<DCRTPoly>> fastRotation(gRem);

        int32_t s = levelBudget - flagRem;
#pragma omp parallel for
        for (int32_t j = 0; j < gRem; j++) {
            if (rot_in[s][j] != 0) {
                fastRotation[j] = cc->EvalFastRotationExt(result, rot_in[s][j], digits, true);
            }
            else {
                fastRotation[j] = cc->KeySwitchExt(result, true);
            }
        }

        Ciphertext<DCRTPoly> outer;
        DCRTPoly first;
        for (int32_t i = 0; i < bRem; i++) {
            Ciphertext<DCRTPoly> inner;
            // for the first iteration with j=0:
            int32_t GRem = gRem * i;
            inner        = EvalMultExt(fastRotation[0], A[s][GRem]);
            // continue the loop
            for (int32_t j = 1; j < gRem; j++) {
                if ((GRem + j) != static_cast<int32_t>(numRotationsRem))
                    EvalAddExtInPlace(inner, EvalMultExt(fastRotation[j], A[s][GRem + j]));
            }

            if (i == 0) {
                first         = cc->KeySwitchDownFirstElement(inner);
                auto elements = inner->GetElements();
                elements[0].SetValuesToZero();
                inner->SetElements(std::move(elements));
                outer = inner;
            }
            else {
                if (rot_out[s][i] != 0) {
                    inner = cc->KeySwitchDown(inner);
                    // Find the automorphism index that corresponds to rotation index index.
                    uint32_t autoIndex = FindAutomorphismIndex2nComplex(rot_out[s][i], M);
                    std::vector<uint32_t> map(N);
                    PrecomputeAutoMap(N, autoIndex, &map);
                    first += inner->GetElements()[0].AutomorphismTransform(autoIndex, map);
                    auto innerDigits = cc->EvalFastRotationPrecompute(inner);
                    EvalAddExtInPlace(outer, cc->EvalFastRotationExt(inner, rot_out[s][i], innerDigits, false));
                }
                else {
                    first += cc->KeySwitchDownFirstElement(inner);
                    auto elements = inner->GetElements();
                    elements[0].SetValuesToZero();
                    inner->SetElements(std::move(elements));
                    EvalAddExtInPlace(outer, inner);
                }
            }
        }

        result                          = cc->KeySwitchDown(outer);
        std::vector<DCRTPoly>& elements = result->GetElements();
        elements[0] += first;
    }

    return result;
}

uint32_t FHECKKSRNS::GetBootstrapDepth(uint32_t approxModDepth, const std::vector<uint32_t>& levelBudget,
                                       SecretKeyDist secretKeyDist) {
    if (secretKeyDist == UNIFORM_TERNARY) {
        approxModDepth += R_UNIFORM - 1;
    }

    return approxModDepth + levelBudget[0] + levelBudget[1];
}

uint32_t FHECKKSRNS::GetBootstrapDepth(const std::vector<uint32_t>& levelBudget, SecretKeyDist secretKeyDist) {
    uint32_t approxModDepth = GetModDepthInternal(secretKeyDist);

    return approxModDepth + levelBudget[0] + levelBudget[1];
}
//------------------------------------------------------------------------------
// Auxiliary Bootstrap Functions
//------------------------------------------------------------------------------
uint32_t FHECKKSRNS::GetBootstrapDepthInternal(uint32_t approxModDepth, const std::vector<uint32_t>& levelBudget,
                                               const CryptoContextImpl<DCRTPoly>& cc) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());
    return GetBootstrapDepth(approxModDepth, levelBudget, cryptoParams->GetSecretKeyDist());
}

uint32_t FHECKKSRNS::GetModDepthInternal(SecretKeyDist secretKeyDist) {
    if (secretKeyDist == UNIFORM_TERNARY) {
        return GetMultiplicativeDepthByCoeffVector(g_coefficientsUniform, false) + R_UNIFORM;
    }
    else {
        return GetMultiplicativeDepthByCoeffVector(g_coefficientsSparse, false) + R_SPARSE;
    }
}

void FHECKKSRNS::AdjustCiphertext(Ciphertext<DCRTPoly>& ciphertext, double correction) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());

    auto cc                  = ciphertext->GetCryptoContext();
    auto algo                = cc->GetScheme();
    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();

    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO || cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT ||
        cryptoParams->GetScalingTechnique() == COMPOSITESCALINGAUTO ||
        cryptoParams->GetScalingTechnique() == COMPOSITESCALINGMANUAL) {
        uint32_t lvl       = cryptoParams->GetScalingTechnique() != FLEXIBLEAUTOEXT ? 0 : 1;
        double targetSF    = cryptoParams->GetScalingFactorReal(lvl);
        double sourceSF    = ciphertext->GetScalingFactor();
        uint32_t numTowers = ciphertext->GetElements()[0].GetNumOfElements();
        double modToDrop = cryptoParams->GetElementParams()->GetParams()[numTowers - 1]->GetModulus().ConvertToDouble();
        for (uint32_t j = 2; j <= compositeDegree; ++j) {
            modToDrop *= cryptoParams->GetElementParams()->GetParams()[numTowers - j]->GetModulus().ConvertToDouble();
        }

        // in the case of FLEXIBLEAUTO, we need to bring the ciphertext to the right scale using a
        // a scaling multiplication. Note the at currently FLEXIBLEAUTO is only supported for NATIVEINT = 64.
        // So the other branch is for future purposes (in case we decide to add add the FLEXIBLEAUTO support
        // for NATIVEINT = 128.
#if NATIVEINT != 128
        // Scaling down the message by a correction factor to emulate using a larger q0.
        // This step is needed so we could use a scaling factor of up to 2^59 with q9 ~= 2^60.
        double adjustmentFactor = (targetSF / sourceSF) * (modToDrop / sourceSF) * std::pow(2, -correction);
#else
        double adjustmentFactor = (targetSF / sourceSF) * (modToDrop / sourceSF);
#endif
        cc->EvalMultInPlace(ciphertext, adjustmentFactor);

        algo->ModReduceInternalInPlace(ciphertext, compositeDegree);
        ciphertext->SetScalingFactor(targetSF);
    }
    else {
#if NATIVEINT != 128
        // Scaling down the message by a correction factor to emulate using a larger q0.
        // This step is needed so we could use a scaling factor of up to 2^59 with q9 ~= 2^60.
        cc->EvalMultInPlace(ciphertext, std::pow(2, -correction));
        algo->ModReduceInternalInPlace(ciphertext, compositeDegree);
#endif
    }
}

void FHECKKSRNS::ExtendCiphertext(std::vector<DCRTPoly>& ctxtDCRT, const CryptoContextImpl<DCRTPoly>& cc,
                                  const std::shared_ptr<DCRTPoly::Params> elementParamsRaisedPtr) const {
    // TODO: YSP We should be able to use one of the DCRTPoly methods for this; If not, we can define a new method there and use it here

    // CompositeDegree = 2: [a]_q0q1     =     [a*q1^-1]_q0 *     q1 + [a*q0^-1]_q1 *q0
    // CompositeDegree = 3: [a]_q0q1q2   =   [a*q1q2^-1]_q0 *   q1q2 + [a*q0q2^-1]_q1 *q0q2 + [a*q0q1^-1]_q2 *q0q1
    // CompositeDegree = 4: [a]_q0q1q2q3 = [a*q1q2q3^-1]_q0 * q1q2q3 + [a*q0q2q3^-1]_q1 * q0q2q3 + [a*q0q1q3^-1]_q2 * q0q1q3 + [a*q0q1q2^-1]_q3 * q0q1q2

    const auto cryptoParams  = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());
    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();

    std::vector<NativeInteger> qj(compositeDegree);
    for (uint32_t j = 0; j < compositeDegree; ++j) {
        qj[j] = elementParamsRaisedPtr->GetParams()[j]->GetModulus().ConvertToInt();
    }

    std::vector<NativeInteger> qhat_modqj(compositeDegree);
    qhat_modqj[0] = qj[1].Mod(qj[0]);
    qhat_modqj[1] = qj[0].Mod(qj[1]);

    std::vector<NativeInteger> qhat_inv_modqj(compositeDegree);

    for (uint32_t d = 2; d < compositeDegree; d++) {
        for (uint32_t j = 0; j < d; ++j) {
            qhat_modqj[j] = qj[d].ModMul(qhat_modqj[j], qj[j]);
        }
        qhat_modqj[d] = qj[1].ModMul(qj[0], qj[d]);
        for (uint32_t j = 2; j < d; ++j) {
            qhat_modqj[d] = qj[j].ModMul(qhat_modqj[d], qj[d]);
        }
    }

    for (uint32_t j = 0; j < compositeDegree; ++j) {
        qhat_inv_modqj[j] = qhat_modqj[j].ModInverse(qj[j]);
    }

    NativeInteger qjProduct =
        std::accumulate(qj.begin() + 1, qj.end(), NativeInteger{1}, std::multiplies<NativeInteger>());
    uint32_t init_element_index = compositeDegree;
    for (size_t i = 0; i < ctxtDCRT.size(); i++) {
        std::vector<DCRTPoly> temp(compositeDegree + 1, DCRTPoly(elementParamsRaisedPtr, COEFFICIENT));
        std::vector<DCRTPoly> ctxtDCRT_modq(compositeDegree, DCRTPoly(elementParamsRaisedPtr, COEFFICIENT));

        ctxtDCRT[i].SetFormat(COEFFICIENT);
        for (size_t j = 0; j < ctxtDCRT[i].GetNumOfElements(); j++) {
            for (size_t k = 0; k < compositeDegree; k++)
                ctxtDCRT_modq[k].SetElementAtIndex(j, ctxtDCRT[i].GetElementAtIndex(j) * qhat_inv_modqj[k]);
        }
        //=========================================================================================================
        temp[0] = ctxtDCRT_modq[0].GetElementAtIndex(0);
        for (auto& el : temp[0].GetAllElements()) {
            el *= qjProduct;
        }
        //=========================================================================================================
        for (size_t d = 1; d < compositeDegree; d++) {
            temp[init_element_index] = ctxtDCRT_modq[d].GetElementAtIndex(d);

            for (size_t k = 0; k < compositeDegree; k++) {
                if (k != d) {
                    temp[d].SetElementAtIndex(k, temp[0].GetElementAtIndex(k) * qj[k]);
                }
            }
            //=========================================================================================================
            NativeInteger qjProductD{1};
            for (size_t k = 0; k < compositeDegree; k++) {
                if (k != d)
                    qjProductD *= qj[k];
            }

            for (size_t j = compositeDegree; j < elementParamsRaisedPtr->GetParams().size(); j++) {
                auto value = temp[init_element_index].GetElementAtIndex(j) * qjProductD;
                temp[d].SetElementAtIndex(j, value);
            }
            //=========================================================================================================
            {
                auto value = temp[init_element_index].GetElementAtIndex(d) * qjProductD;
                temp[d].SetElementAtIndex(d, value);
            }
            //=========================================================================================================
            temp[0] += temp[d];
        }

        temp[0].SetFormat(EVALUATION);
        ctxtDCRT[i] = temp[0];
    }
}

void FHECKKSRNS::ApplyDoubleAngleIterations(Ciphertext<DCRTPoly>& ciphertext, uint32_t numIter) const {
    auto cc = ciphertext->GetCryptoContext();

    int32_t r = numIter;
    for (int32_t j = 1; j < r + 1; j++) {
        cc->EvalSquareInPlace(ciphertext);
        ciphertext    = cc->EvalAdd(ciphertext, ciphertext);
        double scalar = -1.0 / std::pow((2.0 * M_PI), std::pow(2.0, j - r));
        cc->EvalAddInPlace(ciphertext, scalar);
        cc->ModReduceInPlace(ciphertext);
    }
}

#if NATIVEINT == 128
Plaintext FHECKKSRNS::MakeAuxPlaintext(const CryptoContextImpl<DCRTPoly>& cc, const std::shared_ptr<ParmType> params,
                                       const std::vector<std::complex<double>>& value, size_t noiseScaleDeg,
                                       uint32_t level, uint32_t slots) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());

    double scFact = cryptoParams->GetScalingFactorReal(level);

    Plaintext p = Plaintext(std::make_shared<CKKSPackedEncoding>(params, cc.GetEncodingParams(), value, noiseScaleDeg,
                                                                 level, scFact, slots, COMPLEX));

    DCRTPoly& plainElement = p->GetElement<DCRTPoly>();

    uint32_t N = cc.GetRingDimension();

    std::vector<std::complex<double>> inverse = value;

    inverse.resize(slots);

    DiscreteFourierTransform::FFTSpecialInv(inverse, N * 2);
    uint64_t pBits = cc.GetEncodingParams()->GetPlaintextModulus();

    double powP      = std::pow(2.0, MAX_DOUBLE_PRECISION);
    int32_t pCurrent = pBits - MAX_DOUBLE_PRECISION;

    std::vector<int128_t> temp(2 * slots);
    for (size_t i = 0; i < slots; ++i) {
        // extract the mantissa of real part and multiply it by 2^52
        int32_t n1 = 0;
        double dre = std::frexp(inverse[i].real(), &n1) * powP;
        // extract the mantissa of imaginary part and multiply it by 2^52
        int32_t n2 = 0;
        double dim = std::frexp(inverse[i].imag(), &n2) * powP;

        // Check for possible overflow
        if (is128BitOverflow(dre) || is128BitOverflow(dim)) {
            DiscreteFourierTransform::FFTSpecial(inverse, N * 2);

            double invLen = static_cast<double>(inverse.size());
            double factor = 2 * M_PI * i;

            double realMax = -1, imagMax = -1;
            uint32_t realMaxIdx = -1, imagMaxIdx = -1;

            for (uint32_t idx = 0; idx < inverse.size(); idx++) {
                // exp( j*2*pi*n*k/N )
                std::complex<double> expFactor = {cos((factor * idx) / invLen), sin((factor * idx) / invLen)};

                // X[k] * exp( j*2*pi*n*k/N )
                std::complex<double> prodFactor = inverse[idx] * expFactor;

                double realVal = prodFactor.real();
                double imagVal = prodFactor.imag();

                if (realVal > realMax) {
                    realMax    = realVal;
                    realMaxIdx = idx;
                }
                if (imagVal > imagMax) {
                    imagMax    = imagVal;
                    imagMaxIdx = idx;
                }
            }

            auto scaledInputSize = ceil(log2(dre));

            std::stringstream buffer;
            buffer << std::endl
                   << "Overflow in data encoding - scaled input is too large to fit "
                      "into a NativeInteger (60 bits). Try decreasing scaling factor."
                   << std::endl;
            buffer << "Overflow at slot number " << i << std::endl;
            buffer << "- Max real part contribution from input[" << realMaxIdx << "]: " << realMax << std::endl;
            buffer << "- Max imaginary part contribution from input[" << imagMaxIdx << "]: " << imagMax << std::endl;
            buffer << "Scaling factor is " << ceil(log2(powP)) << " bits " << std::endl;
            buffer << "Scaled input is " << scaledInputSize << " bits " << std::endl;
            OPENFHE_THROW(buffer.str());
        }

        int64_t re64       = std::llround(dre);
        int32_t pRemaining = pCurrent + n1;
        int128_t re        = 0;
        if (pRemaining < 0) {
            re = re64 >> (-pRemaining);
        }
        else {
            int128_t pPowRemaining = ((int128_t)1) << pRemaining;
            re                     = pPowRemaining * re64;
        }

        int64_t im64 = std::llround(dim);
        pRemaining   = pCurrent + n2;
        int128_t im  = 0;
        if (pRemaining < 0) {
            im = im64 >> (-pRemaining);
        }
        else {
            int128_t pPowRemaining = (static_cast<int64_t>(1)) << pRemaining;
            im                     = pPowRemaining * im64;
        }

        temp[i]         = (re < 0) ? Max128BitValue() + re : re;
        temp[i + slots] = (im < 0) ? Max128BitValue() + im : im;

        if (is128BitOverflow(temp[i]) || is128BitOverflow(temp[i + slots])) {
            OPENFHE_THROW("Overflow, try to decrease scaling factor");
        }
    }

    const std::shared_ptr<ILDCRTParams<BigInteger>> bigParams        = plainElement.GetParams();
    const std::vector<std::shared_ptr<ILNativeParams>>& nativeParams = bigParams->GetParams();

    for (size_t i = 0; i < nativeParams.size(); i++) {
        NativeVector nativeVec(N, nativeParams[i]->GetModulus());
        FitToNativeVector(N, temp, Max128BitValue(), &nativeVec);
        NativePoly element = plainElement.GetElementAtIndex(i);
        element.SetValues(std::move(nativeVec), Format::COEFFICIENT);
        plainElement.SetElementAtIndex(i, std::move(element));
    }

    uint32_t numTowers = nativeParams.size();
    std::vector<DCRTPoly::Integer> moduli(numTowers);
    for (uint32_t i = 0; i < numTowers; i++) {
        moduli[i] = nativeParams[i]->GetModulus();
    }

    DCRTPoly::Integer intPowP = NativeInteger(1) << pBits;
    std::vector<DCRTPoly::Integer> crtPowP(numTowers, intPowP);

    auto currPowP = crtPowP;

    // We want to scale temp by 2^(pd), and the loop starts from j=2
    // because temp is already scaled by 2^p in the re/im loop above,
    // and currPowP already is 2^p.
    for (size_t i = 2; i < noiseScaleDeg; i++) {
        currPowP = CKKSPackedEncoding::CRTMult(currPowP, crtPowP, moduli);
    }

    if (noiseScaleDeg > 1) {
        plainElement = plainElement.Times(currPowP);
    }

    p->SetFormat(Format::EVALUATION);
    p->SetScalingFactor(pow(p->GetScalingFactor(), noiseScaleDeg));

    return p;
}
#else
Plaintext FHECKKSRNS::MakeAuxPlaintext(const CryptoContextImpl<DCRTPoly>& cc, const std::shared_ptr<ParmType> params,
                                       const std::vector<std::complex<double>>& value, size_t noiseScaleDeg,
                                       uint32_t level, uint32_t slots) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());

    double scFact = cryptoParams->GetScalingFactorReal(level);

    Plaintext p = Plaintext(std::make_shared<CKKSPackedEncoding>(params, cc.GetEncodingParams(), value, noiseScaleDeg,
                                                                 level, scFact, slots, COMPLEX));

    DCRTPoly& plainElement = p->GetElement<DCRTPoly>();

    uint32_t N = cc.GetRingDimension();

    std::vector<std::complex<double>> inverse = value;

    inverse.resize(slots);

    DiscreteFourierTransform::FFTSpecialInv(inverse, N * 2);
    double powP = scFact;

    // Compute approxFactor, a value to scale down by, in case the value exceeds a 64-bit integer.
    constexpr int32_t MAX_BITS_IN_WORD = 61;

    int32_t logc = std::numeric_limits<int32_t>::min();
    for (uint32_t i = 0; i < slots; ++i) {
        inverse[i] *= powP;
        if (inverse[i].real() != 0) {
            int32_t logci = static_cast<int32_t>(ceil(log2(std::abs(inverse[i].real()))));
            if (logc < logci)
                logc = logci;
        }
        if (inverse[i].imag() != 0) {
            int32_t logci = static_cast<int32_t>(ceil(log2(std::abs(inverse[i].imag()))));
            if (logc < logci)
                logc = logci;
        }
    }
    logc = (logc == std::numeric_limits<int32_t>::min()) ? 0 : logc;
    if (logc < 0)
        OPENFHE_THROW("Scaling factor too small");

    int32_t logValid    = (logc <= MAX_BITS_IN_WORD) ? logc : MAX_BITS_IN_WORD;
    int32_t logApprox   = logc - logValid;
    double approxFactor = pow(2, logApprox);

    std::vector<int64_t> temp(2 * slots);

    for (size_t i = 0; i < slots; ++i) {
        // Scale down by approxFactor in case the value exceeds a 64-bit integer.
        double dre = inverse[i].real() / approxFactor;
        double dim = inverse[i].imag() / approxFactor;

        // Check for possible overflow
        if (is64BitOverflow(dre) || is64BitOverflow(dim)) {
            DiscreteFourierTransform::FFTSpecial(inverse, N * 2);

            double invLen = static_cast<double>(inverse.size());
            double factor = 2 * M_PI * i;

            double realMax = -1, imagMax = -1;
            uint32_t realMaxIdx = -1, imagMaxIdx = -1;

            for (uint32_t idx = 0; idx < inverse.size(); idx++) {
                // exp( j*2*pi*n*k/N )
                std::complex<double> expFactor = {cos((factor * idx) / invLen), sin((factor * idx) / invLen)};

                // X[k] * exp( j*2*pi*n*k/N )
                std::complex<double> prodFactor = inverse[idx] * expFactor;

                double realVal = prodFactor.real();
                double imagVal = prodFactor.imag();

                if (realVal > realMax) {
                    realMax    = realVal;
                    realMaxIdx = idx;
                }
                if (imagVal > imagMax) {
                    imagMax    = imagVal;
                    imagMaxIdx = idx;
                }
            }

            auto scaledInputSize = ceil(log2(dre));

            std::stringstream buffer;
            buffer << std::endl
                   << "Overflow in data encoding - scaled input is too large to fit "
                      "into a NativeInteger (60 bits). Try decreasing scaling factor."
                   << std::endl;
            buffer << "Overflow at slot number " << i << std::endl;
            buffer << "- Max real part contribution from input[" << realMaxIdx << "]: " << realMax << std::endl;
            buffer << "- Max imaginary part contribution from input[" << imagMaxIdx << "]: " << imagMax << std::endl;
            buffer << "Scaling factor is " << ceil(log2(powP)) << " bits " << std::endl;
            buffer << "Scaled input is " << scaledInputSize << " bits " << std::endl;
            OPENFHE_THROW(buffer.str());
        }

        int64_t re = std::llround(dre);
        int64_t im = std::llround(dim);

        temp[i]         = (re < 0) ? Max64BitValue() + re : re;
        temp[i + slots] = (im < 0) ? Max64BitValue() + im : im;
    }

    const std::shared_ptr<ILDCRTParams<BigInteger>> bigParams        = plainElement.GetParams();
    const std::vector<std::shared_ptr<ILNativeParams>>& nativeParams = bigParams->GetParams();

    for (size_t i = 0; i < nativeParams.size(); i++) {
        NativeVector nativeVec(N, nativeParams[i]->GetModulus());
        FitToNativeVector(N, temp, Max64BitValue(), &nativeVec);
        NativePoly element = plainElement.GetElementAtIndex(i);
        element.SetValues(std::move(nativeVec), Format::COEFFICIENT);
        plainElement.SetElementAtIndex(i, std::move(element));
    }

    uint32_t numTowers = nativeParams.size();
    std::vector<DCRTPoly::Integer> moduli(numTowers);
    for (uint32_t i = 0; i < numTowers; i++) {
        moduli[i] = nativeParams[i]->GetModulus();
    }

    std::vector<DCRTPoly::Integer> crtPowP;
    if (cryptoParams->GetScalingTechnique() == COMPOSITESCALINGAUTO ||
        cryptoParams->GetScalingTechnique() == COMPOSITESCALINGMANUAL) {
        // Duhyeong: Support the case powP > 2^64
        //           Later we might need to use the NATIVE_INT=128 version of FHECKKSRNS::MakeAuxPlaintext for higher precision
        int32_t logPowP = static_cast<int32_t>(ceil(log2(fabs(powP))));

        if (logPowP > 64) {
            // Compute approxFactor, a value to scale down by, in case the value exceeds a 64-bit integer.
            logValid               = (logPowP <= LargeScalingFactorConstants::MAX_BITS_IN_WORD) ?
                                         logPowP :
                                         LargeScalingFactorConstants::MAX_BITS_IN_WORD;
            int32_t logApprox_PowP = logPowP - logValid;
            if (logApprox_PowP > 0) {
                int32_t logStep           = (logApprox <= LargeScalingFactorConstants::MAX_LOG_STEP) ?
                                                logApprox_PowP :
                                                LargeScalingFactorConstants::MAX_LOG_STEP;
                DCRTPoly::Integer intStep = static_cast<uint64_t>(1) << logStep;
                std::vector<DCRTPoly::Integer> crtApprox(numTowers, intStep);
                logApprox_PowP -= logStep;
                while (logApprox_PowP > 0) {
                    int32_t logStep           = (logApprox <= LargeScalingFactorConstants::MAX_LOG_STEP) ?
                                                    logApprox :
                                                    LargeScalingFactorConstants::MAX_LOG_STEP;
                    DCRTPoly::Integer intStep = static_cast<uint64_t>(1) << logStep;
                    std::vector<DCRTPoly::Integer> crtStep(numTowers, intStep);
                    crtApprox = CKKSPackedEncoding::CRTMult(crtApprox, crtStep, moduli);
                    logApprox_PowP -= logStep;
                }
                crtPowP = CKKSPackedEncoding::CRTMult(crtPowP, crtApprox, moduli);
            }
            else {
                double approxFactor = pow(2, logApprox_PowP);
                DCRTPoly::Integer intPowP{static_cast<uint64_t>(std::llround(powP / approxFactor))};
                crtPowP = std::vector<DCRTPoly::Integer>(numTowers, intPowP);
            }
        }
        else {
            DCRTPoly::Integer intPowP{static_cast<uint64_t>(std::llround(powP))};
            crtPowP = std::vector<DCRTPoly::Integer>(numTowers, intPowP);
        }
    }
    else {
        DCRTPoly::Integer intPowP{static_cast<uint64_t>(std::llround(powP))};
        crtPowP = std::vector<DCRTPoly::Integer>(numTowers, intPowP);
    }

    auto currPowP = crtPowP;

    // We want to scale temp by 2^(pd), and the loop starts from j=2
    // because temp is already scaled by 2^p in the re/im loop above,
    // and currPowP already is 2^p.
    for (size_t i = 2; i < noiseScaleDeg; i++) {
        currPowP = CKKSPackedEncoding::CRTMult(currPowP, crtPowP, moduli);
    }

    if (noiseScaleDeg > 1) {
        plainElement = plainElement.Times(currPowP);
    }

    // Scale back up by the approxFactor to get the correct encoding.
    if (logApprox > 0) {
        int32_t logStep = (logApprox <= MAX_LOG_STEP) ? logApprox : MAX_LOG_STEP;
        auto intStep    = DCRTPoly::Integer(static_cast<uint64_t>(1) << logStep);
        std::vector<DCRTPoly::Integer> crtApprox(numTowers, intStep);
        logApprox -= logStep;

        while (logApprox > 0) {
            logStep = (logApprox <= MAX_LOG_STEP) ? logApprox : MAX_LOG_STEP;
            intStep = DCRTPoly::Integer(static_cast<uint64_t>(1) << logStep);
            std::vector<DCRTPoly::Integer> crtSF(numTowers, intStep);
            crtApprox = CKKSPackedEncoding::CRTMult(crtApprox, crtSF, moduli);
            logApprox -= logStep;
        }
        plainElement = plainElement.Times(crtApprox);
    }

    p->SetFormat(Format::EVALUATION);
    p->SetScalingFactor(pow(p->GetScalingFactor(), noiseScaleDeg));

    return p;
}
#endif

Ciphertext<DCRTPoly> FHECKKSRNS::EvalMultExt(ConstCiphertext<DCRTPoly> ciphertext, ConstPlaintext plaintext) const {
    Ciphertext<DCRTPoly> result = ciphertext->Clone();
    std::vector<DCRTPoly>& cv   = result->GetElements();

    DCRTPoly pt = plaintext->GetElement<DCRTPoly>();
    pt.SetFormat(Format::EVALUATION);

    for (auto& c : cv) {
        c *= pt;
    }
    result->SetNoiseScaleDeg(result->GetNoiseScaleDeg() + plaintext->GetNoiseScaleDeg());
    result->SetScalingFactor(result->GetScalingFactor() * plaintext->GetScalingFactor());
    return result;
}

void FHECKKSRNS::EvalAddExtInPlace(Ciphertext<DCRTPoly>& ciphertext1, ConstCiphertext<DCRTPoly> ciphertext2) const {
    std::vector<DCRTPoly>& cv1       = ciphertext1->GetElements();
    const std::vector<DCRTPoly>& cv2 = ciphertext2->GetElements();

    for (size_t i = 0; i < cv1.size(); ++i) {
        cv1[i] += cv2[i];
    }
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalAddExt(ConstCiphertext<DCRTPoly> ciphertext1,
                                            ConstCiphertext<DCRTPoly> ciphertext2) const {
    Ciphertext<DCRTPoly> result = ciphertext1->Clone();
    EvalAddExtInPlace(result, ciphertext2);
    return result;
}

EvalKey<DCRTPoly> FHECKKSRNS::ConjugateKeyGen(const PrivateKey<DCRTPoly> privateKey) const {
    const auto cc = privateKey->GetCryptoContext();
    auto algo     = cc->GetScheme();

    const DCRTPoly& s = privateKey->GetPrivateElement();
    uint32_t N        = s.GetRingDimension();

    PrivateKey<DCRTPoly> privateKeyPermuted = std::make_shared<PrivateKeyImpl<DCRTPoly>>(cc);

    uint32_t index = 2 * N - 1;
    std::vector<uint32_t> vec(N);
    PrecomputeAutoMap(N, index, &vec);

    DCRTPoly sPermuted = s.AutomorphismTransform(index, vec);

    privateKeyPermuted->SetPrivateElement(std::move(sPermuted));
    privateKeyPermuted->SetKeyTag(privateKey->GetKeyTag());

    return algo->KeySwitchGen(privateKey, privateKeyPermuted);
}

Ciphertext<DCRTPoly> FHECKKSRNS::Conjugate(ConstCiphertext<DCRTPoly> ciphertext,
                                           const std::map<uint32_t, EvalKey<DCRTPoly>>& evalKeyMap) const {
    const std::vector<DCRTPoly>& cv = ciphertext->GetElements();
    uint32_t N                      = cv[0].GetRingDimension();

    std::vector<uint32_t> vec(N);
    PrecomputeAutoMap(N, 2 * N - 1, &vec);

    auto algo = ciphertext->GetCryptoContext()->GetScheme();

    Ciphertext<DCRTPoly> result = ciphertext->Clone();

    algo->KeySwitchInPlace(result, evalKeyMap.at(2 * N - 1));

    std::vector<DCRTPoly>& rcv = result->GetElements();

    rcv[0] = rcv[0].AutomorphismTransform(2 * N - 1, vec);
    rcv[1] = rcv[1].AutomorphismTransform(2 * N - 1, vec);

    return result;
}

void FHECKKSRNS::FitToNativeVector(uint32_t ringDim, const std::vector<int64_t>& vec, int64_t bigBound,
                                   NativeVector* nativeVec) const {
    if (nativeVec == nullptr)
        OPENFHE_THROW("The passed native vector is empty.");
    NativeInteger bigValueHf(bigBound >> 1);
    NativeInteger modulus(nativeVec->GetModulus());
    NativeInteger diff = bigBound - modulus;
    uint32_t dslots    = vec.size();
    uint32_t gap       = ringDim / dslots;
    for (uint32_t i = 0; i < vec.size(); i++) {
        NativeInteger n(vec[i]);
        if (n > bigValueHf) {
            (*nativeVec)[gap * i] = n.ModSub(diff, modulus);
        }
        else {
            (*nativeVec)[gap * i] = n.Mod(modulus);
        }
    }
}

#if NATIVEINT == 128
void FHECKKSRNS::FitToNativeVector(uint32_t ringDim, const std::vector<int128_t>& vec, int128_t bigBound,
                                   NativeVector* nativeVec) const {
    if (nativeVec == nullptr)
        OPENFHE_THROW("The passed native vector is empty.");
    NativeInteger bigValueHf((uint128_t)bigBound >> 1);
    NativeInteger modulus(nativeVec->GetModulus());
    NativeInteger diff = NativeInteger((uint128_t)bigBound) - modulus;
    uint32_t dslots    = vec.size();
    uint32_t gap       = ringDim / dslots;
    for (uint32_t i = 0; i < vec.size(); i++) {
        NativeInteger n((uint128_t)vec[i]);
        if (n > bigValueHf) {
            (*nativeVec)[gap * i] = n.ModSub(diff, modulus);
        }
        else {
            (*nativeVec)[gap * i] = n.Mod(modulus);
        }
    }
}
#endif

}  // namespace lbcrypto
