
#include "openfhe.h"

#include "benchmark/benchmark.h"

#include <iostream>
#include <vector>
#include <random>

using namespace lbcrypto;

constexpr double minTime = 100.0;

// random number generator for benchmark
std::mt19937 rng(std::random_device{}());

CryptoContext<DCRTPoly> GetCKKSContext(usint batchSize, ScalingTechnique scalTech, usint dnum) {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetScalingModSize(50);
    parameters.SetBatchSize(batchSize);
    parameters.SetMultiplicativeDepth(5);
    parameters.SetScalingTechnique(scalTech);
    parameters.SetNumLargeDigits(dnum);
    parameters.SetKeySwitchTechnique(HYBRID);
    parameters.SetRingDim(1 << 14); // Set ring dimension to 16384

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    return cc;
}

std::vector<double> GenerateRandomVector(int size) {
    std::vector<double> vec(size);
    std::uniform_real_distribution<double> dist(-1.0, 1.0);
    for (int i = 0; i < size; ++i) {
        vec[i] = dist(rng);
    }
    return vec;
}

void PackUnpack(benchmark::State &state) {
    constexpr int batchSize = 8192;
    constexpr ScalingTechnique scalTech = FIXEDMANUAL;
    constexpr usint dnum = 3;

    auto cc = GetCKKSContext(batchSize, scalTech, dnum);
    auto keys = cc->KeyGen();

    std::vector<double> x1 = GenerateRandomVector(batchSize); // random plaintext

    while (state.KeepRunning()) {
        Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
        auto x2 = ptxt1->GetCKKSPackedValue();
        benchmark::DoNotOptimize(x2);
    }
}

BENCHMARK(PackUnpack)->Unit(benchmark::kMillisecond)->MinTime(minTime);

void EncryptDecrypt(benchmark::State &state) {
    constexpr int batchSize = 8192;
    constexpr ScalingTechnique scalTech = FIXEDMANUAL;
    constexpr usint dnum = 3;

    auto cc = GetCKKSContext(batchSize, scalTech, dnum);
    auto keys = cc->KeyGen();

    std::vector<double> x1 = GenerateRandomVector(batchSize); // random plaintext
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);

    Plaintext result;

    while (state.KeepRunning()) {
        auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
        cc->Decrypt(keys.secretKey, c1, &result);
        benchmark::DoNotOptimize(result);
    }
}

BENCHMARK(EncryptDecrypt)->Unit(benchmark::kMillisecond)->MinTime(minTime);

void AddCiphertext(benchmark::State &state) {
    constexpr int batchSize = 8192;
    constexpr ScalingTechnique scalTech = FIXEDMANUAL;
    constexpr usint dnum = 3;

    auto cc = GetCKKSContext(batchSize, scalTech, dnum);
    auto keys = cc->KeyGen();

    std::vector<double> x1 = GenerateRandomVector(batchSize); // random plaintext
    std::vector<double> x2 = GenerateRandomVector(batchSize); // random plaintext
        
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
    Plaintext ptxt2 = cc->MakeCKKSPackedPlaintext(x2);

    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
    auto c2 = cc->Encrypt(keys.publicKey, ptxt2);

    while (state.KeepRunning()) {
        auto cRes = cc->EvalAdd(c1, c2);
        benchmark::DoNotOptimize(cRes);
    }
}

BENCHMARK(AddCiphertext)->Unit(benchmark::kMillisecond)->MinTime(minTime);

void MultCiphertext(benchmark::State &state) {
    constexpr int batchSize = 8192;
    constexpr ScalingTechnique scalTech = FIXEDMANUAL;
    constexpr usint dnum = 3;

    auto cc = GetCKKSContext(batchSize, scalTech, dnum);
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    std::vector<double> x1 = GenerateRandomVector(batchSize); // random plaintext
    std::vector<double> x2 = GenerateRandomVector(batchSize); // random plaintext
        
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
    Plaintext ptxt2 = cc->MakeCKKSPackedPlaintext(x2);

    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
    auto c2 = cc->Encrypt(keys.publicKey, ptxt2);

    while (state.KeepRunning()) {
        auto cRes = cc->EvalMult(c1, c2);
        benchmark::DoNotOptimize(cRes);
    }
}

BENCHMARK(MultCiphertext)->Unit(benchmark::kMillisecond)->MinTime(minTime);

void Rescale(benchmark::State &state) {
    constexpr int batchSize = 8192;
    constexpr ScalingTechnique scalTech = FIXEDMANUAL;
    constexpr usint dnum = 3;

    auto cc = GetCKKSContext(batchSize, scalTech, dnum);
    auto keys = cc->KeyGen();

    std::vector<double> x1 = GenerateRandomVector(batchSize); // random plaintext
        
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
    auto c2 = c1;

    while (state.KeepRunning()) {
        c2 = c1;
        cc->Rescale(c2);
        benchmark::DoNotOptimize(c2);
    }
}

BENCHMARK(Rescale)->Unit(benchmark::kMillisecond)->MinTime(minTime);

void RotateCiphertext(benchmark::State &state) {
    constexpr int batchSize = 8192;
    constexpr ScalingTechnique scalTech = FIXEDMANUAL;
    constexpr usint dnum = 3;

    auto cc = GetCKKSContext(batchSize, scalTech, dnum);
    auto keys = cc->KeyGen();
    cc->EvalRotateKeyGen(keys.secretKey, {1});

    std::vector<double> x1 = GenerateRandomVector(batchSize); // random plaintext
        
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);

    while (state.KeepRunning()) {
        cc->EvalRotate(c1, 1);
        benchmark::DoNotOptimize(c1);
    }
}

BENCHMARK(RotateCiphertext)->Unit(benchmark::kMillisecond)->MinTime(minTime);

void Bootstrapping(benchmark::State &state) {
    CCParams<CryptoContextCKKSRNS> parameters;

    SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
    parameters.SetSecretKeyDist(secretKeyDist);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1 << 14);
    parameters.SetNumLargeDigits(3);
    parameters.SetKeySwitchTechnique(HYBRID);
    parameters.SetScalingModSize(50);
    parameters.SetScalingTechnique(FLEXIBLEAUTO);
    parameters.SetFirstModSize(58);

    std::vector<uint32_t> levelBudget = {3, 3};
    std::vector<uint32_t> bsgsDim = {0, 0};
    uint32_t levelsAvailableAfterBootstrap = 10;
    usint depth = levelsAvailableAfterBootstrap + FHECKKSRNS::GetBootstrapDepth(levelBudget, secretKeyDist);

    printf("Bootstrapping with depth %u\n", depth);
    parameters.SetMultiplicativeDepth(depth);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);
    cryptoContext->Enable(FHE);

    usint numSlots = 8192; // Number of slots for CKKS
    cryptoContext->EvalBootstrapSetup(levelBudget, bsgsDim, numSlots);
    auto keyPair = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    cryptoContext->EvalBootstrapKeyGen(keyPair.secretKey, numSlots);

    std::vector<double> x1 = GenerateRandomVector(numSlots); // random plaintext

    Plaintext ptxt = cryptoContext->MakeCKKSPackedPlaintext(x1, 1, depth - 1, nullptr, numSlots); // depth 1, levels 0
    ptxt->SetLength(numSlots);

    Ciphertext<DCRTPoly> ciph = cryptoContext->Encrypt(keyPair.publicKey, ptxt); // no levels left

    while(state.KeepRunning()) {
        auto ciphertextAfter = cryptoContext->EvalBootstrap(ciph);
    }
}

BENCHMARK(Bootstrapping)->Unit(benchmark::kMillisecond)->MinTime(minTime);

BENCHMARK_MAIN();