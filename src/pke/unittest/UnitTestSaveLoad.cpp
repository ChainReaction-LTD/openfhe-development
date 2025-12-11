#include "gtest/gtest.h"
#include "openfhe.h"
#include "ciphertext-ser.h"
// Changed to CKKS headers to match your SetUp() parameters
#include "scheme/ckksrns/ckksrns-ser.h"
#include <sstream>
#include <cereal/types/optional.hpp>
#include <vector>
// Add other necessary includes

using namespace lbcrypto;

// --- 1. DEFINE THE FIXTURE CLASS FIRST ---
class EvalKeyCompressionTest : public ::testing::Test {
protected:
    CryptoContext<DCRTPoly> cc;
    KeyPair<DCRTPoly> kp;

    // This runs before every TEST_F
    void SetUp() override {
        CCParams<CryptoContextCKKSRNS> parameters;
        // CKKS REQUIRED PARAMETERS

        cc = GenCryptoContext(parameters);
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);

        kp = cc->KeyGen();
    }
};
TEST_F(EvalKeyCompressionTest, TestOptionalSeedLogic) {
    // Create dummy vectors with valid 0-initialized polynomials
    auto params = cc->GetElementParams();
    DCRTPoly::DugType dug;

    std::vector<DCRTPoly> av(3);
    std::vector<DCRTPoly> bv(3);
    for (size_t i = 0; i < 3; i++) {
        av[i] = DCRTPoly(dug, params, Format::EVALUATION);
        bv[i] = DCRTPoly(dug, params, Format::EVALUATION);
    }

    // 1. Create a key manually with a seed
    EvalKey<DCRTPoly> keyWithSeed = std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(cc);
    keyWithSeed->SetBVector(bv);
    keyWithSeed->SetSeed(123456789);

    // 2. Serialize (should effectively save [bk, true, 123456789])
    std::stringstream ss1;
    Serial::Serialize(keyWithSeed, ss1, SerType::BINARY);

    // 3. Deserialize
    EvalKey<DCRTPoly> loadedKey1;
    Serial::Deserialize(loadedKey1, ss1, SerType::BINARY);

    // 4. Verify seed was recovered
    EXPECT_TRUE(loadedKey1->GetSeed().has_value());
    EXPECT_EQ(loadedKey1->GetSeed().value(), 123456789);
    EXPECT_EQ(loadedKey1->GetBVector(), keyWithSeed->GetBVector());

    // --- CASE 2: No Seed ---

    // 1. Create a key without a seed
    EvalKey<DCRTPoly> keyNoSeed = std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(cc);
    keyNoSeed->SetAVector(av);
    keyNoSeed->SetBVector(bv);

    // 2. Serialize (should effectively save [bk, false, ak_data...])
    std::stringstream ss2;
    Serial::Serialize(keyNoSeed, ss2, SerType::BINARY);

    // 3. Deserialize
    EvalKey<DCRTPoly> loadedKey2;
    Serial::Deserialize(loadedKey2, ss2, SerType::BINARY);

    // 4. Verify seed is empty and AKey is loaded
    EXPECT_FALSE(loadedKey2->GetSeed().has_value());
    EXPECT_EQ(loadedKey2->GetAVector(), keyNoSeed->GetAVector());
    EXPECT_EQ(loadedKey2->GetBVector(), keyNoSeed->GetBVector());
}