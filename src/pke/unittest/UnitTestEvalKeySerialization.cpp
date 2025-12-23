#include "gtest/gtest.h"
#include "openfhe.h"
#include "ciphertext-ser.h"
// Changed to CKKS headers to match your SetUp() parameters
#include "scheme/ckksrns/ckksrns-ser.h"
#include <sstream>
#include <cereal/types/optional.hpp>
#include <vector>
// Add other necessary includes
#include "utils/prng/shake128engine.h" 
#include "math/discreteuniformgenerator-cr.h" 

using namespace lbcrypto;

// --- 1. DEFINE THE FIXTURE CLASS FIRST ---
class EvalKeySerializationTest : public ::testing::Test {
protected:
    CryptoContext<DCRTPoly> cc;
    KeyPair<DCRTPoly> kp;

    // This runs before every TEST_F
    void SetUp() override {
        CCParams<CryptoContextCKKSRNS> parameters;
        // CKKS REQUIRED PARAMETERS
        parameters.SetMultiplicativeDepth(1);    // Usually required for CKKS
        parameters.SetScalingModSize(50);        // Usually required for CKKS
        parameters.SetFirstModSize(60);          // Usually required for CKKS
        parameters.SetSecurityLevel(HEStd_NotSet);
        parameters.SetRingDim(65536);

        cc = GenCryptoContext(parameters);
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);

    }
};
TEST_F(EvalKeySerializationTest, TestHybridKeySwitchGenSerialization) {
    
    KeyPair<DCRTPoly> kp1 = cc->KeyGen();
    KeyPair<DCRTPoly> kp2 = cc->KeyGen();

    // Create a KeySwitchHYBRID instance
    std::shared_ptr<KeySwitchBase<DCRTPoly>> keySwitchImpl = 
        std::make_shared<KeySwitchHYBRID>();

    // Generate the eval key
    EvalKey<DCRTPoly> ek = keySwitchImpl->KeySwitchGenInternal(kp1.secretKey, kp2.secretKey);

    // Test 1: Verify the key has valid vectors
    EXPECT_TRUE(ek != nullptr);
    EXPECT_FALSE(ek->GetAVector().empty());
    EXPECT_FALSE(ek->GetBVector().empty());
    EXPECT_EQ(ek->GetAVector().size(), ek->GetBVector().size());

    // 2. Serialize (should effectively save [bk, true, seed])
    std::stringstream ss1;
    Serial::Serialize(ek, ss1, SerType::BINARY);
    std::cout << "Size of ss1: " << ss1.str().size() << " bytes" << std::endl;
    // 3. Deserialize
    EvalKey<DCRTPoly> loadedKey1;
    Serial::Deserialize(loadedKey1, ss1, SerType::BINARY);
    
     // 4. Verify seed and AVector recovered
    EXPECT_TRUE(loadedKey1->GetSeed().has_value());
    EXPECT_EQ(loadedKey1->GetSeed().value(), ek->GetSeed());
    EXPECT_EQ(loadedKey1->GetBVector(), ek->GetBVector());
    EXPECT_EQ(loadedKey1->GetAVector(), ek->GetAVector());

  
}

TEST_F(EvalKeySerializationTest, TestNoSeedSerialization) {

    auto params = cc->GetElementParams();
    DiscreteUniformGeneratorImpl<NativeVector> dug;
  
    std::vector<DCRTPoly> av(3);
    std::vector<DCRTPoly> bv(3);
    for (size_t i = 0; i < 3; i++) {
        av[i] = DCRTPoly(dug, params, Format::EVALUATION);
        bv[i] = DCRTPoly(dug, params, Format::EVALUATION);
    }

    // 1. Create a key without a seed
    EvalKey<DCRTPoly> keyNoSeed = std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(cc);
    keyNoSeed->SetAVector(std::move(av));
    keyNoSeed->SetBVector(std::move(bv));

    // 2. Serialize (should effectively save [bk, false, ak_data...])
    std::stringstream ss2;
    Serial::Serialize(keyNoSeed, ss2, SerType::BINARY);
    
    std::cout << "Size of ss2: " << ss2.str().size() << " bytes" << std::endl;

    // 3. Deserialize
    EvalKey<DCRTPoly> loadedKey2;
    Serial::Deserialize(loadedKey2, ss2, SerType::BINARY);

    // 4. Verify seed is empty and AKey is loaded
    EXPECT_FALSE(loadedKey2->GetSeed().has_value());
    EXPECT_EQ(loadedKey2->GetAVector(), keyNoSeed->GetAVector());
    EXPECT_EQ(loadedKey2->GetBVector(), keyNoSeed->GetBVector());
}