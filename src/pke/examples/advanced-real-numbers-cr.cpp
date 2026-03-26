

/*
  Advanced examples CKKS - Suitable for Chain Reaction PRNG implementation
 */

// Define PROFILE to enable TIC-TOC timing measurements
#define PROFILE

#include "openfhe.h"

using namespace lbcrypto;

void HybridKeySwitchingDemo1();


int main(int argc, char* argv[]) {
    HybridKeySwitchingDemo1();
    return 0;
}




void HybridKeySwitchingDemo1() {
    /*
   * Please refer to comments in the demo-simple_real_number.cpp
   * for a brief introduction on what key switching is and to
   * find reference for HYBRID key switching.
   *
   * In this demo, we focus on how to choose the number of digits
   * in HYBRID key switching, and how that affects the usage and
   * efficiency of the CKKS scheme.
   *
   */

    std::cout << "\n\n\n ===== HybridKeySwitchingDemo1 ============= " << std::endl;
    /*
   * dnum is the number of large digits in HYBRID decomposition
   *
   * If not supplied (or value 0 is supplied), the default value is
   * set as follows:
   * - If multiplicative depth is > 3, then dnum = 3 digits are used.
   * - If multiplicative depth is 3, then dnum = 2 digits are used.
   * - If multiplicative depth is < 3, then dnum is set to be equal to
   * multDepth+1
   */
    uint32_t dnum = 2;
    /* To understand the effects of changing dnum, it is important to
   * understand how the ciphertext modulus size changes during key
   * switching.
   *
   * In our RNS implementation of CKKS, every ciphertext corresponds
   * to a large number (which is represented as small integers in RNS)
   * modulo a ciphertext modulus Q, which is defined as the product of
   * (multDepth+1) prime numbers: Q = q0 * q1 * ... * qL. Each qi is
   * selected to be close to the scaling factor D=2^p, hence the total
   * size of Q is approximately:
   *
   * sizeof(Q) = (multDepth+1)*scaleModSize.
   *
   * HYBRID key switching takes a number d that's defined modulo Q,
   * and performs 4 steps:
   * 1 - Digit decomposition:
   *     Split d into dnum digits - the size of each digit is roughly
   *     ceil(sizeof(Q)/dnum)
   * 2 - Extend ciphertext modulus from Q to Q*P
   *     Here P is a product of special primes
   * 3 - Multiply extended component with key switching key
   * 4 - Decrease the ciphertext modulus back down to Q
   *
   * It's not necessary to understand how all these stages work, as
   * long as it's clear that the size of the ciphertext modulus is
   * increased from sizeof(Q) to sizeof(Q)+sizeof(P) in stage 2. P
   * is always set to be as small as possible, as long as sizeof(P)
   * is larger than the size of the largest digit, i.e., than
   * ceil(sizeof(Q)/dnum). Therefore, the size of P is inversely
   * related to the number of digits, so the more digits we have, the
   * smaller P has to be.
   *
   * The tradeoff here is that more digits means that the digit
   * decomposition stage becomes more expensive, but the maximum
   * size of the ciphertext modulus Q*P becomes smaller. Since
   * the size of Q*P determines the necessary ring dimension to
   * achieve a certain security level, more digits can in some
   * cases mean that we can use smaller ring dimension and get
   * better performance overall.
   *
   * We show this effect with demos HybridKeySwitchingDemo1 and
   * HybridKeySwitchingDemo2.
   *
   */

    uint32_t batchSize = 8;
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetRingDim(65536);
    parameters.SetMultiplicativeDepth(5);
    parameters.SetScalingModSize(27);
    parameters.SetFirstModSize(27);
    parameters.SetBatchSize(batchSize);
    parameters.SetScalingTechnique(FIXEDAUTO);
    parameters.SetNumLargeDigits(dnum);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl;

    std::cout << "- Using HYBRID key switching with " << dnum << " digits" << std::endl << std::endl;

    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    auto keys = cc->KeyGen();
    cc->EvalRotateKeyGen(keys.secretKey, {1, -2});

    // Input
    std::vector<double> x = {1.0, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7};
    Plaintext ptxt        = cc->MakeCKKSPackedPlaintext(x);

    std::cout << "Input x: " << ptxt << std::endl;

    auto c = cc->Encrypt(keys.publicKey, ptxt);

    TimeVar t;
    TIC(t);
    auto cRot1         = cc->EvalRotate(c, 1);
    auto cRot2         = cc->EvalRotate(cRot1, -2);
    double time2digits = TOC(t);
    // Take note and compare the runtime to the runtime
    // of the same computation in the next demo.

    Plaintext result;
    std::cout.precision(8);

    cc->Decrypt(keys.secretKey, cRot2, &result);
    result->SetLength(batchSize);
    std::cout << "x rotate by -1 = " << result << std::endl;
    std::cout << " - 2 rotations with HYBRID (2 digits) took " << time2digits << "ms" << std::endl;

    /* Interested users may set the following if to 1
   * to observe the prime numbers comprising Q and P,
   * and how these change with the number of digits
   * dnum.
   */
    // #if 0
    // const auto cryptoParamsCKKS =
    //     std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(
    //         cc->GetCryptoParameters());

    // auto paramsQ = cc->GetElementParams()->GetParams();
    // std::cout << "\nModuli in Q:" << std::endl;
    // for (uint32_t i = 0; i < paramsQ.size(); i++) {
    //   // q0 is a bit larger because its default size is 60 bits.
    //   // One can change this by supplying the firstModSize argument
    //   // in genCryptoContextCKKS.
    //   std::cout << "q" << i << ": " << paramsQ[i]->GetModulus() << std::endl;
    // }
    // auto paramsQP = cryptoParamsCKKS->GetParamsQP();
    // std::cout << "Moduli in P: " << std::endl;
    // BigInteger P = BigInteger(1);
    // for (uint32_t i = 0; i < paramsQP->GetParams().size(); i++) {
    //   if (i > paramsQ.size()) {
    //     P = P * BigInteger(paramsQP->GetParams()[i]->GetModulus());
    //     std::cout << "p" << i - paramsQ.size() << ": "
    //               << paramsQP->GetParams()[i]->GetModulus() << std::endl;
    //   }
    // }
    // auto QBitLength = cc->GetModulus().GetLengthForBase(2);
    // auto PBitLength = P.GetLengthForBase(2);
    // std::cout << "\nQ = " << cc->GetModulus() << " (bit length: " << QBitLength
    //           << ")" << std::endl;
    // std::cout << "P = " << P << " (bit length: " << PBitLength << ")"
    //           << std::endl;
    // std::cout << "Total bit-length of ciphertext modulus: "
    //           << QBitLength + PBitLength << std::endl;
    // std::cout << "Given this ciphertext modulus, a ring dimension of "
    //           << cc->GetRingDimension() << " gives us 128-bit security."
    //           << std::endl;
    // #endif
}

