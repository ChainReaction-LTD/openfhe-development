// Copyright (c) 2025 Chain Reaction LTD
// All rights reserved.
//
// This product is protected by copyright and distributed
// under license terms that restrict copying, distribution, and decompilation.

#ifndef LBCRYPTO_INC_MATH_DISCRETEUNIFORMGENERATORCR_H_
#define LBCRYPTO_INC_MATH_DISCRETEUNIFORMGENERATORCR_H_

#include "math/distributiongenerator.h"

#include <limits>
#include <random>
#include <vector>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <cassert>

namespace lbcrypto {

/**
 * @brief The class for Discrete Uniform Distribution generator over Zq.
 */
class DiscreteUniformGeneratorCRImpl : public DiscreteUniformGeneratorImpl<NativeVector>{
public:
    DiscreteUniformGeneratorCRImpl(std::vector<u_int32_t> seed) {
        assert(seed.size()==8);
        m_seed = seed;
    }
    void SetSalt(u_int32_t salt) {
        m_salt = salt;
    }

    NativeVector GenerateVector(const uint32_t size, const NativeVector::Integer& modulus) override;
    NativeVector::Integer GenerateInteger() const override;

private:
    std::vector<uint32_t> m_seed;
    u_int32_t m_salt = 0;
};

}  // namespace lbcrypto

#include "math/discreteuniformgenerator-cr-impl.h"

#endif  // LBCRYPTO_INC_MATH_DISCRETEUNIFORMGENERATORCR_H_
