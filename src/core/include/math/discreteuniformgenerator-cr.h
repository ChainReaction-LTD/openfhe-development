//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2023, NJIT, Duality Technologies Inc. and other contributors
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

/*
  This code provides generation of uniform distributions of discrete values. Discrete uniform generator
  relies on the built-in C++ generator for 32-bit unsigned integers defined in <random>
 */

#ifndef LBCRYPTO_INC_MATH_DISCRETEUNIFORMGENERATORCR_H_
#define LBCRYPTO_INC_MATH_DISCRETEUNIFORMGENERATORCR_H_

#include "math/distributiongenerator.h"

#include <limits>
#include <random>

namespace lbcrypto {

/**
 * @brief The class for Discrete Uniform Distribution generator over Zq.
 */
template <typename VecType>
class DiscreteUniformGeneratorCRImpl : public DiscreteUniformGeneratorImpl<VecType> {
public:
    void SetCustomPRNG(std::unique_ptr<PRNG> prng) {
        m_customPrng = std::move(prng);
    }

    void SetSeed(std::vector<u_int32_t> seed) {
        m_seed = seed;
    }

    void SetQIndex(u_int8_t qIndex) {
        m_qIndex = qIndex;
    }

private:
    std::vector<uint32_t> m_seed;
    std::unique_ptr<PRNG> m_customPrng = nullptr;
    u_int8_t m_qIndex;
};

}  // namespace lbcrypto

#endif  // LBCRYPTO_INC_MATH_DISCRETEUNIFORMGENERATORCR_H_
