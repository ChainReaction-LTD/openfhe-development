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
template <typename VecType>
class DiscreteUniformGeneratorCRImpl : public DiscreteUniformGeneratorImpl<VecType> {
public:
    DiscreteUniformGeneratorCRImpl(std::shared_ptr<lbcrypto::M4DCRTParams> params) {
        m_moduli = std::vector<typename VecType::Integer>(params->GetParams().size());
        for (size_t i = 0; i < params->GetParams().size(); i++) {
            m_moduli[i] = params->GetParams()[i]->GetModulus();
        }
    }

    void SetSeed(std::vector<u_int32_t> seed) {
        m_seed = seed;
    }

    void SetSalt(u_int32_t salt) {
        m_salt = salt;
    }
    // void SetModuliList(std::vector<typename VecType::Integer> moduli) {
    //     m_moduli = moduli;
    // }

    VecType GenerateVector(const uint32_t size, const typename VecType::Integer& modulus) override;
    typename VecType::Integer GenerateInteger() const override;

private:
    std::vector<uint32_t> m_seed;
    u_int32_t m_salt = 0;
    std::vector<typename VecType::Integer> m_moduli;
};

}  // namespace lbcrypto

#include "math/discreteuniformgenerator-cr-impl.h"

#endif  // LBCRYPTO_INC_MATH_DISCRETEUNIFORMGENERATORCR_H_
