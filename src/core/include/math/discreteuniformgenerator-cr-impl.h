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
  This code provides generation of uniform distributions of discrete values. Discrete uniform generator relies on
  the built-in C++ generator for 32-bit unsigned integers defined in <random>
 */

#ifndef LBCRYPTO_INC_MATH_DISCRETEUNIFORMGENERATORCR_IMPL_H_
#define LBCRYPTO_INC_MATH_DISCRETEUNIFORMGENERATORCR_IMPL_H_

#include "math/discreteuniformgenerator-cr.h"
#include "math/discreteuniformgenerator.h"
#include "utils/exception.h"
#include "utils/prng/shake128engine.h"

namespace lbcrypto {

inline bool is_normalize(int32_t x, NativeVector::Integer q) {
    NativeVector::Integer qh = q / 2;
    int64_t x_64             = static_cast<int64_t>(x);
    return (-qh.ConvertToInt<int64_t>() <= x_64) && (x_64 <= qh.ConvertToInt<int64_t>());
}

// -----------------------------------------------------------------------------
// Function: extract_signed_b_bits
// -----------------------------------------------------------------------------
inline int32_t extract_signed_b_bits(int32_t w, size_t b) {
    assert(b > 0 && b <= 32);

    // 1. Extract the signed MSB (W[31])
    // Note: Arithmetic right shift on negative signed integers is implementation-defined
    // prior to C++20, but standard in C++20. Most compilers do arithmetic shift by default.
    int32_t msb = w >> 31;

    // 2. Extract the (b-1) least significant bits
    uint32_t mask    = (1U << (b - 1)) - 1;
    int32_t low_bits = w & static_cast<int32_t>(mask);

    // 3. Concatenate: shift msb to top and OR with low bits.
    // We cast `msb` to uint32_t before shifting to avoid Undefined Behavior
    // (shifting a negative signed integer left is UB in older C++ standards).
    uint32_t msb_shifted = static_cast<uint32_t>(msb) << (b - 1);

    // Combine and cast back to signed
    return static_cast<int32_t>(msb_shifted | static_cast<uint32_t>(low_bits));
}

inline int8_t FindQindex(const std::vector<NativeVector::Integer>& moduliList, const NativeVector::Integer& modulus) {
    for (size_t i = 0; i < moduliList.size(); i++) {
        if (moduliList[i] == modulus) {
            return i;
        }
    }
    return -1;
}

inline NativeVector::Integer DiscreteUniformGeneratorCRImpl::GenerateInteger() const {
    OPENFHE_THROW("GenerateInteger operation not supported");
}

inline NativeVector DiscreteUniformGeneratorCRImpl::GenerateVector(const uint32_t size,
                                                                   const NativeVector::Integer& modulus) {
    this->SetModulus(modulus);

    if (size != 65536)
        OPENFHE_THROW("vector size must be 65536");

    NativeVector v(size, this->m_modulus);
    std::uniform_int_distribution<uint32_t> dist(DUG_CHUNK_MIN, DUG_CHUNK_MAX);
    int8_t qIndex = FindQindex(this->m_moduli, this->m_modulus);

    size_t b = static_cast<size_t>(std::ceil(std::log2(modulus.ConvertToDouble())));

    for (uint16_t seg_i = 0; seg_i < 2048; ++seg_i) {
        std::unique_ptr<PRNG> shake128engine = std::make_unique<Shake128Engine>(m_seed, m_salt, qIndex, seg_i);

        size_t valid_words_idx = 0;

        for (uint32_t i = 0; i < 42; ++i) {
            uint32_t word = dist(*shake128engine);

            int32_t x = extract_signed_b_bits(word, b);

            if (is_normalize(x, modulus)) {
                if (x < 0) {
                    x += modulus.ConvertToInt();
                }
                v[(seg_i * 32) + valid_words_idx] = x;
                valid_words_idx++;
            }
            if (valid_words_idx == 32) {
                break;
            }
        }
        // if we tried 42 words and didn't reach to 32 valid words
        if (valid_words_idx < 32) {
            OPENFHE_THROW("Prng Reject Segment");
        }
    }

    return v;
}

}  // namespace lbcrypto

#endif
