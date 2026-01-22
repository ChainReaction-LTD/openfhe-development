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

inline bool is_accepted(int32_t x, NativeVector::Integer q) {
    NativeVector::Integer qh = q / 2;
     int64_t x_64 = static_cast<int64_t>(x);
    return (-qh.ConvertToInt<int64_t>() <= x_64) && (x_64 <= qh.ConvertToInt<int64_t>());
}


inline int32_t normalize(int32_t x, int32_t q) {
    // 1. Map to [0, q-1]
    int32_t val = x % q;
    if (val < 0) val += q;
    
    return val;
}

inline NativeVector::Integer DiscreteUniformGeneratorCRImpl::GenerateInteger() const{
    OPENFHE_THROW("GenerateInteger operation not supported");
}


inline NativeVector DiscreteUniformGeneratorCRImpl::GenerateVector(const uint32_t size,
                                                              const NativeVector::Integer& modulus){
    this->SetModulus(modulus);

    if (size != 65536)
        OPENFHE_THROW("vector size must be 65536");
    
    
    NativeVector v(size, this->m_modulus);
    std::uniform_int_distribution<uint32_t> dist(DUG_CHUNK_MIN, DUG_CHUNK_MAX);

    for (uint16_t seg_i = 0; seg_i < 2048; ++seg_i) {
        std::unique_ptr<PRNG> shake128engine = std::make_unique<Shake128Engine>(m_seed, m_salt, modulus.ConvertToInt(), seg_i);

        size_t valid_words_idx = 0;
        uint32_t n_q = (static_cast<uint32_t>((1ULL << 32) / modulus.ConvertToInt())) * modulus.ConvertToInt();
        int64_t n_q_h = static_cast<int64_t>(n_q) /2;

        for (uint32_t i = 0; i < 42; ++i) {
            uint32_t word = dist(*shake128engine);
            int32_t signed_word = static_cast<int32_t>(word);

            bool is_accepted = -n_q_h <= signed_word && signed_word < n_q_h;

            if (is_accepted) {
                v[(seg_i * 32) + valid_words_idx] = normalize(signed_word,modulus.ConvertToInt());
                valid_words_idx++;
            }
            if(valid_words_idx==32){
                break;
            }
            
        }
        // if we tried 42 words and didn't reach to 32 valid words
        if(valid_words_idx < 32){
             OPENFHE_THROW("Prng Reject Segment");
        }
      
    }


    return v;
}



}  // namespace lbcrypto

#endif
