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

inline bool is_normalize(int32_t x, uint32_t q) {
    // Rust: let qh = q as i64 / 2;
    int64_t qh = static_cast<int64_t>(q) / 2;
    
    // Rust: let x = x as i64;
    int64_t x_64 = static_cast<int64_t>(x);

    // Rust: -qh <= x && x <= qh
    return (-qh <= x_64) && (x_64 <= qh);
}


// Helper to mimic i32::from_le_bytes specifically for Little Endian
// This ensures code works correctly even on Big Endian machines.
inline int32_t i32_from_le_bytes(const uint8_t* bytes) {
    uint32_t val = 
        static_cast<uint32_t>(bytes[0]) |
        (static_cast<uint32_t>(bytes[1]) << 8) |
        (static_cast<uint32_t>(bytes[2]) << 16) |
        (static_cast<uint32_t>(bytes[3]) << 24);
    
    int32_t result;
    std::memcpy(&result, &val, sizeof(result));
    return result;
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
    uint32_t mask = (1U << (b - 1)) - 1;
    int32_t low_bits = w & static_cast<int32_t>(mask);

    // 3. Concatenate: shift msb to top and OR with low bits.
    // We cast `msb` to uint32_t before shifting to avoid Undefined Behavior 
    // (shifting a negative signed integer left is UB in older C++ standards).
    uint32_t msb_shifted = static_cast<uint32_t>(msb) << (b - 1);
    
    // Combine and cast back to signed
    return static_cast<int32_t>(msb_shifted | static_cast<uint32_t>(low_bits));
}

// -----------------------------------------------------------------------------
// Function: extract_32_words_from_digest
// -----------------------------------------------------------------------------
inline std::array<int32_t, 32> extract_32_words_from_digest(const std::array<uint8_t, 168>& digest, uint32_t q) {
    std::vector<int32_t> valid_integers;
    valid_integers.reserve(32);

    // b = ceil(log2(q))
    size_t b = static_cast<size_t>(std::ceil(std::log2(static_cast<double>(q))));

    // Rust: digest.chunks_exact(4)
    // 168 bytes / 4 bytes per chunk = 42 chunks exactly.
    for (size_t i = 0; i < 42; ++i) {
        size_t offset = i * 4;
        
        // Read 4 bytes (Little Endian)
        int32_t num = i32_from_le_bytes(&digest[offset]);

        int32_t x = extract_signed_b_bits(num, b);

        if (is_normalize(x, q)) {
            valid_integers.push_back(x);
        }

        // Return immediately if we found 32 valid integers
        if (valid_integers.size() == 32) {
            std::array<int32_t, 32> result;
            std::memcpy(result.data(), valid_integers.data(), 32 * sizeof(int32_t));
            return result;
        }
    }

    // Rust: Err(ExecuteError::PrngRejectSegment)?
    OPENFHE_THROW("Prng Reject Segment");
}


inline int8_t FindQindex(const std::vector<NativeVector::Integer>& moduliList,const NativeVector::Integer& modulus){
    for (size_t i = 0; i < moduliList.size(); i++)
    {
        if(moduliList[i]==modulus){
            return i;
        }
    }
    return -1;    
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
    int8_t qIndex = FindQindex(this->m_moduli,this->m_modulus);
    
    for (uint16_t seg_i = 0; seg_i < 2048; ++seg_i){
        std::unique_ptr<PRNG> shake128engine = std::make_unique<Shake128Engine>(m_seed,m_salt,qIndex,seg_i);

        std::uniform_int_distribution<uint32_t> dist(DUG_CHUNK_MIN, DUG_CHUNK_MAX);
        
        std::array<uint8_t, 168> digest;
        
        // Generate 42 32-bit words and store as little-endian bytes in digest
        for (uint32_t i = 0; i < 42; ++i){
            uint32_t word = dist(*shake128engine);
            // Convert 32-bit word to 4 bytes (little-endian)
            digest[4*i]     = static_cast<uint8_t>(word & 0xFF);
            digest[4*i + 1] = static_cast<uint8_t>((word >> 8) & 0xFF);
            digest[4*i + 2] = static_cast<uint8_t>((word >> 16) & 0xFF);
            digest[4*i + 3] = static_cast<uint8_t>((word >> 24) & 0xFF);
        }
        std::array<int32_t, 32> words = extract_32_words_from_digest(digest, 0x7e0001);

        for (uint32_t i = 0; i < 32; ++i){
            v[(seg_i*32) + i] = words[i];
        }
    }


    return v;
}



}  // namespace lbcrypto

#endif
