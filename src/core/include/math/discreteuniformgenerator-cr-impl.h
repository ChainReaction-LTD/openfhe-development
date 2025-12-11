// //==================================================================================
// // BSD 2-Clause License
// //
// // Copyright (c) 2014-2023, NJIT, Duality Technologies Inc. and other contributors
// //
// // All rights reserved.
// //
// // Author TPOC: contact@openfhe.org
// //
// // Redistribution and use in source and binary forms, with or without
// // modification, are permitted provided that the following conditions are met:
// //
// // 1. Redistributions of source code must retain the above copyright notice, this
// //    list of conditions and the following disclaimer.
// //
// // 2. Redistributions in binary form must reproduce the above copyright notice,
// //    this list of conditions and the following disclaimer in the documentation
// //    and/or other materials provided with the distribution.
// //
// // THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// // AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// // IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// // DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// // FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// // DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// // SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// // CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// // OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// // OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// //==================================================================================

// /*
//   This code provides generation of uniform distributions of discrete values. Discrete uniform generator relies on
//   the built-in C++ generator for 32-bit unsigned integers defined in <random>
//  */

// #ifndef LBCRYPTO_INC_MATH_DISCRETEUNIFORMGENERATOR_IMPL_H_
// #define LBCRYPTO_INC_MATH_DISCRETEUNIFORMGENERATOR_IMPL_H_

// #include "math/discreteuniformgenerator-cr.h"
// #include "math/distributiongenerator.h"
// #include "utils/exception.h"
// #include "utils/prng/shake128engine.h"

// namespace lbcrypto {

// template <typename VecType>
// DiscreteUniformGeneratorCRImpl<VecType>::DiscreteUniformGeneratorCRImpl(const typename VecType::Integer& modulus) {
//     this->SetModulus(modulus);
// }

// template <typename VecType>
// void DiscreteUniformGeneratorCRImpl<VecType>::SetModulus(const typename VecType::Integer& modulus) {
//     m_modulus = modulus;

//     // Get the number of chunks in the modulus
//     // 1 is subtracted to make sure the last chunk is fully used by the modulus
//     m_chunksPerValue = (m_modulus.GetMSB() - 1) / DUG_CHUNK_WIDTH;

//     m_shiftChunk = m_chunksPerValue * DUG_CHUNK_WIDTH;

//     m_bound =
//         std::uniform_int_distribution<uint32_t>::param_type(DUG_CHUNK_MIN, (m_modulus >> m_shiftChunk).ConvertToInt());
// }

// template <typename VecType>
// typename VecType::Integer DiscreteUniformGeneratorCRImpl<VecType>::GenerateInteger() const {
//     if (m_modulus == typename VecType::Integer(0))
//         OPENFHE_THROW("0 modulus?");

//     // Determine which engine to use
//     PRNG& engine = (m_customPrng != nullptr) ? *m_customPrng : PseudoRandomNumberGenerator::GetPRNG();
//     std::uniform_int_distribution<uint32_t> dist(DUG_CHUNK_MIN, DUG_CHUNK_MAX);
//     while (true) {
//         typename VecType::Integer result{};
//         for (uint32_t i{0}, shift{0}; i < m_chunksPerValue; ++i, shift += DUG_CHUNK_WIDTH)
//             result += typename VecType::Integer{dist(engine)} << shift;
//         result += typename VecType::Integer{dist(engine, m_bound)} << m_shiftChunk;

//         if (result < m_modulus)
//             return result;
//     }
// }

// template <typename VecType>
// VecType DiscreteUniformGeneratorImpl<VecType>::GenerateVector(const uint32_t size) const {
//     VecType v(size, m_modulus);
//     for (uint32_t i = 0; i < size; ++i)
//         v[i] = this->GenerateInteger();
//     return v;
// }

// template <typename VecType>
// VecType DiscreteUniformGeneratorImpl<VecType>::GenerateVector(const uint32_t size,
//                                                               const typename VecType::Integer& modulus) {
//     this->SetModulus(modulus);

//     if (size != 65536)
//         OPENFHE_THROW("vector size must be 65536");
        
//     VecType v(size, m_modulus);

//     for (uint16_t seg_i = 0; seg_i < 2048; ++seg_i){

//         std::unique_ptr<PRNG> myShakePrng = std::make_unique<Shake128Engine>(m_seed,m_qIndex,seg_i);
//         this->SetCustomPRNG(std::move(myShakePrng));

//         for (uint32_t i = 0; i < 32; ++i){
//             v[(seg_i*32) + i] = this->GenerateInteger();
//         }
//     }


//     return v;
// }

// }  // namespace lbcrypto

// #endif
