#ifndef __SHAKE128ENGINE_H__
#define __SHAKE128ENGINE_H__

#include "utils/prng/prng.h"
#include <vector>
#include <array>
// Include the tiny_sha3 header (adjust path as needed)

#include "utils/exception.h"
#include <random>
#include <thread>

extern "C" {
    #include "sha3.h"
}

namespace lbcrypto {

inline std::vector<uint32_t> GenerateRandomSeed(size_t size) {
    std::vector<uint32_t> seed(size);
    std::random_device rd;
    for (size_t i = 0; i < size; ++i) {
        seed[i] = rd();
    }
    return seed;
}

class Shake128Engine : public PRNG {
public:
    // Buffer size (42 x 32-bit integers)
    enum { PRNG_BUFFER_SIZE = 42 };

    /**
     * @brief Constructor that accepts a seed vector
     * @param seed A vector of integers (or bytes) to seed the SHAKE state
     */
    explicit Shake128Engine(const std::vector<uint32_t>& seed, u_int32_t salt, u_int32_t q, u_int16_t seg_i) {
        assert(seed.size()==8); // 32 bytes

        // 1. Initialize the SHAKE128 context
        shake128_init(&ctx);

        // 2. Absorb the seed
        // We cast the uint32_t vector to bytes for absorption
        shake_update(&ctx, reinterpret_cast<const void*>(seed.data()), seed.size() * sizeof(uint32_t));
        shake_update(&ctx, reinterpret_cast<const void*>(&salt), sizeof(u_int32_t));
        shake_update(&ctx, reinterpret_cast<const void*>(&q), sizeof(u_int32_t));
        shake_update(&ctx, reinterpret_cast<const void*>(&seg_i), sizeof(uint16_t));

        shake_xof(&ctx);
        

        // 3. Prepare the buffer state
        m_bufferIndex = PRNG_BUFFER_SIZE;  // Force a refill on first use
    }

    ~Shake128Engine() = default;

    /**
     * @brief Main call to get a 32-bit random number
     */
    result_type operator()() override {
        // Refill buffer if empty
        if (m_bufferIndex >= PRNG_BUFFER_SIZE) {
            RefillBuffer();
        }

        // Return the next integer from the buffer
        result_type result = m_buffer[m_bufferIndex];
        m_bufferIndex++;
        return result;
    }
    

private:
    void RefillBuffer() {
        // Squeeze output from SHAKE128 directly into the buffer
        shake_out(&ctx, reinterpret_cast<void*>(m_buffer.data()), PRNG_BUFFER_SIZE * sizeof(result_type));

        m_bufferIndex = 0;
    }

    // SHAKE context from tiny_sha3
    sha3_ctx_t ctx;

    // Buffer to store random samples (reduces function call overhead)
    std::array<result_type, PRNG_BUFFER_SIZE> m_buffer;
    size_t m_bufferIndex;
};



}  // namespace lbcrypto

#endif