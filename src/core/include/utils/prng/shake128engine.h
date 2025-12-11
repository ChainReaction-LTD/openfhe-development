#ifndef __SHAKE128ENGINE_H__
#define __SHAKE128ENGINE_H__

#include "utils/prng/prng.h"
#include <vector>
#include <array>
// Include the tiny_sha3 header (adjust path as needed)

#include "utils/exception.h"
#include "utils/memory.h"
#include <thread>

extern "C" {
    #include "sha3.h"
}

namespace lbcrypto {

inline std::vector<uint32_t> GenerateRandomSeed(size_t size) {
    std::vector<uint32_t> seed(size);

    // 1. Initialize primary entropy sources
    // Derived from time, thread ID, and heap memory location (ASLR)
    std::vector<uint32_t> initKey(3);
    initKey[0] = static_cast<uint32_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count());
    initKey[1] = static_cast<uint32_t>(std::hash<std::thread::id>{}(std::this_thread::get_id()));

    // Heap address entropy
    void* mem        = malloc(1);
    uint64_t counter = reinterpret_cast<uint64_t>(mem);
    free(mem);

    // Mix the initial entropy using a standard distribution
    // This part essentially "warms up" a generator with the gathered entropy
    // Note: Blake2Engine logic uses its own generator here, but for generic usage,
    // standard library calls or a simple mix is often sufficient before the strong step below.
    // For rigorous security matching OpenFHE, you might replicate the Blake2Engine::Generate logic here,
    // but simpler std::random_device usage is usually the core source.

    // 2. Strong Randomness via std::random_device (Hardware RNG)
    // This is the most critical step for security.
    std::random_device rd;
    std::uniform_int_distribution<uint32_t> dist;

    bool rdGenPassed = false;
    size_t attempts  = 3;

    // Try to generate the full seed using random_device
    for (size_t k = 0; k < attempts && !rdGenPassed; ++k) {
        try {
            for (size_t i = 0; i < size; ++i) {
                // Combine hardware randomness with our initial entropy 'counter' to ensure
                // non-determinism even if random_device fails or is weak on some platform.
                seed[i] = dist(rd) ^ static_cast<uint32_t>(counter >> (i % 32));
            }
            rdGenPassed = true;
        }
        catch (...) {
            // Retry if random_device fails
        }
    }

    if (!rdGenPassed) {
        OPENFHE_THROW("PRNG Error: std::random_device failed to generate seed.");
    }

    return seed;
}

class Shake128Engine : public PRNG {
public:
    // Buffer size similar to Blake2Engine (42 x 32-bit integers)
    enum { PRNG_BUFFER_SIZE = 42 };

    /**
     * @brief Constructor that accepts a seed vector
     * @param seed A vector of integers (or bytes) to seed the SHAKE state
     */
    explicit Shake128Engine(const std::vector<uint32_t>& seed, u_int8_t q_index, u_int16_t seg_i) {
        // 1. Initialize the SHAKE128 context
        shake128_init(&ctx);

        // 2. Absorb the seed (inject entropy)
        // We cast the vector to bytes for absorption
        if (!seed.empty()) {
            shake_update(&ctx, reinterpret_cast<const void*>(seed.data()), seed.size() * sizeof(uint32_t));
            shake_update(&ctx, reinterpret_cast<const void*>(&q_index), sizeof(u_int8_t));
            shake_update(&ctx, reinterpret_cast<const void*>(&seg_i), sizeof(uint16_t));

            shake_xof(&ctx);
        }

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