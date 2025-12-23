#ifndef LBCRYPTO_UTILS_CUSTOM_PKE_UTILS_H
#define LBCRYPTO_UTILS_CUSTOM_PKE_UTILS_H

#include <algorithm> // for std::sort
#include <cmath>     // for std::log2
#include <cstdint>   // for uint32_t
#include <map>
#include <vector>

namespace lbcrypto {

class CRModuliHelper {
public:
    /**
     * Returns a map of BitLength -> List of Primes.
     * Uses a static local variable to ensure the map is built only once (lazy initialization).
     */
    static const std::map<int, std::vector<uint32_t>>& GetCRModuliMap() {
        // This variable is initialized only the FIRST time the function is called.
        static const std::map<int, std::vector<uint32_t>> map_instance = []() {
            
            std::vector<uint32_t> all_primes = {
                0xf8020001, 0xf8040001, 0x7c020001, 0x7c0e0001, 0x3e0a0001, 0xf83e0001, 0x1f0e0001, 0xf880001,  0x3e220001,
                0x7c480001, 0xf8a0001,  0x7c800001, 0x3e500001, 0x7cc0001,  0x7ce00001, 0xf9c0001,  0x7cfc0001, 0xfa000001,
                0xfa0001,   0xfa080001, 0x3e820001, 0x3e880001, 0x7d200001, 0x1f480001, 0x3eb00001, 0x1f5c0001, 0xfaf00001,
                0x3ebc0001, 0xfafc0001, 0x1f60001,  0xfb020001, 0xfb040001, 0xfb200001, 0xfb20001,  0x3ed00001, 0xfb40001,
                0x7dbe0001, 0x3ee0001,  0xfba00001, 0xfbc80001, 0x3ef40001, 0x3ef80001, 0x7df20001, 0x1f7e0001, 0x7e000001,
                0x7e00001,  0xfc0001,   0x7e0001,   0x7e040001, 0x7e100001, 0xfc220001, 0xfc300001, 0x1f8c0001, 0xfc60001,
                0x7e780001, 0xfd20001,  0xfd800001, 0x1fb00001, 0x7ee20001, 0x1fba0001, 0x3f760001, 0xfdf00001, 0x7efc0001,
                0x7f000001, 0x1fc0001,  0xfe040001, 0x3f820001, 0x7f180001, 0xfe3e0001, 0x1fcc0001, 0x7f3c0001, 0x7f420001,
                0x7f440001, 0x3fac0001, 0xfec20001, 0xfee00001, 0xfef40001, 0xff120001, 0xff1c0001, 0xff1e0001, 0x3fd20001,
                0x7fb40001, 0xff780001, 0x3fde0001, 0xff820001, 0xffa0001,  0xffa20001, 0x7fd20001, 0xffac0001, 0x1ff60001,
                0xffd20001, 0x7fea0001, 0x1ffc0001, 0xfff00001, 0x7ff80001, 0x3ffc0001, 0x7ffe0001
            };

            std::sort(all_primes.rbegin(), all_primes.rend());

            std::map<int, std::vector<uint32_t>> bitlen_map;

            for (const auto& p : all_primes) {
                if (p == 0) continue;
                // Cast to double for log2, then cast result to int
                int bit_len = static_cast<int>(std::log2(static_cast<double>(p))) + 1;
                bitlen_map[bit_len].push_back(p);
            }

            return bitlen_map;
        }(); 

        return map_instance;
    }
};

} // namespace lbcrypto

#endif