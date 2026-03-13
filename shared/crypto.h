#pragma once
#include <cstdint>
#include <vector>
#include <string>

namespace sakura {

class RC4 {
public:
    RC4(const std::string& key) {
        for (int i = 0; i < 256; i++) S[i] = static_cast<uint8_t>(i);
        uint8_t j = 0;
        for (int i = 0; i < 256; i++) {
            j = j + S[i] + static_cast<uint8_t>(key[i % key.size()]);
            std::swap(S[i], S[j]);
        }
        i_ = 0;
        j_ = 0;
    }

    void process(uint8_t* data, size_t len) {
        for (size_t k = 0; k < len; k++) {
            i_ = i_ + 1;
            j_ = j_ + S[i_];
            std::swap(S[i_], S[j_]);
            data[k] ^= S[static_cast<uint8_t>(S[i_] + S[j_])];
        }
    }

    static void encrypt(uint8_t* data, size_t len, const std::string& key) {
        RC4 rc4(key);
        rc4.process(data, len);
    }

    static void decrypt(uint8_t* data, size_t len, const std::string& key) {
        encrypt(data, len, key);
    }

private:
    uint8_t S[256];
    uint8_t i_, j_;
};

inline std::string derive_transit_key(const std::string& license, const std::string& hwid) {
    std::string combined = license + ":" + hwid + ":sakura";
    uint64_t h = 0xcbf29ce484222325ULL;
    for (char c : combined) {
        h ^= static_cast<uint8_t>(c);
        h *= 0x100000001b3ULL;
    }
    char buf[17];
    snprintf(buf, sizeof(buf), "%016llx", static_cast<unsigned long long>(h));
    return std::string(buf);
}

} // namespace sakura
