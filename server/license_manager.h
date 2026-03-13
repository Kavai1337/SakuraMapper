#pragma once
#include <string>
#include <vector>
#include <mutex>

namespace sakura {

enum class KeyType { Initial, Bound };

struct LicenseKey {
    std::string key;
    std::string hwid;
    std::string expires;
    bool        active;
    KeyType     type;
};

class LicenseManager {
public:
    bool load(const std::string& path);
    bool save();

    std::string validate(const std::string& key, const std::string& hwid);

    void add_key(const std::string& key, const std::string& expires = "never");

private:
    std::string            file_path_;
    std::vector<LicenseKey> keys_;
    std::mutex             mtx_;

    bool parse_json(const std::string& json);
    std::string to_json() const;
};

} // namespace sakura
