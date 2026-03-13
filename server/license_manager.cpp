#include "license_manager.h"
#include <fstream>
#include <sstream>
#include <cstdio>
#include <algorithm>

namespace sakura {

static std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n\"");
    auto end   = s.find_last_not_of(" \t\r\n\"");
    if (start == std::string::npos) return "";
    return s.substr(start, end - start + 1);
}

static std::string extract_value(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    auto pos = json.find(search);
    if (pos == std::string::npos) return "";

    pos = json.find(':', pos);
    if (pos == std::string::npos) return "";
    pos++;

    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;

    if (pos >= json.size()) return "";

    if (json[pos] == '"') {
        auto end = json.find('"', pos + 1);
        if (end == std::string::npos) return "";
        return json.substr(pos + 1, end - pos - 1);
    }

    auto end = json.find_first_of(",}]", pos);
    return trim(json.substr(pos, end - pos));
}

bool LicenseManager::parse_json(const std::string& json) {
    keys_.clear();

    size_t pos = 0;
    while (true) {
        auto start = json.find('{', pos);
        if (start == std::string::npos) break;
        auto end = json.find('}', start);
        if (end == std::string::npos) break;

        std::string obj = json.substr(start, end - start + 1);

        LicenseKey lk;
        lk.key     = extract_value(obj, "key");
        lk.hwid    = extract_value(obj, "hwid");
        lk.expires = extract_value(obj, "expires");
        std::string active_str = extract_value(obj, "active");
        lk.active  = (active_str != "false");
        std::string type_str = extract_value(obj, "type");
        lk.type = (type_str == "bound") ? KeyType::Bound : KeyType::Initial;

        if (!lk.key.empty()) {
            keys_.push_back(lk);
        }

        pos = end + 1;
    }

    return true;
}

std::string LicenseManager::to_json() const {
    std::ostringstream ss;
    ss << "[\n";
    for (size_t i = 0; i < keys_.size(); i++) {
        const auto& k = keys_[i];
        ss << "  {\n";
        ss << "    \"key\": \"" << k.key << "\",\n";
        ss << "    \"hwid\": \"" << k.hwid << "\",\n";
        ss << "    \"expires\": \"" << k.expires << "\",\n";
        ss << "    \"active\": " << (k.active ? "true" : "false") << ",\n";
        ss << "    \"type\": \"" << (k.type == KeyType::Bound ? "bound" : "initial") << "\"\n";
        ss << "  }";
        if (i + 1 < keys_.size()) ss << ",";
        ss << "\n";
    }
    ss << "]\n";
    return ss.str();
}

bool LicenseManager::load(const std::string& path) {
    file_path_ = path;

    std::ifstream file(path);
    if (!file.is_open()) {
        keys_.push_back({"SAKURA-TEST-KEY-0001", "", "never", true, KeyType::Initial});
        save();
        printf("[License] Created default keys.json with test key: SAKURA-TEST-KEY-0001\n");
        return true;
    }

    std::ostringstream ss;
    ss << file.rdbuf();
    file.close();

    return parse_json(ss.str());
}

bool LicenseManager::save() {
    if (file_path_.empty()) return false;

    std::ofstream file(file_path_);
    if (!file.is_open()) return false;

    file << to_json();
    return true;
}

std::string LicenseManager::validate(const std::string& key, const std::string& hwid) {
    std::lock_guard<std::mutex> lock(mtx_);

    auto it = std::find_if(keys_.begin(), keys_.end(),
        [&](const LicenseKey& lk) { return lk.key == key; });

    if (it == keys_.end()) {
        return "Invalid license key";
    }

    if (!it->active) {
        return "License key is deactivated";
    }

    if (it->type == KeyType::Initial) {
        it->hwid = hwid;
        it->type = KeyType::Bound;
        save();
        printf("[License] Key %s activated and bound to HWID %s\n", key.c_str(), hwid.c_str());
        return "";
    }

    if (it->hwid != hwid) {
        return "HWID mismatch - key is bound to another machine";
    }

    return "";
}

void LicenseManager::add_key(const std::string& key, const std::string& expires) {
    std::lock_guard<std::mutex> lock(mtx_);
    keys_.push_back({key, "", expires, true, KeyType::Initial});
    save();
}

} // namespace sakura
