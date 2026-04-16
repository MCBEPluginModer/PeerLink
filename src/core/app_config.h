#pragma once

#include <cstdint>
#include <string>

namespace p2p {

struct AppConfig {
    std::uint16_t listenPort = 0;
    std::string nickname;
    std::string logFile = "logs/messenger.log";
    std::string logLevel = "info";
    bool uiShowBanner = true;
    bool uiCompactMode = false;
    bool logToConsole = true;
    bool logTimestamps = true;
};

class ConfigManager {
public:
    static bool LoadFromFile(const std::string& path, AppConfig& outConfig, std::string* error = nullptr);
    static bool SaveToFile(const std::string& path, const AppConfig& config, std::string* error = nullptr);
    static std::string ToDisplayString(const AppConfig& config);
};

} // namespace p2p
