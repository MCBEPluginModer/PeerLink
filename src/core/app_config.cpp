#include "core/app_config.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <cctype>

namespace p2p {
namespace {
std::string Trim(std::string value) {
    auto notSpace = [](unsigned char ch) { return !std::isspace(ch); };
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), notSpace));
    value.erase(std::find_if(value.rbegin(), value.rend(), notSpace).base(), value.end());
    return value;
}

std::string ToLower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

bool ParseBool(const std::string& value, bool& out) {
    const std::string lower = ToLower(Trim(value));
    if (lower == "1" || lower == "true" || lower == "yes" || lower == "on") {
        out = true;
        return true;
    }
    if (lower == "0" || lower == "false" || lower == "no" || lower == "off") {
        out = false;
        return true;
    }
    return false;
}
} // namespace

bool ConfigManager::LoadFromFile(const std::string& path, AppConfig& outConfig, std::string* error) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        if (error) *error = "config file not found";
        return false;
    }

    AppConfig cfg = outConfig;
    std::string line;
    int lineNo = 0;
    while (std::getline(in, line)) {
        ++lineNo;
        line = Trim(line);
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;

        auto pos = line.find('=');
        if (pos == std::string::npos) {
            if (error) *error = "invalid config line " + std::to_string(lineNo);
            return false;
        }

        const std::string key = ToLower(Trim(line.substr(0, pos)));
        const std::string value = Trim(line.substr(pos + 1));

        try {
            if (key == "listen_port") {
                int parsed = std::stoi(value);
                if (parsed <= 0 || parsed > 65535) throw std::runtime_error("port");
                cfg.listenPort = static_cast<std::uint16_t>(parsed);
            } else if (key == "nickname") {
                cfg.nickname = value;
            } else if (key == "log_file") {
                cfg.logFile = value;
            } else if (key == "log_level") {
                cfg.logLevel = ToLower(value);
            } else if (key == "ui_show_banner") {
                if (!ParseBool(value, cfg.uiShowBanner)) throw std::runtime_error("bool");
            } else if (key == "ui_compact_mode") {
                if (!ParseBool(value, cfg.uiCompactMode)) throw std::runtime_error("bool");
            } else if (key == "log_to_console") {
                if (!ParseBool(value, cfg.logToConsole)) throw std::runtime_error("bool");
            } else if (key == "log_timestamps") {
                if (!ParseBool(value, cfg.logTimestamps)) throw std::runtime_error("bool");
            }
        } catch (...) {
            if (error) *error = "invalid value for '" + key + "' on line " + std::to_string(lineNo);
            return false;
        }
    }

    outConfig = cfg;
    return true;
}

bool ConfigManager::SaveToFile(const std::string& path, const AppConfig& config, std::string* error) {
    try {
        std::filesystem::path p(path);
        if (p.has_parent_path()) std::filesystem::create_directories(p.parent_path());
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out) {
            if (error) *error = "failed to open config file for writing";
            return false;
        }

        out
            << "# PeerLink messenger configuration\n"
            << "# Lines use key=value format.\n\n"
            << "listen_port=" << config.listenPort << "\n"
            << "nickname=" << config.nickname << "\n"
            << "log_file=" << config.logFile << "\n"
            << "log_level=" << config.logLevel << "\n"
            << "ui_show_banner=" << (config.uiShowBanner ? "true" : "false") << "\n"
            << "ui_compact_mode=" << (config.uiCompactMode ? "true" : "false") << "\n"
            << "log_to_console=" << (config.logToConsole ? "true" : "false") << "\n"
            << "log_timestamps=" << (config.logTimestamps ? "true" : "false") << "\n";
        return true;
    } catch (const std::exception& ex) {
        if (error) *error = ex.what();
        return false;
    }
}

std::string ConfigManager::ToDisplayString(const AppConfig& config) {
    std::ostringstream out;
    out
        << "listen_port=" << config.listenPort << "\n"
        << "nickname=" << config.nickname << "\n"
        << "log_file=" << config.logFile << "\n"
        << "log_level=" << config.logLevel << "\n"
        << "ui_show_banner=" << (config.uiShowBanner ? "true" : "false") << "\n"
        << "ui_compact_mode=" << (config.uiCompactMode ? "true" : "false") << "\n"
        << "log_to_console=" << (config.logToConsole ? "true" : "false") << "\n"
        << "log_timestamps=" << (config.logTimestamps ? "true" : "false");
    return out.str();
}

} // namespace p2p
