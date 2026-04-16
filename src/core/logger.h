#pragma once

#include <fstream>
#include <mutex>
#include <string>

namespace p2p {

enum class LogLevel {
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3,
};

class Logger {
public:
    static Logger& Instance();

    bool Configure(const std::string& filePath, LogLevel level, bool logToConsole, bool withTimestamps);
    void Log(LogLevel level, const std::string& category, const std::string& message);

    static LogLevel ParseLevel(const std::string& text);
    static std::string LevelToString(LogLevel level);

private:
    Logger() = default;

    std::mutex mutex_;
    std::ofstream file_;
    LogLevel minLevel_ = LogLevel::Info;
    bool logToConsole_ = true;
    bool withTimestamps_ = true;
};

} // namespace p2p
