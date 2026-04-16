#include "core/logger.h"

#include <chrono>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <cctype>
#include <ctime>

namespace p2p {
namespace {
std::string MakeTimestamp() {
    using clock = std::chrono::system_clock;
    const auto now = clock::now();
    const std::time_t tt = clock::to_time_t(now);
    std::tm localTm{};
#ifdef _WIN32
    localtime_s(&localTm, &tt);
#else
    localtime_r(&tt, &localTm);
#endif
    std::ostringstream out;
    out << std::put_time(&localTm, "%Y-%m-%d %H:%M:%S");
    return out.str();
}
} // namespace

Logger& Logger::Instance() {
    static Logger logger;
    return logger;
}

bool Logger::Configure(const std::string& filePath, LogLevel level, bool logToConsole, bool withTimestamps) {
    std::lock_guard<std::mutex> lock(mutex_);
    minLevel_ = level;
    logToConsole_ = logToConsole;
    withTimestamps_ = withTimestamps;

    file_.close();
    if (!filePath.empty()) {
        std::filesystem::path p(filePath);
        if (p.has_parent_path()) std::filesystem::create_directories(p.parent_path());
        file_.open(filePath, std::ios::app | std::ios::binary);
        if (!file_) return false;
    }
    return true;
}

void Logger::Log(LogLevel level, const std::string& category, const std::string& message) {
    if (static_cast<int>(level) < static_cast<int>(minLevel_)) return;

    std::ostringstream line;
    if (withTimestamps_) line << "[" << MakeTimestamp() << "] ";
    line << "[" << LevelToString(level) << "]";
    if (!category.empty()) line << "[" << category << "]";
    line << " " << message;

    std::lock_guard<std::mutex> lock(mutex_);
    const std::string text = line.str();
    if (logToConsole_) std::cout << text << std::endl;
    if (file_) {
        file_ << text << '\n';
        file_.flush();
    }
}

LogLevel Logger::ParseLevel(const std::string& text) {
    std::string lower;
    lower.reserve(text.size());
    for (char c : text) lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    if (lower == "debug") return LogLevel::Debug;
    if (lower == "warn" || lower == "warning") return LogLevel::Warn;
    if (lower == "error") return LogLevel::Error;
    return LogLevel::Info;
}

std::string Logger::LevelToString(LogLevel level) {
    switch (level) {
        case LogLevel::Debug: return "DEBUG";
        case LogLevel::Info: return "INFO";
        case LogLevel::Warn: return "WARN";
        case LogLevel::Error: return "ERROR";
        default: return "INFO";
    }
}

} // namespace p2p
