#include "reliability/crash_logger.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace p2p {

CrashLogger& CrashLogger::Instance() {
    static CrashLogger instance;
    return instance;
}

void CrashLogger::SetLogPath(std::string path) {
    std::scoped_lock lock(mutex_);
    if (!path.empty()) {
        logPath_ = std::move(path);
    }
}

void CrashLogger::LogEvent(const std::string& event) {
    std::scoped_lock lock(mutex_);
    std::ofstream out(logPath_, std::ios::app | std::ios::binary);
    if (!out) {
        return;
    }

    const auto now = std::chrono::system_clock::now();
    const auto ts = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    out << ts << " | " << event << '\n';
}

bool CrashLogger::RecoverIfNeeded() {
    std::scoped_lock lock(mutex_);

    if (!std::filesystem::exists(logPath_)) {
        return false;
    }

    std::ifstream in(logPath_, std::ios::binary);
    if (!in) {
        return false;
    }

    std::string lastLine;
    for (std::string line; std::getline(in, line);) {
        if (!line.empty()) {
            lastLine = std::move(line);
        }
    }

    std::ofstream out(logPath_, std::ios::app | std::ios::binary);
    if (out) {
        const auto now = std::chrono::system_clock::now();
        const auto ts = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
        if (!lastLine.empty()) {
            out << ts << " | recovery: previous session ended after: " << lastLine << '\n';
        } else {
            out << ts << " | recovery: log exists but is empty" << '\n';
        }
    }

    return true;
}

} // namespace p2p
