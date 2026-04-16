#pragma once

#include <mutex>
#include <string>

namespace p2p {

class CrashLogger {
public:
    static CrashLogger& Instance();

    void SetLogPath(std::string path);
    void LogEvent(const std::string& event);
    bool RecoverIfNeeded();

private:
    CrashLogger() = default;

    std::string logPath_ = "crash_recovery.log";
    std::mutex mutex_;
};

} // namespace p2p
