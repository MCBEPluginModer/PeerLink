#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace p2p::ui {

struct StartupUiInfo {
    std::string nickname;
    std::uint16_t port = 0;
    bool compactMode = false;
};

struct CommandHelpItem {
    std::string command;
    std::string description;
};

void PrintBanner(const StartupUiInfo& info);
void PrintSection(const std::string& title);
void PrintStatusLine(const std::string& mode, const std::string& target, bool connected);
void PrintInfo(const std::string& text);
void PrintSuccess(const std::string& text);
void PrintWarning(const std::string& text);
void PrintError(const std::string& text);
void PrintTip(const std::string& text);
void PrintHelpTable(const std::string& title, const std::vector<CommandHelpItem>& items);
std::string BuildPrompt(const std::string& mode, const std::string& target, bool connected);

} // namespace p2p::ui
