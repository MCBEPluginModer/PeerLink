#include "ui/console_ui.h"

#include <algorithm>
#include <iostream>

namespace p2p::ui {

void PrintBanner(const StartupUiInfo& info) {
    std::cout
        << "====================================================\n"
        << "                 PeerLink Messenger                 \n"
        << "====================================================\n"
        << " Nickname : " << info.nickname << "\n"
        << " Port     : " << info.port << "\n"
        << " UI mode  : " << (info.compactMode ? "compact" : "standard") << "\n"
        << "====================================================\n";
    PrintTip("Use /help to see commands, /status for current session, /keys for local key status.");
}

void PrintSection(const std::string& title) {
    std::cout << "\n---- " << title << " ----\n";
}

void PrintStatusLine(const std::string& mode, const std::string& target, bool connected) {
    std::cout << "[Status] mode=" << mode;
    if (!target.empty()) std::cout << " target=" << target;
    std::cout << " link=" << (connected ? "online" : "offline/relay") << "\n";
}

void PrintInfo(const std::string& text) { std::cout << "[Info] " << text << "\n"; }
void PrintSuccess(const std::string& text) { std::cout << "[OK] " << text << "\n"; }
void PrintWarning(const std::string& text) { std::cout << "[Warn] " << text << "\n"; }
void PrintError(const std::string& text) { std::cout << "[Error] " << text << "\n"; }
void PrintTip(const std::string& text) { std::cout << "[Tip] " << text << "\n"; }

void PrintHelpTable(const std::string& title, const std::vector<CommandHelpItem>& items) {
    PrintSection(title);
    std::size_t width = 0;
    for (const auto& item : items) width = std::max(width, item.command.size());
    for (const auto& item : items) {
        std::cout << "  " << item.command;
        if (item.command.size() < width) std::cout << std::string(width - item.command.size(), ' ');
        std::cout << "  - " << item.description << "\n";
    }
}

std::string BuildPrompt(const std::string& mode, const std::string& target, bool connected) {
    if (mode == "global") return "[Global] > ";
    if (target.empty()) return "[Private] > ";
    if (connected) return "[Private | " + target + "] > ";
    return "[Private | " + target + " | relay/reconnecting] > ";
}

} // namespace p2p::ui
