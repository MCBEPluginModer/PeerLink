#include "net/p2p_node.h"

#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <windows.h>

struct UiState {
    enum class Mode { Global, Private };
    Mode mode = Mode::Global;
    p2p::NodeId currentPrivatePeerId;
    std::string currentPrivatePeerNickname;
};

static void PrintHelp() {
    std::cout
        << "\nComm&&s:\n"
        << "/help                 - help\n"
        << "/users                - show users\n"
        << "/connect <ip> <port>  - connect manually\n"
        << "/invite <n>           - invite to private chat\n"
        << "/accept <n>           - accept invite\n"
        << "/reject <n>           - reject invite\n"
        << "/chat <n>             - switch to private chat\n"
        << "/deletechat <n>       - delete local chat history\n"
        << "/leave                - leave private chat\n"
        << "/all <text>           - send to global chat\n"
        << "/invites              - list incoming invites\n"
        << "/sessions             - list private chats\n"
        << "/info                 - self info\n"
        << "/exit                 - quit\n\n"
        << "Bootstrap nodes are loaded from bootstrap_nodes.txt (one ip:port per line).\n\n";
}

static std::optional<p2p::DisplayUser> ResolveUserByIndex(const std::vector<p2p::DisplayUser>& users, int index) {
    for (const auto& u : users) if (u.index == index) return u;
    return std::nullopt;
}

int main(int argc, char* argv[]) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    if (argc < 3) {
        std::cout << "Usage: messenger <listen_port> <nickname>\n";
        return 1;
    }

    std::uint16_t port = 0;
    try {
        int value = std::stoi(argv[1]);
        if (value <= 0 || value > 65535) return 1;
        port = static_cast<std::uint16_t>(value);
    } catch (...) {
        return 1;
    }

    p2p::P2PNode node(argv[2], port);
    if (!node.Start()) return 1;

    UiState ui{};
    PrintHelp();

    std::string line;
    while (true) {
        if (ui.mode == UiState::Mode::Private && !node.IsPeerConnected(ui.currentPrivatePeerId)) {
            std::cout << "[System] Private chat with " << ui.currentPrivatePeerNickname
                      << " was closed because the direct connection was lost.\n";
            ui.mode = UiState::Mode::Global;
            ui.currentPrivatePeerId.clear();
            ui.currentPrivatePeerNickname.clear();
        }

        if (ui.mode == UiState::Mode::Global) std::cout << "[Global] > ";
        else std::cout << "[Private | " << ui.currentPrivatePeerNickname << "] > ";

        if (!std::getline(std::cin, line)) break;
        if (line.empty()) continue;

        if (line[0] != '/') {
            if (ui.mode == UiState::Mode::Global) node.BroadcastChat(line);
            else node.SendPrivateMessage(ui.currentPrivatePeerId, line);
            continue;
        }

        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;

        if (cmd == "/help") {
            PrintHelp();
        } else if (cmd == "/users") {
            node.PrintKnownNodes();
        } else if (cmd == "/connect") {
            std::string ip; int remotePort = 0;
            iss >> ip >> remotePort;
            node.ConnectToPeer(ip, static_cast<std::uint16_t>(remotePort));
        } else if (cmd == "/invite") {
            int idx = 0; iss >> idx;
            auto user = ResolveUserByIndex(node.GetDisplayUsers(), idx);
            if (user) node.SendInvite(user->nodeId);
        } else if (cmd == "/accept") {
            int idx = 0; iss >> idx;
            auto user = ResolveUserByIndex(node.GetDisplayUsers(), idx);
            if (user) {
                node.AcceptInvite(user->nodeId);
                if (node.OpenPrivateChat(user->nodeId, user->nickname)) {
                    ui.mode = UiState::Mode::Private;
                    ui.currentPrivatePeerId = user->nodeId;
                    ui.currentPrivatePeerNickname = user->nickname;
                }
            }
        } else if (cmd == "/reject") {
            int idx = 0; iss >> idx;
            auto user = ResolveUserByIndex(node.GetDisplayUsers(), idx);
            if (user) node.RejectInvite(user->nodeId);
        } else if (cmd == "/chat") {
            int idx = 0; iss >> idx;
            auto user = ResolveUserByIndex(node.GetDisplayUsers(), idx);
            if (user && node.OpenPrivateChat(user->nodeId, user->nickname)) {
                ui.mode = UiState::Mode::Private;
                ui.currentPrivatePeerId = user->nodeId;
                ui.currentPrivatePeerNickname = user->nickname;
            }
        } else if (cmd == "/deletechat") {
            int idx = 0; iss >> idx;
            auto user = ResolveUserByIndex(node.GetDisplayUsers(), idx);
            if (user && node.DeleteConversationHistory(user->nodeId)) {
                if (ui.mode == UiState::Mode::Private && ui.currentPrivatePeerId == user->nodeId) {
                    ui.mode = UiState::Mode::Global;
                    ui.currentPrivatePeerId.clear();
                    ui.currentPrivatePeerNickname.clear();
                }
            }
        } else if (cmd == "/leave") {
            ui.mode = UiState::Mode::Global;
            ui.currentPrivatePeerId.clear();
            ui.currentPrivatePeerNickname.clear();
        } else if (cmd == "/all") {
            std::string text;
            std::getline(iss, text);
            if (!text.empty() && text[0] == ' ') text.erase(0, 1);
            node.BroadcastChat(text);
        } else if (cmd == "/invites") {
            node.PrintInvites();
        } else if (cmd == "/sessions") {
            node.PrintSessions();
        } else if (cmd == "/info") {
            node.PrintInfo();
        } else if (cmd == "/exit") {
            break;
        }
    }

    node.Stop();
    return 0;
}
