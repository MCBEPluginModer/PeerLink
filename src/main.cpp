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
        << "\nCommands:\n"
        << "/help                      - show help\n"
        << "/users                     - show known users\n"
        << "/contacts                  - show saved contacts\n"
        << "/fingerprint               - show local identity fingerprint\n"
        << "/trust <n>                 - mark contact from /contacts as trusted\n"
        << "/untrust <n>               - mark contact from /contacts as untrusted\n"
        << "/block <n>                 - block contact from /contacts and tear down sessions\n"
        << "/unblock <n>               - unblock contact from /contacts\n"
        << "/repin <n>                 - adopt pending key/fingerprint after manual verification\n"
        << "/distrustmismatch <n>      - reject pending mismatched key and keep contact untrusted\n"
        << "/migrate <n>               - approve device-replacement identity migration for contact\n"
        << "/connect <ip> <port>       - connect manually\n"
        << "/addcontact <n>            - add contact from /users list\n"
        << "/removecontact <n>         - remove contact from /users list\n"
        << "/renamecontact <n> <name>  - rename contact from /users list\n"
        << "/invitecode                - generate your invite code\n"
        << "/addinvite <code>          - add contact using invite code\n"
        << "/invite <n>                - invite user from /users list to private chat\n"
        << "/invites                   - show incoming invites\n"
        << "/accept <n>                - accept invite from /invites list\n"
        << "/reject <n>                - reject invite from /invites list\n"
        << "/chat <n>                  - switch to private chat using /users list\n"
        << "/deletechat <n>            - delete local chat history\n"
        << "/leave                     - leave private chat\n"
        << "/all <text>                - send to global chat\n"
        << "/sessions                  - list private chats\n"
        << "/resetsession <n>          - clear E2E session for contact from /contacts\n"
        << "/rekey <n>                 - reset session and send a fresh private invite\n"
        << "/info                      - self info\n"
        << "/exit                      - quit\n\n"
        << "Bootstrap nodes are loaded from bootstrap_nodes.txt (one ip:port per line).\n\n";
}

static std::optional<p2p::DisplayUser> ResolveUserByIndex(const std::vector<p2p::DisplayUser>& users, int index) {
    for (const auto& u : users) if (u.index == index) return u;
    return std::nullopt;
}

static std::optional<p2p::DisplayInvite> ResolveInviteByIndex(const std::vector<p2p::DisplayInvite>& invites, int index) {
    for (const auto& inv : invites) if (inv.index == index) return inv;
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
        if (ui.mode == UiState::Mode::Global) {
            std::cout << "[Global] > ";
        } else if (node.IsPeerConnected(ui.currentPrivatePeerId)) {
            std::cout << "[Private | " << ui.currentPrivatePeerNickname << "] > ";
        } else {
            std::cout << "[Private | " << ui.currentPrivatePeerNickname << " | relay/reconnecting] > ";
        }

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
        } else if (cmd == "/contacts") {
            node.PrintContacts();
        } else if (cmd == "/fingerprint") {
            node.PrintFingerprint();
        } else if (cmd == "/trust") {
            int idx = 0; iss >> idx;
            if (!node.TrustContactByIndex(idx)) std::cout << "[Error] Failed to trust contact\n";
        } else if (cmd == "/untrust") {
            int idx = 0; iss >> idx;
            if (!node.UntrustContactByIndex(idx)) std::cout << "[Error] Failed to untrust contact\n";
        } else if (cmd == "/block") {
            int idx = 0; iss >> idx;
            if (!node.BlockContactByIndex(idx)) std::cout << "[Error] Failed to block contact\n";
        } else if (cmd == "/unblock") {
            int idx = 0; iss >> idx;
            if (!node.UnblockContactByIndex(idx)) std::cout << "[Error] Failed to unblock contact\n";
        } else if (cmd == "/repin") {
            int idx = 0; iss >> idx;
            if (!node.RePinContactByIndex(idx)) std::cout << "[Error] Failed to re-pin contact\n";
        } else if (cmd == "/distrustmismatch") {
            int idx = 0; iss >> idx;
            if (!node.DistrustMismatchByIndex(idx)) std::cout << "[Error] Failed to reject mismatched key\n";
        } else if (cmd == "/migrate") {
            int idx = 0; iss >> idx;
            if (!node.ApproveIdentityMigrationByIndex(idx)) std::cout << "[Error] Failed to approve identity migration\n";
        } else if (cmd == "/connect") {

            std::string ip; int remotePort = 0;
            iss >> ip >> remotePort;
            node.ConnectToPeer(ip, static_cast<std::uint16_t>(remotePort));
        } else if (cmd == "/addcontact") {
            int idx = 0; iss >> idx;
            auto user = ResolveUserByIndex(node.GetDisplayUsers(), idx);
            if (user) node.AddOrUpdateContact(user->nodeId, user->nickname);
        } else if (cmd == "/removecontact") {
            int idx = 0; iss >> idx;
            auto user = ResolveUserByIndex(node.GetDisplayUsers(), idx);
            if (user) node.RemoveContact(user->nodeId);
        } else if (cmd == "/renamecontact") {
            int idx = 0; iss >> idx;
            std::string name;
            std::getline(iss, name);
            if (!name.empty() && name[0] == ' ') name.erase(0, 1);
            auto user = ResolveUserByIndex(node.GetDisplayUsers(), idx);
            if (user && !name.empty()) node.RenameContact(user->nodeId, name);
        } else if (cmd == "/invitecode") {
            std::cout << node.BuildLocalInviteCode() << "\n";
        } else if (cmd == "/addinvite") {
            std::string code;
            std::getline(iss, code);
            if (!code.empty() && code[0] == ' ') code.erase(0, 1);
            node.AddContactFromInviteCode(code);
        } else if (cmd == "/invite") {
            int idx = 0; iss >> idx;
            auto user = ResolveUserByIndex(node.GetDisplayUsers(), idx);
            if (user) node.SendInvite(user->nodeId);
        } else if (cmd == "/accept") {
            int idx = 0; iss >> idx;
            auto inv = ResolveInviteByIndex(node.GetDisplayInvites(), idx);
            if (inv) {
                node.AcceptInvite(inv->fromNodeId);
                if (node.OpenPrivateChat(inv->fromNodeId, inv->fromNickname)) {
                    ui.mode = UiState::Mode::Private;
                    ui.currentPrivatePeerId = inv->fromNodeId;
                    ui.currentPrivatePeerNickname = inv->fromNickname;
                }
            }
        } else if (cmd == "/reject") {
            int idx = 0; iss >> idx;
            auto inv = ResolveInviteByIndex(node.GetDisplayInvites(), idx);
            if (inv) node.RejectInvite(inv->fromNodeId);
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
        } else if (cmd == "/resetsession") {
            int idx = 0; iss >> idx;
            if (!node.ResetSessionByIndex(idx)) std::cout << "[Error] Failed to reset session\n";
        } else if (cmd == "/rekey") {
            int idx = 0; iss >> idx;
            if (!node.RekeySessionByIndex(idx)) std::cout << "[Error] Failed to rekey session\n";
        } else if (cmd == "/info") {

            node.PrintInfo();
        } else if (cmd == "/exit") {
            break;
        }
    }

    node.Stop();
    return 0;
}
