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
        << "/devices                   - list linked devices\n"
        << "/linkdevice <contact> [l]  - link trusted contact as device\n"
        << "/revokedevice <n>          - revoke linked device\n"
        << "/groups                    - list groups\n"
        << "/mkgroup <name>            - create group\n"
        << "/groupadd <g> <contact>    - add member to group\n"
        << "/groupremove <g> <contact> - remove member from group\n"
        << "/grouprole <g> <c> <role>  - set member role\n"
        << "/groupsync <g>             - sync group snapshot\n"
        << "/groupmsg <g> <text>       - send group message\n"
        << "/attach <contact> <path>   - send attachment metadata\n"
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
        } else if (cmd == "/checkhistory") {
            int idx = 0; iss >> idx;
            auto user = ResolveUserByIndex(node.GetDisplayUsers(), idx);
            if (user) node.CheckConversationHistory(user->nodeId);
        } else if (cmd == "/repairhistory") {
            int idx = 0; iss >> idx;
            auto user = ResolveUserByIndex(node.GetDisplayUsers(), idx);
            if (user) node.RepairConversationHistory(user->nodeId);
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
        } else if (cmd == "/devices") {
            node.PrintDevices();
        } else if (cmd == "/linkdevice") {
            int idx = 0; iss >> idx;
            std::string label; std::getline(iss, label);
            if (!label.empty() && label[0] == ' ') label.erase(0,1);
            if (!node.LinkDeviceByContactIndex(idx, label)) std::cout << "[Error] Failed to link device\n";
        } else if (cmd == "/revokedevice") {
            int idx = 0; iss >> idx;
            if (!node.RevokeDeviceByIndex(idx)) std::cout << "[Error] Failed to revoke device\n";
        } else if (cmd == "/groups") {
            node.PrintGroups();
        } else if (cmd == "/mkgroup") {
            std::string name; std::getline(iss, name);
            if (!name.empty() && name[0] == ' ') name.erase(0,1);
            if (!node.CreateGroup(name)) std::cout << "[Error] Failed to create group\n";
        } else if (cmd == "/groupadd") {
            int g = 0, c = 0; iss >> g >> c;
            if (!node.AddGroupMember(g, c)) std::cout << "[Error] Failed to add member\n";
        } else if (cmd == "/groupremove") {
            int g = 0, c = 0; iss >> g >> c;
            if (!node.RemoveGroupMember(g, c)) std::cout << "[Error] Failed to remove member\n";
        } else if (cmd == "/grouprole") {
            int g = 0, c = 0; std::string role; iss >> g >> c >> role;
            if (!node.ChangeGroupRole(g, c, role)) std::cout << "[Error] Failed to change role\n";
        } else if (cmd == "/groupsync") {
            int g = 0; iss >> g;
            if (!node.SyncGroupByIndex(g)) std::cout << "[Error] Failed to sync group\n";
        } else if (cmd == "/groupmsg") {
            int g = 0; iss >> g;
            std::string text2; std::getline(iss, text2);
            if (!text2.empty() && text2[0] == ' ') text2.erase(0,1);
            if (!node.SendGroupMessageByIndex(g, text2)) std::cout << "[Error] Failed to send group message\n";
        } else if (cmd == "/attach") {
            int c = 0; iss >> c;
            std::string path; std::getline(iss, path);
            if (!path.empty() && path[0] == ' ') path.erase(0,1);
            if (!node.SendAttachmentByContactIndex(c, path)) std::cout << "[Error] Failed to send file\n";
        } else if (cmd == "/groupattach") {
            int g = 0; iss >> g;
            std::string path; std::getline(iss, path);
            if (!path.empty() && path[0] == ' ') path.erase(0,1);
            if (!node.SendGroupAttachmentByIndex(g, path)) std::cout << "[Error] Failed to send group file\n";
        } else if (cmd == "/downloads") {
            node.PrintPendingFiles();
        } else if (cmd == "/download") {
            int idx = 0; iss >> idx;
            if (!node.AcceptPendingFileByIndex(idx)) std::cout << "[Error] Failed to accept file\n";
        } else if (cmd == "/rejectfile") {
            int idx = 0; iss >> idx;
            if (!node.RejectPendingFileByIndex(idx)) std::cout << "[Error] Failed to reject file\n";
        } else if (cmd == "/info") {
            node.PrintInfo();
        } else if (cmd == "/exit") {
            break;
        }
    }

    node.Stop();
    return 0;
}
