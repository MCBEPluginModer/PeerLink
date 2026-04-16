#include "net/p2p_node.h"
#include "core/app_config.h"
#include "core/logger.h"
#include "core/utils.h"
#include "ui/console_ui.h"

#include <filesystem>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif

struct UiState {
    enum class Mode { Global, Private };
    Mode mode = Mode::Global;
    p2p::NodeId currentPrivatePeerId;
    std::string currentPrivatePeerNickname;
};

static void PrintHelp() {
    using p2p::ui::CommandHelpItem;
    p2p::ui::PrintHelpTable("Discovery & identity", {
        {"/help", "show this help"},
        {"/users", "show known users"},
        {"/contacts", "show saved contacts"},
        {"/fingerprint", "show local signing fingerprint"},
        {"/keys", "show key lifecycle status"},
        {"/keybackup [dir]", "backup public key material manifest"},
        {"/keyrotate", "rotate local signing/exchange keys"},
        {"/keyrevoke", "revoke local key container (restart after)"}
    });
    p2p::ui::PrintHelpTable("Connections & chats", {
        {"/connect <ip> <port>", "connect manually"},
        {"/invitecode", "generate your invite code"},
        {"/addinvite <code>", "add contact using invite code"},
        {"/invite <n>", "invite user from /users list to private chat"},
        {"/invites", "show incoming invites"},
        {"/accept <n>", "accept invite"},
        {"/reject <n>", "reject invite"},
        {"/chat <n>", "switch to private chat using /users list"},
        {"/leave", "leave private chat and return to global"},
        {"/sessions", "list private chats"},
        {"/deletechat <n>", "delete local chat history"}
    });
    p2p::ui::PrintHelpTable("Contacts & trust", {
        {"/addcontact <n>", "add contact from /users list"},
        {"/removecontact <n>", "remove contact from /users list"},
        {"/renamecontact <n> <name>", "rename contact"},
        {"/trust <n>", "mark contact from /contacts as trusted"},
        {"/untrust <n>", "mark contact from /contacts as untrusted"}
    });
    p2p::ui::PrintHelpTable("Devices, groups & files", {
        {"/devices", "show linked devices"},
        {"/linkdevice <contactIndex> [label]", "link selected contact as your device"},
        {"/revokedevice <deviceIndex>", "revoke linked device"},
        {"/syncdevice <deviceIndex>", "sync recent conversations to device"},
        {"/groups", "show groups"},
        {"/creategroup <name>", "create group"},
        {"/groupadd <groupIndex> <contactIndex>", "add member to group"},
        {"/groupremove <groupIndex> <contactIndex>", "remove member from group"},
        {"/grouprole <groupIndex> <contactIndex> <role>", "change member role"},
        {"/groupsync <groupIndex>", "send group snapshot to members"},
        {"/groupmsg <groupIndex> <text>", "send group text message"},
        {"/sendfile <contactIndex> <path>", "send file to contact"},
        {"/sendgroupfile <groupIndex> <path>", "send file to group"},
        {"/pendingfiles", "list pending incoming files"},
        {"/download <n>", "accept and download pending file"},
        {"/rejectfile <n>", "reject pending file"},
        {"/transfers", "list file transfer states"},
        {"/controlstates", "list protocol control states"}
    });
    p2p::ui::PrintHelpTable("Diagnostics", {
        {"/status", "show current UI/session status"},
        {"/config", "show effective config"},
        {"/reputation", "show peer reputation scores"},
        {"/info", "show local node info"},
        {"/exit", "quit"}
    });
    p2p::ui::PrintTip("Regular chat text without a slash is sent to the current target (global or private).");
    std::cout << "\nBootstrap nodes are loaded from bootstrap_nodes.txt (one ip:port per line).\n\n";
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

    const std::string configPath = "messenger.cfg";
    p2p::AppConfig config{};
    std::string configError;
    const bool loadedConfig = p2p::ConfigManager::LoadFromFile(configPath, config, &configError);

    if (!loadedConfig && (argc < 3)) {
        p2p::AppConfig templateConfig{};
        templateConfig.listenPort = 4000;
        templateConfig.nickname = "peer";
        std::string saveError;
        p2p::ConfigManager::SaveToFile(configPath, templateConfig, &saveError);
    }

    if (argc >= 2) {
        try {
            const int value = std::stoi(argv[1]);
            if (value <= 0 || value > 65535) {
                std::cout << "Invalid listen port\n";
                return 1;
            }
            config.listenPort = static_cast<std::uint16_t>(value);
        } catch (...) {
            std::cout << "Invalid listen port\n";
            return 1;
        }
    }

    if (argc >= 3) config.nickname = argv[2];

    if (config.listenPort == 0 || config.nickname.empty()) {
        std::cout << "Usage: messenger <listen_port> <nickname>\n";
        std::cout << "Or create messenger.cfg and set listen_port / nickname there.\n";
        return 1;
    }

    if (!p2p::Logger::Instance().Configure(
            config.logFile,
            p2p::Logger::ParseLevel(config.logLevel),
            config.logToConsole,
            config.logTimestamps)) {
        std::cout << "Failed to initialize logger: " << config.logFile << "\n";
        return 1;
    }

    if (loadedConfig) {
        p2p::utils::LogSystem("Loaded config from " + configPath);
    } else {
        p2p::utils::LogWarn("Config file not loaded (" + configError + "). Using CLI/default values.");
    }

    if (!std::filesystem::exists(configPath)) {
        std::string saveError;
        if (p2p::ConfigManager::SaveToFile(configPath, config, &saveError)) {
            p2p::utils::LogSystem("Created default config file at " + configPath);
        } else {
            p2p::utils::LogWarn("Failed to create default config file: " + saveError);
        }
    }

    p2p::P2PNode node(config.nickname, config.listenPort);
    if (!node.Start()) return 1;

    UiState ui{};
    if (config.uiShowBanner) {
        p2p::ui::PrintBanner({config.nickname, config.listenPort, config.uiCompactMode});
    }
    PrintHelp();
    p2p::ui::PrintStatusLine("global", "", true);
    p2p::ui::PrintTip("Start with /users to inspect discovered peers or /invitecode to share your identity.");

    std::string line;
    while (true) {
        const bool isConnected = (ui.mode == UiState::Mode::Global) ? true : node.IsPeerConnected(ui.currentPrivatePeerId);
        const std::string modeText = (ui.mode == UiState::Mode::Global) ? "global" : "private";
        const std::string targetText = (ui.mode == UiState::Mode::Global) ? "" : ui.currentPrivatePeerNickname;
        std::cout << p2p::ui::BuildPrompt(modeText, targetText, isConnected);

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
        } else if (cmd == "/keys") {
            node.PrintKeyStatus();
        } else if (cmd == "/keybackup") {
            std::string dir;
            std::getline(iss, dir);
            if (!dir.empty() && dir[0] == " "[0]) dir.erase(0, 1);
            if (dir.empty()) dir = "profile/key_backups";
            if (node.BackupLocalKeys(dir)) p2p::ui::PrintSuccess("Key backup manifest created.");
            else p2p::ui::PrintError("Key backup failed.");
        } else if (cmd == "/keyrotate") {
            if (node.RotateLocalKeys()) p2p::ui::PrintWarning("Local keys rotated. Share your new fingerprint with trusted contacts.");
            else p2p::ui::PrintError("Key rotation failed.");
        } else if (cmd == "/keyrevoke") {
            if (node.RevokeLocalKeys()) p2p::ui::PrintWarning("Local keys revoked. Restart the messenger before continuing.");
            else p2p::ui::PrintError("Key revoke failed.");
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
        } else if (cmd == "/syncdevices") {
            int idx = 0; iss >> idx;
            if (!node.SyncDeviceByIndex(idx)) std::cout << "[Error] Failed to sync device\n";
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
        } else if (cmd == "/transfers") {
            node.PrintFileTransfers();
        } else if (cmd == "/controlstates") {
            node.PrintControlStates();
        } else if (cmd == "/status") {
            p2p::ui::PrintStatusLine(modeText, targetText, isConnected);
        } else if (cmd == "/reputation") {
            node.PrintPeerReputation();
        } else if (cmd == "/config") {
            std::cout << p2p::ConfigManager::ToDisplayString(config) << "\n";
        } else if (cmd == "/info") {
            node.PrintInfo();
        } else if (cmd == "/exit") {
            break;
        } else {
            std::cout << "[Error] Unknown command. Use /help\n";
        }
    }

    node.Stop();
    return 0;
}
