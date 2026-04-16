#include "crypto/secure_key_store.h"

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
#include <wincrypt.h>

#include <filesystem>
#include <fstream>
#include <sstream>

namespace p2p {
namespace fs = std::filesystem;

namespace {
fs::path MetadataPathFor(const std::string& nodeId) {
    return fs::path("profile") / "secure_keys" / (nodeId + ".bin");
}

std::string Escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char ch : s) {
        if (ch == '\\' || ch == '|' || ch == '\n' || ch == '\r') out.push_back('\\');
        out.push_back(ch);
    }
    return out;
}

std::string Unescape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    bool esc = false;
    for (char ch : s) {
        if (esc) {
            out.push_back(ch);
            esc = false;
        } else if (ch == '\\') {
            esc = true;
        } else {
            out.push_back(ch);
        }
    }
    return out;
}

std::vector<std::string> SplitEscaped(const std::string& line) {
    std::vector<std::string> parts;
    std::string cur;
    bool esc = false;
    for (char ch : line) {
        if (esc) {
            cur.push_back(ch);
            esc = false;
        } else if (ch == '\\') {
            esc = true;
        } else if (ch == '|') {
            parts.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(ch);
        }
    }
    parts.push_back(cur);
    for (auto& part : parts) part = Unescape(part);
    return parts;
}

std::string WideToUtf8Lossy(const std::wstring& s) {
    return std::string(s.begin(), s.end());
}

std::wstring Utf8LossyToWide(const std::string& s) {
    return std::wstring(s.begin(), s.end());
}

std::string Serialize(const SecureKeyMetadata& m) {
    std::ostringstream out;
    out << Escape(m.nodeId) << '|'
        << Escape(WideToUtf8Lossy(m.containerName)) << '|'
        << Escape(m.signFingerprint) << '|'
        << Escape(m.encryptFingerprint) << '|'
        << m.protocolVersion << '|'
        << m.updatedAtUnix << '|'
        << (m.revoked ? 1 : 0);
    return out.str();
}

bool Deserialize(const std::string& text, SecureKeyMetadata& m) {
    auto parts = SplitEscaped(text);
    if (parts.size() < 7) return false;
    m = {};
    m.nodeId = parts[0];
    m.containerName = Utf8LossyToWide(parts[1]);
    m.signFingerprint = parts[2];
    m.encryptFingerprint = parts[3];
    try {
        m.protocolVersion = static_cast<std::uint16_t>(std::stoul(parts[4]));
        m.updatedAtUnix = static_cast<std::int64_t>(std::stoll(parts[5]));
        m.revoked = (parts[6] == "1" || parts[6] == "true");
    } catch (...) {
        return false;
    }
    return !m.nodeId.empty();
}
}

bool SecureKeyStore::SaveMetadata(const SecureKeyMetadata& metadata, std::string* error) {
    try {
        fs::path path = MetadataPathFor(metadata.nodeId);
        fs::create_directories(path.parent_path());

        const std::string plain = Serialize(metadata);
        DATA_BLOB inBlob{};
        inBlob.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(plain.data()));
        inBlob.cbData = static_cast<DWORD>(plain.size());
        DATA_BLOB outBlob{};
        if (!CryptProtectData(&inBlob, L"PeerLink Secure Key Metadata", nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &outBlob)) {
            if (error) *error = "CryptProtectData failed";
            return false;
        }

        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out) {
            if (error) *error = "failed to open secure metadata file";
            LocalFree(outBlob.pbData);
            return false;
        }
        out.write(reinterpret_cast<const char*>(outBlob.pbData), static_cast<std::streamsize>(outBlob.cbData));
        LocalFree(outBlob.pbData);
        return static_cast<bool>(out);
    } catch (const std::exception& ex) {
        if (error) *error = ex.what();
        return false;
    } catch (...) {
        if (error) *error = "unknown secure metadata save failure";
        return false;
    }
}

bool SecureKeyStore::LoadMetadata(const std::string& nodeId, SecureKeyMetadata& metadata, std::string* error) {
    try {
        fs::path path = MetadataPathFor(nodeId);
        std::ifstream in(path, std::ios::binary);
        if (!in) {
            if (error) *error = "secure metadata file missing";
            return false;
        }
        std::string cipher((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        if (cipher.empty()) {
            if (error) *error = "secure metadata file is empty";
            return false;
        }

        DATA_BLOB inBlob{};
        inBlob.pbData = reinterpret_cast<BYTE*>(cipher.data());
        inBlob.cbData = static_cast<DWORD>(cipher.size());
        DATA_BLOB outBlob{};
        if (!CryptUnprotectData(&inBlob, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &outBlob)) {
            if (error) *error = "CryptUnprotectData failed";
            return false;
        }
        std::string plain(reinterpret_cast<const char*>(outBlob.pbData), reinterpret_cast<const char*>(outBlob.pbData) + outBlob.cbData);
        LocalFree(outBlob.pbData);
        if (!Deserialize(plain, metadata)) {
            if (error) *error = "failed to parse secure metadata";
            return false;
        }
        return true;
    } catch (const std::exception& ex) {
        if (error) *error = ex.what();
        return false;
    } catch (...) {
        if (error) *error = "unknown secure metadata load failure";
        return false;
    }
}

bool SecureKeyStore::HasMetadata(const std::string& nodeId) {
    return fs::exists(MetadataPathFor(nodeId));
}

} // namespace p2p
