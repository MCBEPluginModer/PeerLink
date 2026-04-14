#include "core/fingerprint_utils.h"

#include <windows.h>
#include <wincrypt.h>

#include <cstdio>

namespace p2p {

std::string ComputeFingerprint(const ByteVector& publicKeyBlob) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE hash[32]{};
    DWORD hashLen = sizeof(hash);
    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return {};
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) { CryptReleaseContext(hProv,0); return {}; }
    if (!publicKeyBlob.empty() && !CryptHashData(hHash, publicKeyBlob.data(), static_cast<DWORD>(publicKeyBlob.size()), 0)) { CryptDestroyHash(hHash); CryptReleaseContext(hProv,0); return {}; }
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) { CryptDestroyHash(hHash); CryptReleaseContext(hProv,0); return {}; }
    std::string out; char buf[4];
    for (DWORD i=0;i<hashLen;++i) { sprintf_s(buf, "%02X", hash[i]); out += buf; if (i + 1 < hashLen) out += ':'; }
    CryptDestroyHash(hHash); CryptReleaseContext(hProv,0);
    return out;
}

}
