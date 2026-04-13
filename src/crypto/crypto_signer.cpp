#include "crypto/crypto_signer.h"

namespace p2p {

CryptoSigner::CryptoSigner() = default;

CryptoSigner::~CryptoSigner() {
    Cleanup();
}

bool CryptoSigner::Initialize(const std::wstring& containerName) {
    if (CryptAcquireContextW(&hProv_, containerName.c_str(), nullptr, PROV_RSA_AES, 0)) {
        return EnsureKeyPair();
    }

    if (GetLastError() == NTE_BAD_KEYSET) {
        if (!CryptAcquireContextW(
                &hProv_,
                containerName.c_str(),
                nullptr,
                PROV_RSA_AES,
                CRYPT_NEWKEYSET)) {
            return false;
        }

        return EnsureKeyPair();
    }

    return false;
}

bool CryptoSigner::EnsureKeyPair() {
    if (CryptGetUserKey(hProv_, AT_SIGNATURE, &hKey_)) {
        return true;
    }

    return CryptGenKey(
               hProv_,
               AT_SIGNATURE,
               (2048 << 16) | CRYPT_EXPORTABLE,
               &hKey_) == TRUE;
}

void CryptoSigner::Cleanup() {
    if (hKey_) {
        CryptDestroyKey(hKey_);
        hKey_ = 0;
    }

    if (hProv_) {
        CryptReleaseContext(hProv_, 0);
        hProv_ = 0;
    }
}

bool CryptoSigner::ExportPublicKey(ByteVector& outBlob) const {
    DWORD size = 0;
    if (!CryptExportKey(hKey_, 0, PUBLICKEYBLOB, 0, nullptr, &size)) {
        return false;
    }

    outBlob.resize(size);

    if (!CryptExportKey(hKey_, 0, PUBLICKEYBLOB, 0, outBlob.data(), &size)) {
        return false;
    }

    outBlob.resize(size);
    return true;
}

bool CryptoSigner::ImportPublicKey(const ByteVector& blob, HCRYPTKEY& outKey) const {
    outKey = 0;
    return CryptImportKey(
               hProv_,
               blob.data(),
               static_cast<DWORD>(blob.size()),
               0,
               0,
               &outKey) == TRUE;
}

bool CryptoSigner::Sign(const ByteVector& data, ByteVector& signature) const {
    HCRYPTHASH hHash = 0;
    if (!CryptCreateHash(hProv_, CALG_SHA_256, 0, 0, &hHash)) {
        return false;
    }

    bool ok = false;

    do {
        if (!CryptHashData(hHash, data.data(), static_cast<DWORD>(data.size()), 0)) {
            break;
        }

        DWORD sigSize = 0;
        if (!CryptSignHashW(hHash, AT_SIGNATURE, nullptr, 0, nullptr, &sigSize)) {
            break;
        }

        signature.resize(sigSize);

        if (!CryptSignHashW(hHash, AT_SIGNATURE, nullptr, 0, signature.data(), &sigSize)) {
            break;
        }

        signature.resize(sigSize);
        ok = true;
    } while (false);

    CryptDestroyHash(hHash);
    return ok;
}

bool CryptoSigner::Verify(const ByteVector& data,
                          const ByteVector& signature,
                          const ByteVector& publicKeyBlob) const {
    HCRYPTKEY hPubKey = 0;
    HCRYPTHASH hHash = 0;

    if (!ImportPublicKey(publicKeyBlob, hPubKey)) {
        return false;
    }

    if (!CryptCreateHash(hProv_, CALG_SHA_256, 0, 0, &hHash)) {
        CryptDestroyKey(hPubKey);
        return false;
    }

    bool ok = false;

    do {
        if (!CryptHashData(hHash, data.data(), static_cast<DWORD>(data.size()), 0)) {
            break;
        }

        if (!CryptVerifySignatureW(
                hHash,
                signature.data(),
                static_cast<DWORD>(signature.size()),
                hPubKey,
                nullptr,
                0)) {
            break;
        }

        ok = true;
    } while (false);

    CryptDestroyHash(hHash);
    CryptDestroyKey(hPubKey);
    return ok;
}

} // namespace p2p