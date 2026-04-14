
#include "crypto/crypto_signer.h"

namespace p2p {

namespace {
#pragma pack(push, 1)
struct AesPlaintextKeyBlob {
    BLOBHEADER hdr;
    DWORD keySize;
    BYTE key[32];
};
#pragma pack(pop)
}

CryptoSigner::CryptoSigner() = default;
CryptoSigner::~CryptoSigner() { Cleanup(); }

bool CryptoSigner::Initialize(const std::wstring& containerName) {
    if (CryptAcquireContextW(&hProv_, containerName.c_str(), nullptr, PROV_RSA_AES, 0)) {
        return EnsureKeyPair();
    }
    if (GetLastError() == NTE_BAD_KEYSET) {
        if (!CryptAcquireContextW(&hProv_, containerName.c_str(), nullptr, PROV_RSA_AES, CRYPT_NEWKEYSET)) {
            return false;
        }
        return EnsureKeyPair();
    }
    return false;
}

bool CryptoSigner::EnsureKeyPair() {
    if (!CryptGetUserKey(hProv_, AT_SIGNATURE, &hSignKey_)) {
        if (!CryptGenKey(hProv_, AT_SIGNATURE, (2048 << 16) | CRYPT_EXPORTABLE, &hSignKey_)) return false;
    }
    if (!CryptGetUserKey(hProv_, AT_KEYEXCHANGE, &hExchangeKey_)) {
        if (!CryptGenKey(hProv_, AT_KEYEXCHANGE, (2048 << 16) | CRYPT_EXPORTABLE, &hExchangeKey_)) return false;
    }
    return true;
}

void CryptoSigner::Cleanup() {
    if (hSignKey_) { CryptDestroyKey(hSignKey_); hSignKey_ = 0; }
    if (hExchangeKey_) { CryptDestroyKey(hExchangeKey_); hExchangeKey_ = 0; }
    if (hProv_) { CryptReleaseContext(hProv_, 0); hProv_ = 0; }
}

bool CryptoSigner::ExportPublicKey(ByteVector& outBlob) const {
    DWORD size = 0;
    if (!CryptExportKey(hSignKey_, 0, PUBLICKEYBLOB, 0, nullptr, &size)) return false;
    outBlob.resize(size);
    if (!CryptExportKey(hSignKey_, 0, PUBLICKEYBLOB, 0, outBlob.data(), &size)) return false;
    outBlob.resize(size);
    return true;
}

bool CryptoSigner::ExportEncryptPublicKey(ByteVector& outBlob) const {
    DWORD size = 0;
    if (!CryptExportKey(hExchangeKey_, 0, PUBLICKEYBLOB, 0, nullptr, &size)) return false;
    outBlob.resize(size);
    if (!CryptExportKey(hExchangeKey_, 0, PUBLICKEYBLOB, 0, outBlob.data(), &size)) return false;
    outBlob.resize(size);
    return true;
}

bool CryptoSigner::ImportPublicKey(const ByteVector& blob, HCRYPTKEY& outKey) const {
    outKey = 0;
    return CryptImportKey(hProv_, blob.data(), static_cast<DWORD>(blob.size()), 0, 0, &outKey) == TRUE;
}

bool CryptoSigner::ImportAesKey(const ByteVector& key, HCRYPTKEY& outKey) const {
    outKey = 0;
    if (key.size() != 32) return false;
    AesPlaintextKeyBlob blob{};
    blob.hdr.bType = PLAINTEXTKEYBLOB;
    blob.hdr.bVersion = CUR_BLOB_VERSION;
    blob.hdr.aiKeyAlg = CALG_AES_256;
    blob.keySize = 32;
    memcpy(blob.key, key.data(), 32);
    return CryptImportKey(hProv_, reinterpret_cast<const BYTE*>(&blob), sizeof(blob), 0, CRYPT_EXPORTABLE, &outKey) == TRUE;
}

bool CryptoSigner::Sign(const ByteVector& data, ByteVector& signature) const {
    HCRYPTHASH hHash = 0;
    if (!CryptCreateHash(hProv_, CALG_SHA_256, 0, 0, &hHash)) return false;
    bool ok = false;
    do {
        if (!CryptHashData(hHash, data.data(), static_cast<DWORD>(data.size()), 0)) break;
        DWORD sigSize = 0;
        if (!CryptSignHashW(hHash, AT_SIGNATURE, nullptr, 0, nullptr, &sigSize)) break;
        signature.resize(sigSize);
        if (!CryptSignHashW(hHash, AT_SIGNATURE, nullptr, 0, signature.data(), &sigSize)) break;
        signature.resize(sigSize);
        ok = true;
    } while (false);
    CryptDestroyHash(hHash);
    return ok;
}

bool CryptoSigner::Verify(const ByteVector& data, const ByteVector& signature, const ByteVector& publicKeyBlob) const {
    HCRYPTKEY hPubKey = 0; HCRYPTHASH hHash = 0;
    if (!ImportPublicKey(publicKeyBlob, hPubKey)) return false;
    if (!CryptCreateHash(hProv_, CALG_SHA_256, 0, 0, &hHash)) { CryptDestroyKey(hPubKey); return false; }
    bool ok = false;
    do {
        if (!CryptHashData(hHash, data.data(), static_cast<DWORD>(data.size()), 0)) break;
        if (!CryptVerifySignatureW(hHash, signature.data(), static_cast<DWORD>(signature.size()), hPubKey, nullptr, 0)) break;
        ok = true;
    } while (false);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hPubKey);
    return ok;
}

bool CryptoSigner::GenerateRandomBytes(std::size_t count, ByteVector& out) const {
    out.resize(count);
    return CryptGenRandom(hProv_, static_cast<DWORD>(out.size()), out.data()) == TRUE;
}

bool CryptoSigner::EncryptFor(const ByteVector& plaintext, const ByteVector& publicKeyBlob, ByteVector& encrypted) const {
    HCRYPTKEY hPub = 0;
    if (!ImportPublicKey(publicKeyBlob, hPub)) return false;
    DWORD bufSize = 0;
    encrypted = plaintext;
    bufSize = static_cast<DWORD>(encrypted.size());
    if (!CryptEncrypt(hPub, 0, TRUE, 0, nullptr, &bufSize, 0)) { CryptDestroyKey(hPub); return false; }
    encrypted.resize(bufSize);
    memcpy(encrypted.data(), plaintext.data(), plaintext.size());
    DWORD dataLen = static_cast<DWORD>(plaintext.size());
    const bool ok = CryptEncrypt(hPub, 0, TRUE, 0, encrypted.data(), &dataLen, bufSize) == TRUE;
    if (ok) encrypted.resize(dataLen);
    CryptDestroyKey(hPub);
    return ok;
}

bool CryptoSigner::Decrypt(const ByteVector& encrypted, ByteVector& plaintext) const {
    plaintext = encrypted;
    DWORD dataLen = static_cast<DWORD>(plaintext.size());
    if (!CryptDecrypt(hExchangeKey_, 0, TRUE, 0, plaintext.data(), &dataLen)) return false;
    plaintext.resize(dataLen);
    return true;
}

bool CryptoSigner::EncryptAes(const ByteVector& key, const ByteVector& iv, const ByteVector& plaintext, ByteVector& ciphertext) const {
    HCRYPTKEY hAes = 0;
    if (!ImportAesKey(key, hAes)) return false;
    if (iv.size() != 16) { CryptDestroyKey(hAes); return false; }
    if (!CryptSetKeyParam(hAes, KP_IV, const_cast<BYTE*>(iv.data()), 0)) { CryptDestroyKey(hAes); return false; }
    DWORD mode = CRYPT_MODE_CBC;
    CryptSetKeyParam(hAes, KP_MODE, reinterpret_cast<BYTE*>(&mode), 0);
    ciphertext = plaintext;
    DWORD required = static_cast<DWORD>(ciphertext.size());
    if (!CryptEncrypt(hAes, 0, TRUE, 0, nullptr, &required, 0)) { CryptDestroyKey(hAes); return false; }
    ciphertext.resize(required);
    memcpy(ciphertext.data(), plaintext.data(), plaintext.size());
    DWORD dataLen = static_cast<DWORD>(plaintext.size());
    bool ok = CryptEncrypt(hAes, 0, TRUE, 0, ciphertext.data(), &dataLen, required) == TRUE;
    if (ok) ciphertext.resize(dataLen);
    CryptDestroyKey(hAes);
    return ok;
}

bool CryptoSigner::DecryptAes(const ByteVector& key, const ByteVector& iv, const ByteVector& ciphertext, ByteVector& plaintext) const {
    HCRYPTKEY hAes = 0;
    if (!ImportAesKey(key, hAes)) return false;
    if (iv.size() != 16) { CryptDestroyKey(hAes); return false; }
    if (!CryptSetKeyParam(hAes, KP_IV, const_cast<BYTE*>(iv.data()), 0)) { CryptDestroyKey(hAes); return false; }
    DWORD mode = CRYPT_MODE_CBC;
    CryptSetKeyParam(hAes, KP_MODE, reinterpret_cast<BYTE*>(&mode), 0);
    plaintext = ciphertext;
    DWORD dataLen = static_cast<DWORD>(plaintext.size());
    bool ok = CryptDecrypt(hAes, 0, TRUE, 0, plaintext.data(), &dataLen) == TRUE;
    if (ok) plaintext.resize(dataLen);
    CryptDestroyKey(hAes);
    return ok;
}

} // namespace p2p
