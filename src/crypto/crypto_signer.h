#pragma once

#include "core/types.h"

#include <windows.h>
#include <wincrypt.h>
#include <string>

namespace p2p {

class CryptoSigner {
public:
    CryptoSigner();
    ~CryptoSigner();

    bool Initialize(const std::wstring& containerName);
    void Cleanup();

    bool ExportPublicKey(ByteVector& outBlob) const;
    bool ExportEncryptPublicKey(ByteVector& outBlob) const;
    bool Sign(const ByteVector& data, ByteVector& signature) const;
    bool Verify(const ByteVector& data,
                const ByteVector& signature,
                const ByteVector& publicKeyBlob) const;
    bool GenerateRandomBytes(std::size_t count, ByteVector& out) const;
    bool EncryptFor(const ByteVector& plaintext, const ByteVector& publicKeyBlob, ByteVector& encrypted) const;
    bool Decrypt(const ByteVector& encrypted, ByteVector& plaintext) const;
    bool EncryptAes(const ByteVector& key, const ByteVector& iv, const ByteVector& plaintext, ByteVector& ciphertext) const;
    bool DecryptAes(const ByteVector& key, const ByteVector& iv, const ByteVector& ciphertext, ByteVector& plaintext) const;

private:
    bool EnsureKeyPair();
    bool ImportPublicKey(const ByteVector& blob, HCRYPTKEY& outKey) const;
    bool ImportAesKey(const ByteVector& key, HCRYPTKEY& outKey) const;

private:
    HCRYPTPROV hProv_ = 0;
    HCRYPTKEY hSignKey_ = 0;
    HCRYPTKEY hExchangeKey_ = 0;
};

} // namespace p2p