#pragma once

#include "core/types.h"

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
#include <string>

namespace p2p {

class CryptoSigner {
public:
    CryptoSigner();
    ~CryptoSigner();

    bool Initialize(const std::wstring& containerName);
    void Cleanup();

    const std::wstring& GetContainerName() const { return containerName_; }

    static std::wstring MakeContainerNameForNodeId(const std::string& nodeId);
    static bool DeleteContainer(const std::wstring& containerName);
    static bool ContainerExists(const std::wstring& containerName);

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
    std::wstring containerName_;
    HCRYPTPROV hProv_ = 0;
    HCRYPTKEY hSignKey_ = 0;
    HCRYPTKEY hExchangeKey_ = 0;
};

} // namespace p2p