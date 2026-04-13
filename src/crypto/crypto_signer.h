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
    bool Sign(const ByteVector& data, ByteVector& signature) const;
    bool Verify(const ByteVector& data,
                const ByteVector& signature,
                const ByteVector& publicKeyBlob) const;

private:
    bool EnsureKeyPair();
    bool ImportPublicKey(const ByteVector& blob, HCRYPTKEY& outKey) const;

private:
    HCRYPTPROV hProv_ = 0;
    HCRYPTKEY hKey_ = 0;
};

} // namespace p2p