#pragma once

#include "core/types.h"
#include <string>

namespace p2p {

std::string ComputeFingerprint(const ByteVector& publicKeyBlob);

}
