/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "extra_auth.h"

#include <cctype>
#include <cstdio>
#include <string>
#include <vector>

#include "base.h"

namespace HdcExtraAuth {
using namespace Hdc;

namespace {
constexpr int HEX_CHARS_PER_BYTE = 2;
constexpr int BITS_PER_HEX_NIBBLE = 4;
constexpr int HEX_ALPHA_VALUE_BASE = 10;

struct HdcVersion {
    int major;
    int minor;
    int patch;
    char fix;
};

bool ParseVersionNumber(const std::string &value, int &number)
{
    if (value.empty()) {
        return false;
    }
    for (unsigned char ch : value) {
        if (!std::isdigit(ch)) {
            return false;
        }
    }
    return Hdc::Base::StringToInt(value, number) && number >= 0;
}

bool ParseClientVersion(const std::string &version, HdcVersion &parsed)
{
    constexpr char versionPrefix[] = "Ver: ";
    constexpr size_t versionPrefixLength = sizeof(versionPrefix) - 1;
    if (version.rfind(versionPrefix, 0) != 0) {
        return false;
    }

    const size_t majorBegin = versionPrefixLength;
    const size_t majorEnd = version.find('.', majorBegin);
    if (majorEnd == std::string::npos) {
        return false;
    }
    const size_t minorBegin = majorEnd + 1;
    const size_t minorEnd = version.find('.', minorBegin);
    if (minorEnd == std::string::npos) {
        return false;
    }
    const size_t patchBegin = minorEnd + 1;
    const size_t fixBegin = version.find_first_not_of("0123456789", patchBegin);
    if (fixBegin == std::string::npos || fixBegin == patchBegin || fixBegin >= version.size()) {
        return false;
    }
    if (version[fixBegin] < 'a' || version[fixBegin] > 'p') {
        return false;
    }

    return ParseVersionNumber(version.substr(majorBegin, majorEnd - majorBegin), parsed.major) &&
           ParseVersionNumber(version.substr(minorBegin, minorEnd - minorBegin), parsed.minor) &&
           ParseVersionNumber(version.substr(patchBegin, fixBegin - patchBegin), parsed.patch);
}

bool IsVersionAtLeast(const HdcVersion &version, const HdcVersion &minimum)
{
    if (version.major != minimum.major) {
        return version.major > minimum.major;
    }
    if (version.minor != minimum.minor) {
        return version.minor > minimum.minor;
    }
    if (version.patch != minimum.patch) {
        return version.patch > minimum.patch;
    }
    return version.fix >= minimum.fix;
}

int HexVal(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + HEX_ALPHA_VALUE_BASE;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + HEX_ALPHA_VALUE_BASE;
    }
    return -1;
}
}  // namespace

bool IsClientVersionSupported(const std::string &version)
{
    HdcVersion clientVersion = {};
    HdcVersion minimumVersion = {};
    if (!ParseClientVersion(version, clientVersion) ||
        !ParseClientVersion(MIN_CLIENT_VERSION, minimumVersion)) {
        return false;
    }
    return IsVersionAtLeast(clientVersion, minimumVersion);
}

bool Hex2Bytes(const std::string &hex, std::vector<uint8_t> &out)
{
    if (hex.size() % HEX_CHARS_PER_BYTE != 0) {
        WRITE_LOG(LOG_FATAL, "Hex2Bytes: odd-length hex (%zu), cannot decode", hex.size());
        return false;
    }
    out.clear();
    out.reserve(hex.size() / HEX_CHARS_PER_BYTE);
    for (size_t i = 0; i < hex.size(); i += HEX_CHARS_PER_BYTE) {
        int hi = HexVal(hex[i]);
        int lo = HexVal(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            WRITE_LOG(LOG_FATAL, "Hex2Bytes: invalid hex char at pos %zu ('%c%c')",
                i, hex[i], hex[i + 1]);
            return false;
        }
        out.push_back(static_cast<uint8_t>((hi << BITS_PER_HEX_NIBBLE) | lo));
    }
    return true;
}
}  // namespace HdcExtraAuth
