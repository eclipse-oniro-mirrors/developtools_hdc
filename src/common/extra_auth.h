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

#ifndef HDC_EXTRA_AUTH_H
#define HDC_EXTRA_AUTH_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace HdcExtraAuth {
inline constexpr char MIN_CLIENT_VERSION[] = "Ver: 3.3.0a";
inline constexpr char UNSUPPORTED_CLIENT_MESSAGE[] =
    "[E000001]:The sdk hdc.exe version is too low for additional authentication. "
    "Please upgrade hdc to version 3.3.0a or later.";

inline constexpr std::size_t MAX_PDA_LENGTH = 8192;

inline constexpr uint64_t CHALLENGE_TIMEOUT_MS = 30000;

inline constexpr char AUTH_TOOL_JAR_ENV[] = "HDC_AUTH_TOOL_JAR";

inline constexpr char AUTH_TOOL_SERVER_URL_ENV[] = "HDC_AUTH_SERVER_URL";

bool IsClientVersionSupported(const std::string &version);

bool Hex2Bytes(const std::string &hex, std::vector<uint8_t> &out);

bool ApplyPda(const std::string &rpmBytes, std::string &pda);
bool GetRpm(std::string &rpmPayload);
bool StoreAndVerifyPda(const std::string &pda);
}  // namespace HdcExtraAuth

#endif  // HDC_EXTRA_AUTH_H
