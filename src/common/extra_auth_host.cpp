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

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

#include "base.h"

namespace HdcExtraAuth {
using namespace Hdc;

namespace {
constexpr char AUTH_TOOL_MODE[] = "HDC";
constexpr uint64_t PDA_CALL_TIMEOUT_MS = 30000;

bool GetJarPath(std::string &jarPath)
{
    const char *jarEnv = std::getenv(AUTH_TOOL_JAR_ENV);
    if (jarEnv == nullptr || jarEnv[0] == '\0') {
        WRITE_LOG(LOG_FATAL, "pda: env %s not set, cannot locate device-auth-tool.jar",
            AUTH_TOOL_JAR_ENV);
        return false;
    }
    jarPath = jarEnv;
    while (!jarPath.empty()) {
        char last = jarPath.back();
        if (last == '\r' || last == '\n' || last == ' ' || last == '\t') {
            jarPath.pop_back();
        } else {
            break;
        }
    }
    if (jarPath.empty()) {
        WRITE_LOG(LOG_FATAL, "pda: env %s contains only whitespace", AUTH_TOOL_JAR_ENV);
        return false;
    }
    return true;
}

bool GetServerUrl(std::string &serverUrl)
{
    const char *urlEnv = std::getenv(AUTH_TOOL_SERVER_URL_ENV);
    if (urlEnv == nullptr || urlEnv[0] == '\0') {
        WRITE_LOG(LOG_FATAL, "pda: env %s not set, cannot locate pki server url",
            AUTH_TOOL_SERVER_URL_ENV);
        return false;
    }
    serverUrl = urlEnv;
    while (!serverUrl.empty()) {
        char last = serverUrl.back();
        if (last == '\r' || last == '\n' || last == ' ' || last == '\t') {
            serverUrl.pop_back();
        } else {
            break;
        }
    }
    if (serverUrl.empty()) {
        WRITE_LOG(LOG_FATAL, "pda: env %s contains only whitespace", AUTH_TOOL_SERVER_URL_ENV);
        return false;
    }
    return true;
}

void MakeTempFilePaths(std::string &rpmFile, std::string &pdaFile)
{
    std::string tmpDir = Hdc::Base::GetTmpDir();
    if (tmpDir.empty()) {
#ifdef _WIN32
        tmpDir = ".";
#else
        tmpDir = "/tmp";
#endif
    }
    if (tmpDir.back() != Hdc::Base::GetPathSep()) {
        tmpDir += Hdc::Base::GetPathSep();
    }
    std::string stamp = std::to_string(Hdc::Base::GetRuntimeMSec()) + "_" +
        Hdc::Base::GetRandomString(8);
    rpmFile = tmpDir + "hdc_auth_" + stamp + ".rpm";
    pdaFile = tmpDir + "hdc_auth_" + stamp + ".pda";
}

constexpr char HEX_TABLE[] = "0123456789abcdef";
constexpr int HEX_CHARS_PER_BYTE = 2;
constexpr int BITS_PER_HEX_NIBBLE = 4;

bool WriteHexRpm(const std::string &rpmBytes, const std::string &rpmFile)
{
    std::string hexRpm;
    hexRpm.reserve(rpmBytes.size() * HEX_CHARS_PER_BYTE);
    for (size_t i = 0; i < rpmBytes.size(); ++i) {
        unsigned char byte = static_cast<unsigned char>(rpmBytes[i]);
        hexRpm += HEX_TABLE[byte >> BITS_PER_HEX_NIBBLE];
        hexRpm += HEX_TABLE[byte & 0x0f];
    }
    if (Hdc::Base::WriteBinFile(rpmFile.c_str(),
        reinterpret_cast<const uint8_t *>(hexRpm.data()), hexRpm.size(), true) < 0) {
        WRITE_LOG(LOG_FATAL, "pda: write rpm temp file failed: %s",
            Hdc::MaskString(rpmFile).c_str());
        return false;
    }
    return true;
}

bool ValidateFilePath(const std::string &path)
{
    if (path.empty() || !Hdc::Base::CheckPathTraversal(path)) {
        return false;
    }
    for (char c : path) {
        unsigned char uc = static_cast<unsigned char>(c);
        if (uc >= 0x80) {
            continue;
        }
        if (std::isalnum(uc)) {
            continue;
        }
        switch (c) {
            case '/':
            case '\\':
            case '.':
            case '-':
            case '_':
            case ':':
            case ' ':
            case '~':
                continue;
            default:
                WRITE_LOG(LOG_FATAL, "ValidateFilePath: invalid char in path: %s",
                    Hdc::MaskString(path).c_str());
                return false;
        }
    }
    return true;
}

uint64_t RunPdaTool(const std::string &jarPath, const std::string &rpmFile,
                    const std::string &pdaFile, char *toolOut, size_t toolOutSize)
{
    if (!ValidateFilePath(jarPath) || !ValidateFilePath(rpmFile) || !ValidateFilePath(pdaFile)) {
        return 0;
    }
    std::string serverUrl;
    if (!GetServerUrl(serverUrl)) {
        return 0;
    }
    std::string cmd = std::string("java -jar \"") + jarPath + "\" applyPda -server " +
        serverUrl + " -mode " + std::string(AUTH_TOOL_MODE) +
        " -tokenInputMode ENV -rpmFile \"" + rpmFile + "\" -pdaFile \"" + pdaFile + "\" 2>&1";
    uint64_t started = Hdc::Base::GetRuntimeMSec();
    (void)Hdc::Base::RunPipeComand(cmd.c_str(), toolOut, toolOutSize - 1, true);
    uint64_t elapsed = Hdc::Base::GetRuntimeMSec() - started;
    if (elapsed > PDA_CALL_TIMEOUT_MS) {
        WRITE_LOG(LOG_WARN, "pda: tool call exceeded budget %llums (took %llums)",
            PDA_CALL_TIMEOUT_MS, elapsed);
    }
    return elapsed;
}

bool ReadPdaFile(const std::string &pdaFile, std::string &pda)
{
    void *pdaRaw = nullptr;
    int pdaLen = Hdc::Base::ReadBinFile(pdaFile.c_str(), &pdaRaw, 0);
    bool ok = false;
    if (pdaLen > 0 && pdaRaw != nullptr) {
        pda.assign(static_cast<const char *>(pdaRaw), static_cast<size_t>(pdaLen));
        delete[] static_cast<uint8_t *>(pdaRaw);
        while (!pda.empty() && (pda.back() == '\n' || pda.back() == '\r')) {
            pda.pop_back();
        }
        ok = !pda.empty() && pda.size() <= MAX_PDA_LENGTH;
    }
    return ok;
}

}  // namespace

bool ApplyPda(const std::string &rpmBytes, std::string &pda)
{
    pda.clear();
    WRITE_LOG(LOG_INFO, "pda: entry, rpmBytes size=%zu", rpmBytes.size());
    if (rpmBytes.empty()) {
        WRITE_LOG(LOG_WARN, "pda: empty rpm input");
        return false;
    }

    std::string jarPath;
    if (!GetJarPath(jarPath)) {
        return false;
    }

    std::string rpmFile;
    std::string pdaFile;
    MakeTempFilePaths(rpmFile, pdaFile);

    if (!WriteHexRpm(rpmBytes, rpmFile)) {
        return false;
    }

    char toolOut[4096] = { 0 };
    uint64_t elapsed = RunPdaTool(jarPath, rpmFile, pdaFile, toolOut, sizeof(toolOut));

    bool ok = ReadPdaFile(pdaFile, pda);
    if (!ok) {
        WRITE_LOG(LOG_FATAL, "pda: device-auth-tool produced no pda (%llums), output=%s",
            elapsed, toolOut);
    } else {
        WRITE_LOG(LOG_INFO, "pda: device-auth-tool success (%llums), pda size=%zu",
            elapsed, pda.size());
    }

    std::remove(rpmFile.c_str());
    std::remove(pdaFile.c_str());
    return ok;
}

}  // namespace HdcExtraAuth
