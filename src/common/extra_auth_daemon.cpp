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
#include <dlfcn.h>
#include <mutex>
#include <string>
#include <vector>

#include "base.h"

namespace HdcExtraAuth {
using namespace Hdc;

#if defined(__aarch64__) || defined(__x86_64__)
constexpr char DHA_LIBRARY_PATH[] = "/system/lib64/platformsdk/libdevice_health_attestation_sdk.z.so";
#else
constexpr char DHA_LIBRARY_PATH[] = "/system/lib/platformsdk/libdevice_health_attestation_sdk.z.so";
#endif

#define PDA_VERIFY_RESULT_RESERVED_BYTES 13
struct PdaVerifyResult {
    uint32_t remainingTime = 0;
    uint32_t remainingRebootCount = 0;
    bool isValid = false;
    bool rebootCountAvailable = false;
    uint8_t policy = 0;
    uint8_t reserved[PDA_VERIFY_RESULT_RESERVED_BYTES] = {0};
};

constexpr char DHA_GET_RPM_SYMBOL[] =
    "_ZN4OHOS8Security23DeviceHealthAttestation25DhaPrototypeCtrlInterface9DhaGetRpmE"
    "RNSt3__h6vectorIhNS3_9allocatorIhEEEE";
constexpr char DHA_STORE_PDA_SYMBOL[] =
    "_ZN4OHOS8Security23DeviceHealthAttestation25DhaPrototypeCtrlInterface11DhaStorePdaE"
    "RKNSt3__h6vectorIhNS3_9allocatorIhEEEE";
constexpr char DHA_VERIFY_PDA_SYMBOL[] =
    "_ZN4OHOS8Security23DeviceHealthAttestation25DhaPrototypeCtrlInterface12DhaVerifyPdaE"
    "RNS1_15PdaVerifyResultE";

using DhaGetRpmFunc = int32_t (*)(std::vector<uint8_t> &);
using DhaStorePdaFunc = int32_t (*)(const std::vector<uint8_t> &);
using DhaVerifyPdaFunc = int32_t (*)(PdaVerifyResult &);

class DhaLibraryLoader {
public:
    static DhaLibraryLoader &GetInstance()
    {
        static DhaLibraryLoader *instance = nullptr;
        static std::once_flag flag;
        std::call_once(flag, []() { instance = new DhaLibraryLoader(); });
        return *instance;
    }

    DhaGetRpmFunc GetGetRpmFunction() const { return getRpm_; }
    DhaStorePdaFunc GetStorePdaFunction() const { return storePda_; }
    DhaVerifyPdaFunc GetVerifyPdaFunction() const { return verifyPda_; }

private:
    DhaLibraryLoader()
    {
        WRITE_LOG(LOG_INFO, "DHA: dlopen %s", DHA_LIBRARY_PATH);
        handle_ = dlopen(DHA_LIBRARY_PATH, RTLD_NOW | RTLD_LOCAL);
        if (handle_ == nullptr) {
            const char *error = dlerror();
            WRITE_LOG(LOG_FATAL, "Load DHA library failed: %s", error == nullptr ? "unknown" : error);
            return;
        }
        getRpm_ = reinterpret_cast<DhaGetRpmFunc>(ResolveSymbol(DHA_GET_RPM_SYMBOL));
        storePda_ = reinterpret_cast<DhaStorePdaFunc>(ResolveSymbol(DHA_STORE_PDA_SYMBOL));
        verifyPda_ = reinterpret_cast<DhaVerifyPdaFunc>(ResolveSymbol(DHA_VERIFY_PDA_SYMBOL));
    }

    ~DhaLibraryLoader()
    {
        if (handle_ != nullptr) {
            dlclose(handle_);
            handle_ = nullptr;
        }
        getRpm_ = nullptr;
        storePda_ = nullptr;
        verifyPda_ = nullptr;
    }

    DhaLibraryLoader(const DhaLibraryLoader &) = delete;
    DhaLibraryLoader &operator=(const DhaLibraryLoader &) = delete;

    void *ResolveSymbol(const char *symbol) const
    {
        (void)dlerror();
        void *sym = dlsym(handle_, symbol);
        const char *error = dlerror();
        if (sym == nullptr) {
            WRITE_LOG(LOG_FATAL, "Load DHA symbol %s failed: %s", symbol, error == nullptr ? "unknown" : error);
        } else if (error != nullptr) {
            WRITE_LOG(LOG_WARN, "dlerror returned after successful dlsym %s: %s", symbol, error);
        }
        return sym;
    }

    void *handle_ = nullptr;
    DhaGetRpmFunc getRpm_ = nullptr;
    DhaStorePdaFunc storePda_ = nullptr;
    DhaVerifyPdaFunc verifyPda_ = nullptr;
};

bool GetRpm(std::string &rpmPayload)
{
    DhaGetRpmFunc getRpm = DhaLibraryLoader::GetInstance().GetGetRpmFunction();
    if (getRpm == nullptr) {
        WRITE_LOG(LOG_FATAL, "DHA library not loaded, GetRpm function is null");
        return false;
    }

    std::vector<uint8_t> tlvRpm;
    int32_t dhaRet = getRpm(tlvRpm);
    WRITE_LOG(LOG_INFO, "DHA: GetRpm returned, ret=%d, tlvRpm size=%zu", dhaRet, tlvRpm.size());
    if (dhaRet != 0 || tlvRpm.empty()) {
        WRITE_LOG(LOG_FATAL, "DHA GetRpm failed, ret=%d", dhaRet);
        return false;
    }
    rpmPayload.assign(reinterpret_cast<const char *>(tlvRpm.data()), tlvRpm.size());
    return true;
}

bool StoreAndVerifyPda(const std::string &pda)
{
    DhaStorePdaFunc storePda = DhaLibraryLoader::GetInstance().GetStorePdaFunction();
    DhaVerifyPdaFunc verifyPda = DhaLibraryLoader::GetInstance().GetVerifyPdaFunction();
    if (storePda == nullptr || verifyPda == nullptr) {
        WRITE_LOG(LOG_FATAL, "DHA StorePda/VerifyPda not loaded");
        return false;
    }

    std::vector<uint8_t> tlvPda;
    if (!Hex2Bytes(pda, tlvPda)) {
        WRITE_LOG(LOG_FATAL, "DHA: decode pda hex failed");
        return false;
    }
    int32_t storeRet = storePda(tlvPda);
    if (storeRet != 0) {
        WRITE_LOG(LOG_FATAL, "DHA StorePda failed, ret=%d", storeRet);
        return false;
    }

    PdaVerifyResult result{};
    int32_t verifyRet = verifyPda(result);
    if (verifyRet != 0) {
        WRITE_LOG(LOG_FATAL, "DHA VerifyPda failed, ret=%d", verifyRet);
        return false;
    }
    if (!result.isValid) {
        WRITE_LOG(LOG_WARN, "DHA VerifyPda: PDA invalid");
        return false;
    }
    WRITE_LOG(LOG_INFO, "DHA: PDA valid success, remainingTime=%u, remainingRebootCount=%u, policy=%u",
        result.remainingTime, result.remainingRebootCount, result.policy);
    return true;
}

}  // namespace HdcExtraAuth
