/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#ifndef UPDATER_MODE
#include "daemon_base.h"
#include <dlfcn.h>
#include <mutex>
#include "base.h"
#include "daemon_account.h"
#include "define.h"

namespace {
static const int32_t DEFAULT_USER_ID = 100;
}

namespace Hdc {
namespace HdcDaemonBase {
#ifndef HDC_NO_ACCOUNT
class AccountAdapterLoader {
public:
    static AccountAdapterLoader &GetInstance()
    {
        static AccountAdapterLoader *instance = nullptr;
        static std::once_flag flag;
        std::call_once(flag, []() { instance = new AccountAdapterLoader(); });
        return *instance;
    }

    QueryActiveUserId GetQueryFunction() const
    {
        return queryActiveUserId_;
    }

private:
    AccountAdapterLoader()
    {
        handle_ = dlopen(HDC_ACCOUNT_ADAPTER_LIB, RTLD_NOW | RTLD_LOCAL);
        if (handle_ == nullptr) {
            const char *error = dlerror();
            WRITE_LOG(LOG_FATAL, "Load account adapter failed: %s", error == nullptr ? "unknown" : error);
            return;
        }

        (void)dlerror();
        queryActiveUserId_ = reinterpret_cast<QueryActiveUserId>(dlsym(handle_, HDC_QUERY_ACTIVE_USER_ID));
        const char *error = dlerror();
        if (queryActiveUserId_ == nullptr) {
            WRITE_LOG(LOG_FATAL, "Load account adapter symbol failed: %s", error == nullptr ? "unknown" : error);
            queryActiveUserId_ = nullptr;
        } else if (error != nullptr) {
            WRITE_LOG(LOG_WARN, "dlerror returned after successful dlsym: %s", error);
        }
    }

    ~AccountAdapterLoader()
    {
        if (handle_ != nullptr) {
            dlclose(handle_);
            handle_ = nullptr;
        }
        queryActiveUserId_ = nullptr;
    }

    AccountAdapterLoader(const AccountAdapterLoader &) = delete;
    AccountAdapterLoader &operator=(const AccountAdapterLoader &) = delete;

    // Keep the adapter and its dependency closure loaded because the account client
    // may retain callbacks and process-wide state after the query returns.
    void *handle_ = nullptr;
    QueryActiveUserId queryActiveUserId_ = nullptr;
};
#endif

static int32_t GetUserId()
{
#ifndef HDC_NO_ACCOUNT
    QueryActiveUserId queryActiveUserId = AccountAdapterLoader::GetInstance().GetQueryFunction();
    if (queryActiveUserId == nullptr) {
        WRITE_LOG(LOG_FATAL, "Account adapter not loaded, query function is null");
        return 0;
    }

    int32_t userId = 0;
    int32_t err = queryActiveUserId(&userId);
    if (err != 0) {
        WRITE_LOG(LOG_FATAL, "Query active OS account failed, err: %d", err);
        return 0;
    }
    if (userId <= 0) {
        WRITE_LOG(LOG_FATAL, "Invalid active OS account id: %d", userId);
        return 0;
    }
    return userId;
#else
    return 0;
#endif
}

bool CheckBundlePath(const std::string &bundleName, std::string &mountPath)
{
    int32_t currentUserId = GetUserId();
    if (currentUserId == 0) {
        WRITE_LOG(LOG_FATAL, "GetUserId failed, use default userId");
        currentUserId = DEFAULT_USER_ID;
    }
    std::string bundlePath = DEBUG_BUNDLE_PATH + std::to_string(currentUserId) + "/debug_hap/";
    uv_fs_t req;
    int rc = uv_fs_lstat(uv_default_loop(), &req, bundlePath.c_str(), nullptr);
    if (rc != 0) {
        WRITE_LOG(LOG_FATAL, "debug path %s lstat failed, rc:%d", bundlePath.c_str(), rc);
        uv_fs_req_cleanup(&req);
        return false;
    }
    if (req.statbuf.st_mode & S_IFLNK) {
        WRITE_LOG(LOG_FATAL, "debug path %s is a symlink", bundlePath.c_str());
        uv_fs_req_cleanup(&req);
        return false;
    }
    uv_fs_req_cleanup(&req);
    if (access(bundlePath.c_str(), F_OK) != 0 || !Base::CheckBundleName(bundleName)) {
        WRITE_LOG(LOG_FATAL, "debug path %s not found", bundlePath.c_str());
        return false;
    }
    string targetPath = "";
    targetPath += bundlePath;
    targetPath += bundleName;
    if (access(targetPath.c_str(), F_OK) != 0) {
        WRITE_LOG(LOG_FATAL, "bundle mount path %s not found", targetPath.c_str());
        return false;
    }
    mountPath = targetPath;
    return true;
}
}
}
#endif
