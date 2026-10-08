/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "daemon_account.h"

#include <vector>

#include "os_account_manager.h"

namespace Hdc {
int32_t HdcQueryActiveUserId(int32_t *userId)
{
    if (userId == nullptr) {
        return QUERY_ACCOUNT_FAILED;
    }

    std::vector<int32_t> ids;
    OHOS::ErrCode err = OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
    if (err != 0) {
        return QUERY_ACCOUNT_FAILED;
    }
    if (ids.empty() || ids[0] <= 0) {
        return QUERY_ACCOUNT_FAILED;
    }
    *userId = ids[0];
    return QUERY_ACCOUNT_SUCCESS;
}
}
