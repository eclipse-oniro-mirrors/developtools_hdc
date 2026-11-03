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
#ifndef HDC_DAEMON_ACCOUNT_H
#define HDC_DAEMON_ACCOUNT_H

#include <cstdint>

namespace Hdc {
constexpr int32_t QUERY_ACCOUNT_SUCCESS = 0;
constexpr int32_t QUERY_ACCOUNT_FAILED = -1;
#if defined(__aarch64__) || defined(__x86_64__)
constexpr char HDC_ACCOUNT_ADAPTER_LIB[] = "/system/lib64/libhdc_account_adapter.z.so";
#else
constexpr char HDC_ACCOUNT_ADAPTER_LIB[] = "/system/lib/libhdc_account_adapter.z.so";
#endif
constexpr char HDC_QUERY_ACTIVE_USER_ID[] = "HdcQueryActiveUserId";
using QueryActiveUserId = int32_t (*)(int32_t *userId);

extern "C" __attribute__((visibility("default"))) int32_t HdcQueryActiveUserId(int32_t *userId);
}

#endif
