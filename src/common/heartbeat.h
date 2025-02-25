/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#ifndef HDC_HEARTBEAT_H
#define HDC_HEARTBEAT_H
#include <string>
#include <atomic>

namespace Hdc {
class HdcHeartbeat {
public:
    void AddHeartbeatCount(void);
    void AddMessageCount(void);
    void SetSupportHeartbeat(bool heartbeatStatus);
    bool GetSupportHeartbeat();
    uint64_t GetHeartbeatCount(void) const;
    std::string ToString(void) const;
    std::string HandleRecvHeartbeatMsg(uint8_t *payload, int payloadSize);
private:
    std::atomic<uint64_t> heartbeatCount = 0;
    std::atomic<uint64_t> messageCount = 0;
    bool supportHeartbeat = false;
};
}

#endif // HDC_HEARTBEAT_H