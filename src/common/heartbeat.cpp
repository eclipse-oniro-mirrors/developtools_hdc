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
#include <sstream>
#include <string>
#include "heartbeat.h"
#include "serial_struct.h"
namespace Hdc {
void HdcHeartbeat::AddHeartbeatCount(void)
{
    heartbeatCount++;
}

void HdcHeartbeat::AddMessageCount(void)
{
    messageCount++;
}

uint64_t HdcHeartbeat::GetHeartbeatCount(void) const
{
    return heartbeatCount;
}

std::string HdcHeartbeat::ToString(void) const
{
    std::stringstream ss;
    ss << "heartbeat count is " << heartbeatCount << " and messages count is " << messageCount;
    return ss.str();
}

std::string HdcHeartbeat::HandleRecvHeartbeatMsg(uint8_t *payload, int payloadSize)
{
    if (payloadSize <= 0) {
        return "invalid heartbeat message";
    }
    string s = string(reinterpret_cast<char *>(payload), payloadSize);
    HdcSessionBase::HeartbeatMsg heartbeat;
    SerialStruct::ParseFromString(heartbeat, s);
    std::stringstream ss;
    ss << "heartbeat count is " << heartbeat.heartbeatCount;
    return ss.str();
}

void HdcHeartbeat::SetSupportHeartbeat(bool heartbeatStatus)
{
    supportHeartbeat = heartbeatStatus;
}

bool HdcHeartbeat::GetSupportHeartbeat()
{
    return supportHeartbeat;
}
}   //namespace Hdc