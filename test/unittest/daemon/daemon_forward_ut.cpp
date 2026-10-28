/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file in compliance with the License.
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

#include <cstring>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "daemon_forward.h"
#include "task.h"

using namespace testing::ext;
using namespace testing;

namespace Hdc {
class HdcDaemonForwardTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    HTaskInfo NewInfo();
};

void HdcDaemonForwardTest::SetUpTestCase() {}
void HdcDaemonForwardTest::TearDownTestCase() {}
void HdcDaemonForwardTest::SetUp() {}
void HdcDaemonForwardTest::TearDown() {}

HTaskInfo HdcDaemonForwardTest::NewInfo()
{
    HTaskInfo info = new TaskInformation();
    return info;
}

// 构造：以默认 TaskInformation 构造 HdcDaemonForward，不崩溃
HWTEST_F(HdcDaemonForwardTest, Constructor_NoCrash, TestSize.Level0)
{
    HTaskInfo info = NewInfo();
    ASSERT_NO_FATAL_FAILURE(HdcDaemonForward f(info));
    delete info;
}

// ReadyForRelease：初始 refCount=0 → true（继承自 HdcTaskBase）
HWTEST_F(HdcDaemonForwardTest, ReadyForRelease_Initial_True, TestSize.Level0)
{
    HTaskInfo info = NewInfo();
    HdcDaemonForward f(info);
    EXPECT_TRUE(f.ReadyForRelease());
    delete info;
}

// StopTask：默认实现设置 singalStop，不崩溃
HWTEST_F(HdcDaemonForwardTest, StopTask_NoCrash, TestSize.Level0)
{
    HTaskInfo info = NewInfo();
    HdcDaemonForward f(info);
    EXPECT_NO_FATAL_FAILURE(f.StopTask());
    delete info;
}

// CommandDispatch：未知 command + 空 payload → ForwardCommandDispatch 短路 → false
HWTEST_F(HdcDaemonForwardTest, CommandDispatch_UnknownCommand_ReturnsFalse, TestSize.Level0)
{
    HTaskInfo info = NewInfo();
    info->channelTask = true;
    HdcDaemonForward f(info);
    uint8_t payload = 0;
    EXPECT_FALSE(f.CommandDispatch(0xFFFF, &payload, 0));
    delete info;
}

// CommandDispatch：CMD_FORWARD_CHECK_RESULT + payloadSize>DWORD + 无 ctx → true（ctx 未找到早返回）
HWTEST_F(HdcDaemonForwardTest, CommandDispatch_ForwardCheckResult_NoCtx_ReturnsTrue, TestSize.Level0)
{
    HTaskInfo info = NewInfo();
    info->channelTask = true;
    HdcDaemonForward f(info);
    uint8_t payload[8] = {0};
    EXPECT_TRUE(f.CommandDispatch(CMD_FORWARD_CHECK_RESULT, payload, sizeof(payload)));
    delete info;
}

// CommandDispatch：CMD_FORWARD_DATA + 空 payload → 短路 → false
HWTEST_F(HdcDaemonForwardTest, CommandDispatch_ForwardData_ShortPayload_ReturnsFalse, TestSize.Level0)
{
    HTaskInfo info = NewInfo();
    info->channelTask = true;
    HdcDaemonForward f(info);
    uint8_t payload = 0;
    EXPECT_FALSE(f.CommandDispatch(CMD_FORWARD_DATA, &payload, 0));
    delete info;
}
}  // namespace Hdc
