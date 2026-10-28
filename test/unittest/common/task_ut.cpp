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
#include <gtest/gtest.h>
#include "task.h"
#include "base.h"
#include "session.h"

using namespace testing::ext;
using namespace testing;

namespace Hdc {
namespace {
constexpr uint32_t TASK_UT_SESSION_ID = 0x1F1F1F1F;

HTaskInfo CreateTaskInfo(bool masterSlave)
{
    HTaskInfo info = new TaskInformation();
    info->taskType = 1;
    info->sessionId = TASK_UT_SESSION_ID;
    info->channelId = 1;
    info->masterSlave = masterSlave;
    info->channelTask = false;
    info->runLoop = nullptr;
    info->runLoopStatus = nullptr;
    info->ownerSessionClass = nullptr;
    return info;
}
}  // namespace

class HdcTaskBaseTest : public ::testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

class HdcTaskBaseExpose : public HdcTaskBase {
public:
    explicit HdcTaskBaseExpose(HTaskInfo hTaskInfo) : HdcTaskBase(hTaskInfo) {}
    using HdcTaskBase::childReady;
    using HdcTaskBase::singalStop;
    using HdcTaskBase::loopTask;
    using HdcTaskBase::loopTaskStatus;
    using HdcTaskBase::clsSession;
    using HdcTaskBase::taskInfo;
    using HdcTaskBase::refCount;
    using HdcTaskBase::SendToAnother;
    using HdcTaskBase::LogMsg;
    using HdcTaskBase::ServerCommand;
    using HdcTaskBase::ThreadCtrlCommunicate;
};

void HdcTaskBaseTest::SetUpTestCase() {}
void HdcTaskBaseTest::TearDownTestCase() {}
void HdcTaskBaseTest::SetUp() {}
void HdcTaskBaseTest::TearDown() {}

HWTEST_F(HdcTaskBaseTest, HdcTaskBase_Constructor_InitializesMembers, TestSize.Level0)
{
    HTaskInfo info = CreateTaskInfo(false);
    uv_loop_t loop;
    LoopStatus status(&loop, "TaskUtLoop");
    void *owner = reinterpret_cast<void *>(0x1);
    info->runLoop = &loop;
    info->runLoopStatus = &status;
    info->ownerSessionClass = owner;

    HdcTaskBaseExpose task(info);
    EXPECT_EQ(task.taskInfo, info);
    EXPECT_EQ(task.loopTask, &loop);
    EXPECT_EQ(task.loopTaskStatus, &status);
    EXPECT_EQ(task.clsSession, owner);
    EXPECT_FALSE(task.childReady);
    EXPECT_FALSE(task.singalStop);
    EXPECT_EQ(task.refCount.load(), 0);

    delete info;
}

HWTEST_F(HdcTaskBaseTest, HdcTaskBase_Constructor_MasterSlaveSendsWakeup, TestSize.Level0)
{
    HTaskInfo info = CreateTaskInfo(true);
    Base::AddDeletedSessionId(info->sessionId);

    EXPECT_NO_FATAL_FAILURE(HdcTaskBaseExpose task(info));

    delete info;
}

HWTEST_F(HdcTaskBaseTest, HdcTaskBase_ReadyForRelease_RefCountZero, TestSize.Level0)
{
    HTaskInfo info = CreateTaskInfo(false);
    HdcTaskBaseExpose task(info);
    EXPECT_TRUE(task.ReadyForRelease());

    delete info;
}

HWTEST_F(HdcTaskBaseTest, HdcTaskBase_ReadyForRelease_RefCountNonZero, TestSize.Level0)
{
    HTaskInfo info = CreateTaskInfo(false);
    HdcTaskBaseExpose task(info);
    task.refCount++;
    EXPECT_FALSE(task.ReadyForRelease());
    task.refCount--;
    EXPECT_TRUE(task.ReadyForRelease());

    delete info;
}

HWTEST_F(HdcTaskBaseTest, HdcTaskBase_StopTask_SetsSingalStop, TestSize.Level0)
{
    HTaskInfo info = CreateTaskInfo(false);
    HdcTaskBaseExpose task(info);
    EXPECT_FALSE(task.singalStop);
    task.StopTask();
    EXPECT_TRUE(task.singalStop);

    delete info;
}

HWTEST_F(HdcTaskBaseTest, HdcTaskBase_CommandDispatch_DefaultReturnsTrue, TestSize.Level0)
{
    HTaskInfo info = CreateTaskInfo(false);
    HdcTaskBaseExpose task(info);
    EXPECT_TRUE(task.CommandDispatch(CMD_KERNEL_ECHO, nullptr, 0));

    delete info;
}

HWTEST_F(HdcTaskBaseTest, HdcTaskBase_TaskFinish_SingalStop, TestSize.Level0)
{
    HTaskInfo info = CreateTaskInfo(false);
    HdcTaskBaseExpose task(info);
    task.singalStop = true;
    EXPECT_NO_FATAL_FAILURE(task.TaskFinish());

    delete info;
}

HWTEST_F(HdcTaskBaseTest, HdcTaskBase_TaskFinish_SessionDeleted, TestSize.Level0)
{
    HTaskInfo info = CreateTaskInfo(false);
    Base::AddDeletedSessionId(info->sessionId);
    HdcTaskBaseExpose task(info);
    EXPECT_NO_FATAL_FAILURE(task.TaskFinish());

    delete info;
}

HWTEST_F(HdcTaskBaseTest, HdcTaskBase_SendToAnother_SingalStopReturnsFalse, TestSize.Level0)
{
    HTaskInfo info = CreateTaskInfo(false);
    HdcTaskBaseExpose task(info);
    task.singalStop = true;
    EXPECT_FALSE(task.SendToAnother(CMD_KERNEL_CHANNEL_CLOSE, nullptr, 0));

    delete info;
}

HWTEST_F(HdcTaskBaseTest, HdcTaskBase_SendToAnother_SessionDeletedReturnsFalse, TestSize.Level0)
{
    HTaskInfo info = CreateTaskInfo(false);
    Base::AddDeletedSessionId(info->sessionId);
    HdcTaskBaseExpose task(info);
    EXPECT_FALSE(task.SendToAnother(CMD_KERNEL_CHANNEL_CLOSE, nullptr, 0));

    delete info;
}

HWTEST_F(HdcTaskBaseTest, HdcTaskBase_LogMsg_ChannelTaskOutputs, TestSize.Level0)
{
    HTaskInfo info = CreateTaskInfo(false);
    info->channelTask = true;
    HdcTaskBaseExpose task(info);
    EXPECT_NO_FATAL_FAILURE(task.LogMsg(MSG_INFO, "task ut log message"));

    delete info;
}

HWTEST_F(HdcTaskBaseTest, HdcTaskBase_LogMsg_ChannelTaskFail, TestSize.Level0)
{
    HTaskInfo info = CreateTaskInfo(false);
    info->channelTask = true;
    HdcTaskBaseExpose task(info);
    EXPECT_NO_FATAL_FAILURE(task.LogMsg(MSG_FAIL, "task ut fail message"));

    delete info;
}

HWTEST_F(HdcTaskBaseTest, HdcTaskBase_LogMsg_ChannelTaskOk, TestSize.Level0)
{
    HTaskInfo info = CreateTaskInfo(false);
    info->channelTask = true;
    HdcTaskBaseExpose task(info);
    EXPECT_NO_FATAL_FAILURE(task.LogMsg(MSG_OK, "task ut ok message"));

    delete info;
}

HWTEST_F(HdcTaskBaseTest, HdcTaskBase_LogMsg_NonChannelTask, TestSize.Level0)
{
    HTaskInfo info = CreateTaskInfo(false);
    HdcSessionBase *sessionBase = new HdcSessionBase(false);
    info->ownerSessionClass = sessionBase;
    HdcTaskBaseExpose task(info);
    EXPECT_NO_FATAL_FAILURE(task.LogMsg(MSG_INFO, "task ut non channel log"));

    delete info;
    delete sessionBase;
}

HWTEST_F(HdcTaskBaseTest, HdcTaskBase_ServerCommand_Default, TestSize.Level0)
{
    HTaskInfo info = CreateTaskInfo(false);
    HdcSessionBase *sessionBase = new HdcSessionBase(false);
    info->ownerSessionClass = sessionBase;
    HdcTaskBaseExpose task(info);
    EXPECT_TRUE(task.ServerCommand(CMD_KERNEL_ECHO, nullptr, 0));

    delete info;
    delete sessionBase;
}

HWTEST_F(HdcTaskBaseTest, HdcTaskBase_ThreadCtrlCommunicate_SessionNotFound, TestSize.Level0)
{
    HTaskInfo info = CreateTaskInfo(false);
    HdcSessionBase *sessionBase = new HdcSessionBase(false);
    info->ownerSessionClass = sessionBase;
    HdcTaskBaseExpose task(info);
    uint8_t buf = 0;
    EXPECT_EQ(task.ThreadCtrlCommunicate(&buf, 1), -1);

    delete info;
    delete sessionBase;
}

HWTEST_F(HdcTaskBaseTest, HdcTaskBase_SendToAnother_NormalPath, TestSize.Level0)
{
    HTaskInfo info = CreateTaskInfo(false);
    info->sessionId = 0x2F2F2F2F;
    HdcSessionBase *sessionBase = new HdcSessionBase(false);
    info->ownerSessionClass = sessionBase;
    HdcTaskBaseExpose task(info);
    EXPECT_FALSE(task.SendToAnother(CMD_KERNEL_CHANNEL_CLOSE, nullptr, 0));

    delete info;
    delete sessionBase;
}
}  // namespace Hdc
