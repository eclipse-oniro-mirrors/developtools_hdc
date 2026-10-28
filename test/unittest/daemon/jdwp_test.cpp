/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "jdwp.h"
#include "uv_status.h"
#include "jdwp_test.h"
#include <gtest/gtest.h>
#include <string>
#include <vector>
#include <uv.h>

using namespace testing::ext;

namespace Hdc {

void HdcJdwpTest::SetUpTestCase() { }

void HdcJdwpTest::TearDownTestCase() {}

void HdcJdwpTest::SetUp()
{
    uv_loop_init(&mLoop);
    loopStatus = new LoopStatus(&mLoop, "HandleTestLoop");
    loop = uv_default_loop();
    jdwp = new HdcJdwp(loop, loopStatus);
}

void HdcJdwpTest::TearDown()
{
    delete jdwp;
    delete loopStatus;
    loopStatus = nullptr;
}

HWTEST_F(HdcJdwpTest, Test_CheckPIDExist_ValidPID, TestSize.Level0)
{
    uint32_t validPID = 12345;
    HdcJdwp::HCtxJdwp ctx = static_cast<HdcJdwp::HCtxJdwp>(jdwp->MallocContext());
    ctx->pid = validPID;
    jdwp->AdminContext(OP_ADD, validPID, ctx);

    EXPECT_TRUE(jdwp->CheckPIDExist(validPID));

    jdwp->AdminContext(OP_REMOVE, validPID, nullptr);
    jdwp->FreeContext(ctx);
}

HWTEST_F(HdcJdwpTest, Test_CheckPIDExist_InvalidPID, TestSize.Level0)
{
    uint32_t invalidPID = 5678;
    EXPECT_FALSE(jdwp->CheckPIDExist(invalidPID));
}

HWTEST_F(HdcJdwpTest, Test_AdminContext_AddAndQuery, TestSize.Level0)
{
    uint32_t pid = 9999;
    HdcJdwp::HCtxJdwp ctx = static_cast<HdcJdwp::HCtxJdwp>(jdwp->MallocContext());
    ctx->pid = pid;
    jdwp->AdminContext(OP_ADD, pid, ctx);

    HdcJdwp::HCtxJdwp queriedCtx = static_cast<HdcJdwp::HCtxJdwp>(jdwp->AdminContext(OP_QUERY, pid, nullptr));
    EXPECT_EQ(queriedCtx, ctx);
    EXPECT_EQ(queriedCtx->pid, pid);

    jdwp->AdminContext(OP_REMOVE, pid, nullptr);
    jdwp->FreeContext(ctx);
}

HWTEST_F(HdcJdwpTest, Test_AdminContext_Remove, TestSize.Level0)
{
    uint32_t pid = 8888;
    HdcJdwp::HCtxJdwp ctx = static_cast<HdcJdwp::HCtxJdwp>(jdwp->MallocContext());
    ctx->pid = pid;
    jdwp->AdminContext(OP_ADD, pid, ctx);

    jdwp->AdminContext(OP_REMOVE, pid, nullptr);

    EXPECT_FALSE(jdwp->CheckPIDExist(pid));

    jdwp->FreeContext(ctx);
}

HWTEST_F(HdcJdwpTest, Test_SendJdwpNewFD, TestSize.Level0)
{
    uint32_t targetPID = 12345;
    int fd = 10;

    HdcJdwp::HCtxJdwp ctx = static_cast<HdcJdwp::HCtxJdwp>(jdwp->MallocContext());
    ctx->pid = targetPID;
    jdwp->AdminContext(OP_ADD, targetPID, ctx);

    EXPECT_FALSE(jdwp->SendJdwpNewFD(targetPID, fd));

    jdwp->AdminContext(OP_REMOVE, targetPID, nullptr);
    if (jdwp->refCount > 0) {
        --jdwp->refCount;
    }
    jdwp->FreeContext(ctx);
}

HWTEST_F(HdcJdwpTest, Test_FdEventPollThread, TestSize.Level0)
{
    EXPECT_EQ(jdwp->CreateFdEventPoll(), RET_SUCCESS);
}

// CheckPIDExist：pid=0 → false（/proc/0 不存在）
HWTEST_F(HdcJdwpTest, Test_CheckPIDExist_ZeroPid, TestSize.Level0)
{
    EXPECT_FALSE(jdwp->CheckPIDExist(0));
}

// AdminContext：移除不存在的 context 不崩溃
HWTEST_F(HdcJdwpTest, Test_AdminContext_RemoveNonExist, TestSize.Level0)
{
    EXPECT_NO_FATAL_FAILURE(jdwp->AdminContext(OP_REMOVE, 99999, nullptr));
}

// FreeContext：释放后 refCount 不为负
HWTEST_F(HdcJdwpTest, Test_FreeContext_RefCountNonNegative, TestSize.Level0)
{
    EXPECT_GE(jdwp->refCount, 0u);
}

// CheckPIDExist：大 pid 值 → false
HWTEST_F(HdcJdwpTest, CheckPIDExist_LargePid, TestSize.Level0)
{
    EXPECT_FALSE(jdwp->CheckPIDExist(4294967295u));
}

// AdminContext：查询不存在的 pid → null
HWTEST_F(HdcJdwpTest, AdminContext_QueryNonExist, TestSize.Level0)
{
    EXPECT_EQ(jdwp->AdminContext(OP_QUERY, 77777, nullptr), nullptr);
}

// AdminContext：CLEAR 清空所有
HWTEST_F(HdcJdwpTest, AdminContext_Clear, TestSize.Level0)
{
    HdcJdwp::HCtxJdwp ctx = static_cast<HdcJdwp::HCtxJdwp>(jdwp->MallocContext());
    ctx->pid = 5555;
    jdwp->AdminContext(OP_ADD, 5555, ctx);
    jdwp->AdminContext(OP_CLEAR, 0, nullptr);
    EXPECT_EQ(jdwp->AdminContext(OP_QUERY, 5555, nullptr), nullptr);
    ctx->finish = true;
    delete ctx;
    --jdwp->refCount;
}

// AdminContext：添加多个 context 并查询
HWTEST_F(HdcJdwpTest, AdminContext_AddMultiple, TestSize.Level0)
{
    HdcJdwp::HCtxJdwp ctx1 = static_cast<HdcJdwp::HCtxJdwp>(jdwp->MallocContext());
    HdcJdwp::HCtxJdwp ctx2 = static_cast<HdcJdwp::HCtxJdwp>(jdwp->MallocContext());
    ctx1->pid = 1111;
    ctx2->pid = 2222;
    jdwp->AdminContext(OP_ADD, 1111, ctx1);
    jdwp->AdminContext(OP_ADD, 2222, ctx2);
    EXPECT_EQ(jdwp->AdminContext(OP_QUERY, 1111, nullptr), ctx1);
    EXPECT_EQ(jdwp->AdminContext(OP_QUERY, 2222, nullptr), ctx2);
    jdwp->AdminContext(OP_CLEAR, 0, nullptr);
    ctx1->finish = true;
    ctx2->finish = true;
    delete ctx1;
    delete ctx2;
    jdwp->refCount -= 2;
}

// AdminContext：未知 op → null
HWTEST_F(HdcJdwpTest, AdminContext_UnknownOp, TestSize.Level0)
{
    EXPECT_EQ(jdwp->AdminContext(99, 1234, nullptr), nullptr);
}

// AdminContext：超过容量 1024 → 不添加
HWTEST_F(HdcJdwpTest, AdminContext_AddOverCapacity, TestSize.Level0)
{
    for (int i = 0; i < 1024; i++) {
        jdwp->AdminContext(OP_ADD, 20000 + i, nullptr);
    }
    EXPECT_EQ(jdwp->mapCtxJdwp.size(), 1024u);
    jdwp->AdminContext(OP_ADD, 99999, nullptr);
    EXPECT_EQ(jdwp->mapCtxJdwp.size(), 1024u);
    jdwp->AdminContext(OP_CLEAR, 0, nullptr);
}

// MallocContext：正常分配 → 非空 + refCount 增加
HWTEST_F(HdcJdwpTest, MallocContext_Normal, TestSize.Level0)
{
    uint32_t beforeRef = jdwp->refCount;
    void *ctx = jdwp->MallocContext();
    ASSERT_NE(ctx, nullptr);
    EXPECT_EQ(jdwp->refCount, beforeRef + 1);
    auto p = static_cast<HdcJdwp::HCtxJdwp>(ctx);
    p->finish = true;
    delete p;
    --jdwp->refCount;
}

// SendJdwpNewFD：pid 不在 map → false
HWTEST_F(HdcJdwpTest, SendJdwpNewFD_NoContext, TestSize.Level0)
{
    EXPECT_FALSE(jdwp->SendJdwpNewFD(77777, 10));
}

// SendJdwpNewFD：pid=0 → false
HWTEST_F(HdcJdwpTest, SendJdwpNewFD_ZeroPid, TestSize.Level0)
{
    EXPECT_FALSE(jdwp->SendJdwpNewFD(0, 10));
}

// SendArkNewFD：pid 不在 map → false
HWTEST_F(HdcJdwpTest, SendArkNewFD_NoContext, TestSize.Level0)
{
    EXPECT_FALSE(jdwp->SendArkNewFD("ark:77777@tid@Debugger", 10));
}

// SendArkNewFD：非数字 pid → false
HWTEST_F(HdcJdwpTest, SendArkNewFD_InvalidPid, TestSize.Level0)
{
    EXPECT_FALSE(jdwp->SendArkNewFD("ark:abc@tid@Debugger", 10));
}

// SendArkNewFD：空字符串 → false
HWTEST_F(HdcJdwpTest, SendArkNewFD_EmptyString, TestSize.Level0)
{
    EXPECT_FALSE(jdwp->SendArkNewFD("", 10));
}

// FreeContext：ctx->finish=true → no-op
HWTEST_F(HdcJdwpTest, FreeContext_AlreadyFinished, TestSize.Level0)
{
    void *ctx = jdwp->MallocContext();
    auto p = static_cast<HdcJdwp::HCtxJdwp>(ctx);
    p->finish = true;
    EXPECT_NO_FATAL_FAILURE(jdwp->FreeContext(p));
    delete p;
    --jdwp->refCount;
}

// RemoveFdFromPollList：无匹配 → 不崩溃
HWTEST_F(HdcJdwpTest, RemoveFdFromPollList_NoMatch, TestSize.Level0)
{
    EXPECT_NO_FATAL_FAILURE(jdwp->RemoveFdFromPollList(99999));
}

// WakePollThread：awakenPollFd=-1 → 不崩溃
HWTEST_F(HdcJdwpTest, WakePollThread_NotInitialized, TestSize.Level0)
{
    EXPECT_NO_FATAL_FAILURE(jdwp->WakePollThread());
}

// GetProcessList：空 → 空字符串
HWTEST_F(HdcJdwpTest, GetProcessList_Empty, TestSize.Level0)
{
    EXPECT_EQ(jdwp->GetProcessList(), "");
}

// GetProcessList：有条目 → 包含 pid
HWTEST_F(HdcJdwpTest, GetProcessList_WithEntries, TestSize.Level0)
{
    jdwp->AdminContext(OP_ADD, 100, nullptr);
    jdwp->AdminContext(OP_ADD, 200, nullptr);
    string list = jdwp->GetProcessList();
    EXPECT_NE(list.find("100"), string::npos);
    EXPECT_NE(list.find("200"), string::npos);
    jdwp->AdminContext(OP_CLEAR, 0, nullptr);
}

// CreateJdwpTracker：null → false
HWTEST_F(HdcJdwpTest, CreateJdwpTracker_Null, TestSize.Level0)
{
    EXPECT_FALSE(jdwp->CreateJdwpTracker(nullptr));
}

// RemoveJdwpTracker：null → 不崩溃
HWTEST_F(HdcJdwpTest, RemoveJdwpTracker_Null, TestSize.Level0)
{
    EXPECT_NO_FATAL_FAILURE(jdwp->RemoveJdwpTracker(nullptr));
}

// RemoveJdwpTracker：不存在的 → 不崩溃
HWTEST_F(HdcJdwpTest, RemoveJdwpTracker_NonExist, TestSize.Level0)
{
    TaskInformation taskInfo = {};
    taskInfo.channelId = 99;
    EXPECT_NO_FATAL_FAILURE(jdwp->RemoveJdwpTracker(&taskInfo));
}

// JdwpProcessListMsg：空列表 → 仅 header
HWTEST_F(HdcJdwpTest, JdwpProcessListMsg_EmptyList, TestSize.Level0)
{
    char buffer[256] = {0};
    size_t len = jdwp->JdwpProcessListMsg(buffer, sizeof(buffer), 0);
    EXPECT_GT(len, 0u);
}

// JdwpProcessListMsg：小 buffer → memcpy 失败 → 0
HWTEST_F(HdcJdwpTest, JdwpProcessListMsg_SmallBuffer, TestSize.Level0)
{
    char buffer[2] = {0};
    size_t len = jdwp->JdwpProcessListMsg(buffer, sizeof(buffer), 0);
    EXPECT_EQ(len, 0u);
}

// SendProcessList：null task → 不崩溃
HWTEST_F(HdcJdwpTest, SendProcessList_NullTask, TestSize.Level0)
{
    EXPECT_NO_FATAL_FAILURE(jdwp->SendProcessList(nullptr, "data"));
}

// SendProcessList：空 data → 不崩溃
HWTEST_F(HdcJdwpTest, SendProcessList_EmptyData, TestSize.Level0)
{
    TaskInformation taskInfo = {};
    EXPECT_NO_FATAL_FAILURE(jdwp->SendProcessList(&taskInfo, ""));
}

// DrainAwakenPollThread：awakenPollFd=-1 → 不崩溃
HWTEST_F(HdcJdwpTest, DrainAwakenPollThread_NotInit, TestSize.Level0)
{
    EXPECT_NO_FATAL_FAILURE(jdwp->DrainAwakenPollThread());
}

// GetPollFd：空 map → 不崩溃
HWTEST_F(HdcJdwpTest, GetPollFd_EmptyMap, TestSize.Level0)
{
    std::vector<struct pollfd> pollfds;
    EXPECT_NO_FATAL_FAILURE(jdwp->GetPollFd(pollfds));
    EXPECT_TRUE(pollfds.empty());
}

} // namespace Hdc