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
#include <gtest/gtest.h>
#include "forward.h"
#include "task.h"

using namespace testing::ext;
using namespace testing;

namespace Hdc {
class HdcForwardBaseTest : public ::testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HdcForwardBaseTest::SetUpTestCase() {}
void HdcForwardBaseTest::TearDownTestCase() {}
void HdcForwardBaseTest::SetUp() {}
void HdcForwardBaseTest::TearDown() {}

HWTEST_F(HdcForwardBaseTest, HdcForwardBase_ConstructorInitializesFdsToMinusOne, TestSize.Level0)
{
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);
    EXPECT_EQ(forward.fds[0], -1);
    EXPECT_EQ(forward.fds[1], -1);

    delete info;
}

HWTEST_F(HdcForwardBaseTest, StopTask_WithTwoEntries, TestSize.Level0)
{
    auto* ctx1 = new HdcForwardBase::ContextForward();
    auto* ctx2 = new HdcForwardBase::ContextForward();
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);

    ctx1->id = 1;
    ctx1->type = HdcForwardBase::FORWARD_TCP;
    ctx1->thisClass = &forward;
    ctx1->localArgs[0] = "tcp";
    ctx1->localArgs[1] = "8080";
    ctx1->remoteArgs[0] = "tcp";
    ctx1->remoteArgs[1] = "remote:9090";
    ctx1->tcp.data = ctx1;  // 设置 data 为自身，供 uv_close 使用
    ctx1->finish = true;

    ctx2->id = 2;
    ctx2->type = HdcForwardBase::FORWARD_ABSTRACT;
    ctx2->thisClass = &forward;
    ctx2->localArgs[0] = "localabstract";
    ctx2->localArgs[1] = "sockname";
    ctx2->pipe.data = ctx2;
    ctx2->finish = true;

    forward.mapCtxPoint[1] = ctx1;
    forward.mapCtxPoint[2] = ctx2;

    EXPECT_FALSE(forward.mapCtxPoint.empty());
    forward.StopTask();
    EXPECT_TRUE(forward.mapCtxPoint.empty());

    delete ctx1;
    delete ctx2;
    delete info;
}

HWTEST_F(HdcForwardBaseTest, CheckNodeInfo_ValidTcp, TestSize.Level0)
{
    std::string as[2];
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);
    EXPECT_TRUE(forward.CheckNodeInfo("tcp:1234", as));
    EXPECT_EQ(as[0], "tcp");
    EXPECT_EQ(as[1], "1234");

    delete info;
}

HWTEST_F(HdcForwardBaseTest, CheckNodeInfo_InvalidFormat, TestSize.Level0)
{
    std::string as[2];
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);
    EXPECT_FALSE(forward.CheckNodeInfo("tcp:", as));
    EXPECT_FALSE(forward.CheckNodeInfo(":1234", as));
    EXPECT_FALSE(forward.CheckNodeInfo("tcp", as));
    EXPECT_FALSE(forward.CheckNodeInfo("", as));

    delete info;
}

HWTEST_F(HdcForwardBaseTest, CheckNodeInfo_InvalidPort, TestSize.Level0)
{
    std::string as[2];
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);
    EXPECT_FALSE(forward.CheckNodeInfo("tcp:0", as));
    EXPECT_FALSE(forward.CheckNodeInfo("tcp:999999", as));

    delete info;
}

HWTEST_F(HdcForwardBaseTest, AllocForwardBuf_SizeExceedsMaxBulk, TestSize.Level0)
{
    size_t sizeSuggested = MAX_USBFFS_BULK + 1024;
    uv_handle_t dummyHandle;
    uv_buf_t buf;
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);

    forward.AllocForwardBuf(&dummyHandle, sizeSuggested, &buf);

    ASSERT_NE(buf.base, nullptr);
    EXPECT_EQ(buf.len, MAX_USBFFS_BULK - 1);

    delete info;
    delete[] buf.base;
}

HWTEST_F(HdcForwardBaseTest, AllocForwardBuf_NormalSize, TestSize.Level0)
{
    size_t sizeSuggested = 1024;
    uv_handle_t dummyHandle;
    uv_buf_t buf;
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);

    forward.AllocForwardBuf(&dummyHandle, sizeSuggested, &buf);

    ASSERT_NE(buf.base, nullptr);
    EXPECT_EQ(buf.len, sizeSuggested - 1);

    delete info;
    delete[] buf.base;
}

HWTEST_F(HdcForwardBaseTest, AllocForwardBuf_ZeroSize, TestSize.Level0)
{
    size_t sizeSuggested = 0;
    uv_handle_t dummyHandle;
    uv_buf_t buf;
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);

    forward.AllocForwardBuf(&dummyHandle, sizeSuggested, &buf);

    ASSERT_NE(buf.base, nullptr);
    EXPECT_EQ(buf.len, 0);

    delete info;
    delete[] buf.base;
}

HWTEST_F(HdcForwardBaseTest, AllocForwardBuf_ExactMaxBulkSize, TestSize.Level0)
{
    size_t sizeSuggested = MAX_USBFFS_BULK;
    uv_handle_t dummyHandle;
    uv_buf_t buf;
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);

    forward.AllocForwardBuf(&dummyHandle, sizeSuggested, &buf);

    ASSERT_NE(buf.base, nullptr);
    EXPECT_EQ(buf.len, MAX_USBFFS_BULK - 1);
    
    delete info;
    delete[] buf.base;
}

HWTEST_F(HdcForwardBaseTest, CheckNodeInfo_NullInput, TestSize.Level0)
{
    string result[2];
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);
    EXPECT_FALSE(forward.CheckNodeInfo(nullptr, result));

    delete info;
}

HWTEST_F(HdcForwardBaseTest, CheckNodeInfo_EmptyString, TestSize.Level0)
{
    string result[2];
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);
    EXPECT_FALSE(forward.CheckNodeInfo("", result));

    delete info;
}

HWTEST_F(HdcForwardBaseTest, CheckNodeInfo_ColonAtStart, TestSize.Level0)
{
    string result[2];
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);
    EXPECT_FALSE(forward.CheckNodeInfo(":8080", result));

    delete info;
}

HWTEST_F(HdcForwardBaseTest, CheckNodeInfo_ColonAtEnd, TestSize.Level0)
{
    string result[2];
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);
    EXPECT_FALSE(forward.CheckNodeInfo("tcp:", result));

    delete info;
}

HWTEST_F(HdcForwardBaseTest, CheckNodeInfo_NoColon, TestSize.Level0)
{
    string result[2];
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);
    EXPECT_FALSE(forward.CheckNodeInfo("tcp", result));

    delete info;
}

HWTEST_F(HdcForwardBaseTest, CheckNodeInfo_TcpWithInvalidPortText, TestSize.Level0)
{
    string result[2];
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);
    EXPECT_FALSE(forward.CheckNodeInfo("tcp:abc", result));

    delete info;
}

HWTEST_F(HdcForwardBaseTest, CheckNodeInfo_TcpWithZeroPort, TestSize.Level0)
{
    string result[2];
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);
    EXPECT_FALSE(forward.CheckNodeInfo("tcp:0", result));

    delete info;
}

HWTEST_F(HdcForwardBaseTest, CheckNodeInfo_TcpWithPortExceedingMax, TestSize.Level0)
{
    string result[2];
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);
    EXPECT_FALSE(forward.CheckNodeInfo("tcp:65536", result)); // MAX_IP_PORT = 65535

    delete info;
}

HWTEST_F(HdcForwardBaseTest, CheckNodeInfo_TcpWithValidPort, TestSize.Level0)
{
    string result[2];
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);
    EXPECT_TRUE(forward.CheckNodeInfo("tcp:8080", result));
    EXPECT_EQ(result[0], "tcp");
    EXPECT_EQ(result[1], "8080");

    delete info;
}

HWTEST_F(HdcForwardBaseTest, CheckNodeInfo_NonTcpWithValidFormat, TestSize.Level0)
{
    string result[2];
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);
    EXPECT_TRUE(forward.CheckNodeInfo("udp:192.168.1.1", result));
    EXPECT_EQ(result[0], "udp");
    EXPECT_EQ(result[1], "192.168.1.1");

    delete info;
}

HWTEST_F(HdcForwardBaseTest, DetechForwardType_TC01_TCP, TestSize.Level0)
{
    auto* ctx = new HdcForwardBase::ContextForward();
    ctx->localArgs[0] = "tcp";
    ctx->localArgs[1] = "any";
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);
    EXPECT_TRUE(forward.DetechForwardType(ctx));
    EXPECT_EQ(ctx->type, HdcForwardBase::FORWARD_TCP);

    delete info;
    delete ctx;
}

HWTEST_F(HdcForwardBaseTest, DetectForwardType_TC02_DEV, TestSize.Level0)
{
    auto* ctx = new HdcForwardBase::ContextForward();
    ctx->localArgs[0] = "dev";
    ctx->localArgs[1] = "any";
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);
    EXPECT_TRUE(forward.DetechForwardType(ctx));
    EXPECT_EQ(ctx->type, HdcForwardBase::FORWARD_DEVICE);

    delete info;
    delete ctx;
}

HWTEST_F(HdcForwardBaseTest, DetectForwardType_TC03_LOCALABSTRACT, TestSize.Level0)
{
    auto* ctx = new HdcForwardBase::ContextForward();
    ctx->localArgs[0] = "localabstract";
    ctx->localArgs[1] = "any";
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);
    EXPECT_TRUE(forward.DetechForwardType(ctx));
    EXPECT_EQ(ctx->type, HdcForwardBase::FORWARD_ABSTRACT);

    delete info;
    delete ctx;
}

HWTEST_F(HdcForwardBaseTest, DetectForwardType_TC04_LOCALRESERVED, TestSize.Level0)
{
    auto* ctx = new HdcForwardBase::ContextForward();
    ctx->localArgs[0] = "localreserved";
    ctx->localArgs[1] = "sockname";
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);
    EXPECT_TRUE(forward.DetechForwardType(ctx));
    EXPECT_EQ(ctx->type, HdcForwardBase::FORWARD_RESERVED);
    EXPECT_EQ(ctx->localArgs[1], "/dev/socket/sockname");

    delete info;
    delete ctx;
}

HWTEST_F(HdcForwardBaseTest, DetectForwardType_TC05_LOCALFILESYSTEM, TestSize.Level0)
{
    auto* ctx = new HdcForwardBase::ContextForward();
    ctx->localArgs[0] = "localfilesystem";
    ctx->localArgs[1] = "path";
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);
    EXPECT_TRUE(forward.DetechForwardType(ctx));
    EXPECT_EQ(ctx->type, HdcForwardBase::FORWARD_FILESYSTEM);
    EXPECT_EQ(ctx->localArgs[1], "/tmp/path");

    delete info;
    delete ctx;
}

HWTEST_F(HdcForwardBaseTest, DetectForwardType_TC06_JDWP, TestSize.Level0)
{
    auto* ctx = new HdcForwardBase::ContextForward();
    ctx->localArgs[0] = "jdwp";
    ctx->localArgs[1] = "any";
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);
    EXPECT_TRUE(forward.DetechForwardType(ctx));
    EXPECT_EQ(ctx->type, HdcForwardBase::FORWARD_JDWP);

    delete info;
    delete ctx;
}

HWTEST_F(HdcForwardBaseTest, DetectForwardType_TC07_ARK, TestSize.Level0)
{
    auto* ctx = new HdcForwardBase::ContextForward();
    ctx->localArgs[0] = "ark";
    ctx->localArgs[1] = "any";
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);
    EXPECT_TRUE(forward.DetechForwardType(ctx));
    EXPECT_EQ(ctx->type, HdcForwardBase::FORWARD_ARK);

    delete info;
    delete ctx;
}

HWTEST_F(HdcForwardBaseTest, DetectForwardType_TC08_INVALID, TestSize.Level0)
{
    auto* ctx = new HdcForwardBase::ContextForward();
    ctx->localArgs[0] = "invalid";
    ctx->localArgs[1] = "any";
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);
    EXPECT_FALSE(forward.DetechForwardType(ctx));

    delete info;
    delete ctx;
}

HWTEST_F(HdcForwardBaseTest, CheckNodeInfo_WhitespaceInput, TestSize.Level0)
{
    std::string as[2];
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);
    EXPECT_FALSE(forward.CheckNodeInfo(" ", as));
    EXPECT_TRUE(forward.CheckNodeInfo("tcp:8080", as));
    EXPECT_EQ(as[0], "tcp");
    EXPECT_EQ(as[1], "8080");

    delete info;
}

HWTEST_F(HdcForwardBaseTest, DetectForwardType_EmptyArgs, TestSize.Level0)
{
    auto* ctx = new HdcForwardBase::ContextForward();
    ctx->localArgs[0] = "";
    ctx->localArgs[1] = "";
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);
    EXPECT_FALSE(forward.DetechForwardType(ctx));

    delete info;
    delete ctx;
}

HWTEST_F(HdcForwardBaseTest, StopTask_EmptyMap, TestSize.Level0)
{
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);

    EXPECT_TRUE(forward.mapCtxPoint.empty());
    forward.StopTask();
    EXPECT_TRUE(forward.mapCtxPoint.empty());

    delete info;
}

HWTEST_F(HdcForwardBaseTest, AdminContext_AddAndQuery, TestSize.Level0)
{
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);

    auto* ctx = new HdcForwardBase::ContextForward();
    ctx->id = 100;
    ctx->finish = true;

    forward.AdminContext(OP_ADD, 100, ctx);
    auto* result = forward.AdminContext(OP_QUERY, 100, nullptr);
    EXPECT_EQ(result, ctx);

    forward.AdminContext(OP_REMOVE, 100, nullptr);
    result = forward.AdminContext(OP_QUERY, 100, nullptr);
    EXPECT_EQ(result, nullptr);

    delete ctx;
    delete info;
}

HWTEST_F(HdcForwardBaseTest, AdminContext_Update, TestSize.Level0)
{
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);

    auto* ctx1 = new HdcForwardBase::ContextForward();
    ctx1->id = 100;
    ctx1->finish = true;
    forward.AdminContext(OP_ADD, 100, ctx1);

    auto* ctx2 = new HdcForwardBase::ContextForward();
    ctx2->id = 200;
    ctx2->finish = true;
    forward.AdminContext(OP_UPDATE, 100, ctx2);

    auto* result = forward.AdminContext(OP_QUERY, 200, nullptr);
    EXPECT_EQ(result, ctx2);

    delete ctx1;
    delete ctx2;
    delete info;
}

HWTEST_F(HdcForwardBaseTest, ReadyForRelease_InitialState, TestSize.Level0)
{
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);

    EXPECT_TRUE(forward.ReadyForRelease());

    delete info;
}

HWTEST_F(HdcForwardBaseTest, MallocContext_AllocateAndRefCount, TestSize.Level0)
{
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);

    auto* ctx = forward.MallocContext(true);
    EXPECT_NE(ctx, nullptr);
    EXPECT_EQ(forward.refCount, 1);

    auto* ctx2 = forward.MallocContext(false);
    EXPECT_NE(ctx2, nullptr);
    EXPECT_EQ(forward.refCount, 2);

    delete (HdcForwardBase::ContextForward*)ctx;
    delete (HdcForwardBase::ContextForward*)ctx2;
    delete info;
}

HWTEST_F(HdcForwardBaseTest, SendToTask_OverMaxBufSize, TestSize.Level0)
{
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);

    int bufSize = Base::GetMaxBufSizeStable() * BUF_MULTIPLE + 1;
    uint8_t data = 0;
    EXPECT_FALSE(forward.SendToTask(1, CMD_FORWARD_DATA, &data, bufSize));

    delete info;
}

HWTEST_F(HdcForwardBaseTest, SendToTask_SingalStop, TestSize.Level0)
{
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);
    forward.singalStop = true;

    uint8_t data[4] = { 0x11, 0x22, 0x33, 0x44 };
    EXPECT_FALSE(forward.SendToTask(1, CMD_FORWARD_DATA, data, 4));

    delete info;
}

HWTEST_F(HdcForwardBaseTest, SendToTask_ZeroPayload, TestSize.Level0)
{
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);
    forward.singalStop = true;

    EXPECT_FALSE(forward.SendToTask(1, CMD_FORWARD_DATA, nullptr, 0));

    delete info;
}

HWTEST_F(HdcForwardBaseTest, GetForwardStream_TypeToStreamMapping, TestSize.Level0)
{
    auto* ctx = new HdcForwardBase::ContextForward();
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);

    ctx->type = HdcForwardBase::FORWARD_TCP;
    EXPECT_EQ(forward.GetForwardStream(ctx), (uv_stream_t *)&ctx->tcp);
    ctx->type = HdcForwardBase::FORWARD_JDWP;
    EXPECT_EQ(forward.GetForwardStream(ctx), (uv_stream_t *)&ctx->tcp);
    ctx->type = HdcForwardBase::FORWARD_ARK;
    EXPECT_EQ(forward.GetForwardStream(ctx), (uv_stream_t *)&ctx->tcp);
    ctx->type = HdcForwardBase::FORWARD_ABSTRACT;
    EXPECT_EQ(forward.GetForwardStream(ctx), (uv_stream_t *)&ctx->pipe);
    ctx->type = HdcForwardBase::FORWARD_RESERVED;
    EXPECT_EQ(forward.GetForwardStream(ctx), (uv_stream_t *)&ctx->pipe);
    ctx->type = HdcForwardBase::FORWARD_FILESYSTEM;
    EXPECT_EQ(forward.GetForwardStream(ctx), (uv_stream_t *)&ctx->pipe);
    ctx->type = HdcForwardBase::FORWARD_DEVICE;
    EXPECT_EQ(forward.GetForwardStream(ctx), (uv_stream_t *)&ctx->pipe);

    delete ctx;
    delete info;
}

HWTEST_F(HdcForwardBaseTest, SlaveConnect_SmallBufSize, TestSize.Level0)
{
    uint8_t bufCmd[12] = { 0 };
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);

    string sError;
    EXPECT_FALSE(forward.SlaveConnect(bufCmd, sizeof(bufCmd), true, sError));

    delete info;
}

HWTEST_F(HdcForwardBaseTest, SendForwardBuf_SizeExceedMax, TestSize.Level0)
{
    auto* ctx = new HdcForwardBase::ContextForward();
    ctx->id = 1;
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);

    uint8_t data = 0;
    EXPECT_EQ(forward.SendForwardBuf(ctx, &data, INT_MAX), -1);

    delete ctx;
    delete info;
}

HWTEST_F(HdcForwardBaseTest, SendForwardBuf_SizeNotPositive, TestSize.Level0)
{
    auto* ctx = new HdcForwardBase::ContextForward();
    ctx->id = 1;
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);

    uint8_t data = 0;
    EXPECT_EQ(forward.SendForwardBuf(ctx, &data, 0), -1);
    EXPECT_EQ(forward.SendForwardBuf(ctx, &data, -1), -1);

    delete ctx;
    delete info;
}

HWTEST_F(HdcForwardBaseTest, ForwardCommandDispatch_SmallPayload, TestSize.Level0)
{
    uint8_t payload[4] = { 0 };
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);

    EXPECT_FALSE(forward.ForwardCommandDispatch(CMD_FORWARD_DATA, payload, 4));

    delete info;
}

HWTEST_F(HdcForwardBaseTest, ForwardCommandDispatch_UnknownContext, TestSize.Level0)
{
    uint8_t payload[8] = { 0 };
    *reinterpret_cast<uint32_t *>(payload) = htonl(0xDEADBEEF);
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);

    EXPECT_TRUE(forward.ForwardCommandDispatch(CMD_FORWARD_DATA, payload, 8));

    delete info;
}

HWTEST_F(HdcForwardBaseTest, ForwardCommandDispatch_ActiveMasterSmallPayload, TestSize.Level0)
{
    uint8_t payload[4] = { 0 };
    *reinterpret_cast<uint32_t *>(payload) = htonl(0xABCDEF01);
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);

    EXPECT_TRUE(forward.ForwardCommandDispatch(CMD_FORWARD_ACTIVE_MASTER, payload, 4));

    delete info;
}

HWTEST_F(HdcForwardBaseTest, ForwardCommandDispatch_FreeContext, TestSize.Level0)
{
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);

    auto* ctx = (HdcForwardBase::ContextForward *)forward.MallocContext(false);
    ASSERT_NE(ctx, nullptr);
    ctx->finish = true;
    uint8_t payload[8] = { 0 };
    *reinterpret_cast<uint32_t *>(payload) = htonl(ctx->id);
    EXPECT_TRUE(forward.ForwardCommandDispatch(CMD_FORWARD_FREE_CONTEXT, payload, 8));

    forward.AdminContext(OP_REMOVE, ctx->id, nullptr);
    delete ctx;
    delete info;
}

HWTEST_F(HdcForwardBaseTest, ForwardCommandDispatch_CheckResultFail, TestSize.Level0)
{
    HTaskInfo info = new TaskInformation();
    info->channelTask = true;
    HdcForwardBase forward(info);

    auto* ctx = (HdcForwardBase::ContextForward *)forward.MallocContext(false);
    ASSERT_NE(ctx, nullptr);
    ctx->finish = true;
    uint8_t payload[8] = { 0 };
    *reinterpret_cast<uint32_t *>(payload) = htonl(ctx->id);
    EXPECT_FALSE(forward.ForwardCommandDispatch(CMD_FORWARD_CHECK_RESULT, payload, 8));

    forward.AdminContext(OP_REMOVE, ctx->id, nullptr);
    delete ctx;
    delete info;
}

HWTEST_F(HdcForwardBaseTest, ForwardCommandDispatch_DefaultCommand, TestSize.Level0)
{
    HTaskInfo info = new TaskInformation();
    info->channelTask = true;
    HdcForwardBase forward(info);

    auto* ctx = (HdcForwardBase::ContextForward *)forward.MallocContext(false);
    ASSERT_NE(ctx, nullptr);
    ctx->finish = true;
    uint8_t payload[8] = { 0 };
    *reinterpret_cast<uint32_t *>(payload) = htonl(ctx->id);
    EXPECT_FALSE(forward.ForwardCommandDispatch(0x5A5A, payload, 8));

    forward.AdminContext(OP_REMOVE, ctx->id, nullptr);
    delete ctx;
    delete info;
}

HWTEST_F(HdcForwardBaseTest, CommandDispatch_InitInvalidCommand, TestSize.Level0)
{
    HTaskInfo info = new TaskInformation();
    info->channelTask = true;
    HdcForwardBase forward(info);

    const char *cmd = "garbage";
    EXPECT_FALSE(forward.CommandDispatch(CMD_FORWARD_INIT, (uint8_t *)cmd, 7));
    for (auto &iter : forward.mapCtxPoint) {
        delete iter.second;
    }
    forward.mapCtxPoint.clear();

    delete info;
}

HWTEST_F(HdcForwardBaseTest, CommandDispatch_CheckSmallPayload, TestSize.Level0)
{
    uint8_t payload[12] = { 0 };
    HTaskInfo info = new TaskInformation();
    info->channelTask = true;
    HdcForwardBase forward(info);

    EXPECT_FALSE(forward.CommandDispatch(CMD_FORWARD_CHECK, payload, 12));

    delete info;
}

HWTEST_F(HdcForwardBaseTest, CommandDispatch_ActiveSlaveSmallPayload, TestSize.Level0)
{
    uint8_t payload[12] = { 0 };
    HTaskInfo info = new TaskInformation();
    info->channelTask = true;
    HdcForwardBase forward(info);

    EXPECT_FALSE(forward.CommandDispatch(CMD_FORWARD_ACTIVE_SLAVE, payload, 12));

    delete info;
}

HWTEST_F(HdcForwardBaseTest, BeginForward_InvalidCommand, TestSize.Level0)
{
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);

    string sError;
    EXPECT_FALSE(forward.BeginForward("garbage", sError));
    for (auto &iter : forward.mapCtxPoint) {
        delete iter.second;
    }
    forward.mapCtxPoint.clear();

    delete info;
}

HWTEST_F(HdcForwardBaseTest, BeginForward_OverlongArgv, TestSize.Level0)
{
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);

    string longCmd(300, 'a');
    longCmd += ":8080 tcp:1234";
    string sError;
    EXPECT_FALSE(forward.BeginForward(longCmd, sError));
    for (auto &iter : forward.mapCtxPoint) {
        delete iter.second;
    }
    forward.mapCtxPoint.clear();

    delete info;
}

HWTEST_F(HdcForwardBaseTest, ReadyForRelease_RefCountNotZero, TestSize.Level0)
{
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);
    forward.refCount = 1;

    EXPECT_FALSE(forward.ReadyForRelease());

    delete info;
}

HWTEST_F(HdcForwardBaseTest, DetechForwardType_DevPathTraversal, TestSize.Level0)
{
    auto* ctx = new HdcForwardBase::ContextForward();
    ctx->localArgs[0] = "dev";
    ctx->localArgs[1] = "a/../b";
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);

    EXPECT_FALSE(forward.DetechForwardType(ctx));
    EXPECT_EQ(ctx->lastError, "Invalid path: path traversal not allowed");

    delete info;
    delete ctx;
}

HWTEST_F(HdcForwardBaseTest, DetechForwardType_LocalReservedPathTraversal, TestSize.Level0)
{
    auto* ctx = new HdcForwardBase::ContextForward();
    ctx->localArgs[0] = "localreserved";
    ctx->localArgs[1] = "a/../b";
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);

    EXPECT_FALSE(forward.DetechForwardType(ctx));
    EXPECT_EQ(ctx->lastError, "Invalid path: path traversal not allowed");

    delete info;
    delete ctx;
}

HWTEST_F(HdcForwardBaseTest, DetechForwardType_LocalFileSystemPathTraversal, TestSize.Level0)
{
    auto* ctx = new HdcForwardBase::ContextForward();
    ctx->localArgs[0] = "localfilesystem";
    ctx->localArgs[1] = "a/../b";
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);

    EXPECT_FALSE(forward.DetechForwardType(ctx));
    EXPECT_EQ(ctx->lastError, "Invalid path: path traversal not allowed");

    delete info;
    delete ctx;
}

HWTEST_F(HdcForwardBaseTest, SetupPoint_ArkUnsupported, TestSize.Level0)
{
    auto* ctx = new HdcForwardBase::ContextForward();
    ctx->localArgs[0] = "ark";
    ctx->localArgs[1] = "any";
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);

    EXPECT_FALSE(forward.SetupPoint(ctx));
    EXPECT_EQ(ctx->lastError, "Not supoort forward-type");

    delete info;
    delete ctx;
}

HWTEST_F(HdcForwardBaseTest, SetupPointContinue_CheckPointSendFail, TestSize.Level0)
{
    auto* ctx = new HdcForwardBase::ContextForward();
    ctx->checkPoint = true;
    ctx->finish = true;
    ctx->id = 1;
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);
    forward.singalStop = true;

    EXPECT_FALSE(forward.SetupPointContinue(ctx, 0));

    delete info;
    delete ctx;
}

HWTEST_F(HdcForwardBaseTest, SetupPointContinue_StatusNegative, TestSize.Level0)
{
    auto* ctx = new HdcForwardBase::ContextForward();
    ctx->checkPoint = false;
    ctx->finish = true;
    ctx->id = 1;
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);

    EXPECT_FALSE(forward.SetupPointContinue(ctx, -1));

    delete info;
    delete ctx;
}

HWTEST_F(HdcForwardBaseTest, SetupPointContinue_ActiveMasterSendFail, TestSize.Level0)
{
    auto* ctx = new HdcForwardBase::ContextForward();
    ctx->checkPoint = false;
    ctx->finish = true;
    ctx->id = 1;
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);
    forward.singalStop = true;

    EXPECT_FALSE(forward.SetupPointContinue(ctx, 0));

    delete info;
    delete ctx;
}

HWTEST_F(HdcForwardBaseTest, CommandForwardCheckResult_Failed, TestSize.Level0)
{
    HTaskInfo info = new TaskInformation();
    info->channelTask = true;
    HdcForwardBase forward(info);
    auto* ctx = new HdcForwardBase::ContextForward();
    ctx->finish = true;
    ctx->id = 1;

    EXPECT_FALSE(forward.CommandForwardCheckResult(ctx, nullptr));

    delete info;
    delete ctx;
}

HWTEST_F(HdcForwardBaseTest, DoForwardBegin_ArkInvalidFds, TestSize.Level0)
{
    auto* ctx = new HdcForwardBase::ContextForward();
    ctx->type = HdcForwardBase::FORWARD_ARK;
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);

    EXPECT_FALSE(forward.DoForwardBegin(ctx));

    delete info;
    delete ctx;
}

HWTEST_F(HdcForwardBaseTest, DoForwardBegin_InvalidType, TestSize.Level0)
{
    auto* ctx = new HdcForwardBase::ContextForward();
    ctx->type = static_cast<HdcForwardBase::FORWARD_TYPE>(99);
    HTaskInfo info = new TaskInformation();
    HdcForwardBase forward(info);

    EXPECT_FALSE(forward.DoForwardBegin(ctx));

    delete info;
    delete ctx;
}
} // namespace Hdc