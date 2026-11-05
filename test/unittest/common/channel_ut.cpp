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

#include <string>
#include <uv.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "channel.h"

using namespace testing::ext;
using namespace testing;

namespace Hdc {
class HdcChannelBaseTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    uv_loop_t loop{};
};

void HdcChannelBaseTest::SetUpTestCase() {}
void HdcChannelBaseTest::TearDownTestCase() {}
void HdcChannelBaseTest::SetUp()
{
    ASSERT_EQ(uv_loop_init(&loop), 0);
}
void HdcChannelBaseTest::TearDown()
{
    uv_loop_close(&loop);
}

// 构造：合法地址串 host:port 不崩溃
HWTEST_F(HdcChannelBaseTest, Constructor_ValidAddr_NoCrash, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(HdcChannelBase ch(true, "127.0.0.1:5055", &loop));
}

// 构造：空地址串不崩溃（走 SetChannelTCPString 解析失败分支）
HWTEST_F(HdcChannelBaseTest, Constructor_EmptyAddr_NoCrash, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(HdcChannelBase ch(true, "", &loop));
}

// 构造：无端口地址串
HWTEST_F(HdcChannelBaseTest, Constructor_NoPort_NoCrash, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(HdcChannelBase ch(false, "127.0.0.1", &loop));
}

// GetChannelHandshake：返回非空 vector，connectKey 被填充
HWTEST_F(HdcChannelBaseTest, GetChannelHandshake_ReturnsNonEmpty, TestSize.Level0)
{
    HdcChannelBase ch(true, "127.0.0.1:5055", &loop);
    string key;
    auto v = ch.GetChannelHandshake(key);
    EXPECT_FALSE(v.empty());
}

// EchoToAllChannelsViaSessionId：无 channel 时不崩溃（空遍历分支）
HWTEST_F(HdcChannelBaseTest, EchoToAll_NoChannels_NoCrash, TestSize.Level0)
{
    HdcChannelBase ch(true, "127.0.0.1:5055", &loop);
    EXPECT_NO_FATAL_FAILURE(ch.EchoToAllChannelsViaSessionId(999, "hi"));
}

// PushAsyncMessage：未知 channelId 不崩溃
HWTEST_F(HdcChannelBaseTest, PushAsyncMessage_UnknownChannel_NoCrash, TestSize.Level0)
{
    HdcChannelBase ch(true, "127.0.0.1:5055", &loop);
    uint8_t d = 1;
    EXPECT_NO_FATAL_FAILURE(ch.PushAsyncMessage(4321, 0, &d, sizeof(d)));
}

// SendWithCmd：未知 channelId 不崩溃
HWTEST_F(HdcChannelBaseTest, SendWithCmd_UnknownChannel_NoCrash, TestSize.Level0)
{
    HdcChannelBase ch(true, "127.0.0.1:5055", &loop);
    uint8_t d = 0;
    EXPECT_NO_FATAL_FAILURE(ch.SendWithCmd(4321, 0, &d, sizeof(d)));
}

// ===== TestableChannel：派生类暴露 protected 方法 =====
class TestableChannel : public HdcChannelBase {
public:
    using HdcChannelBase::HdcChannelBase;
    uint32_t PubMallocChannel(HChannel *hOutChannel) { return MallocChannel(hOutChannel); }
    void PubInitChannelTransport(HdcChannel *hChannel, uint32_t channelId)
    {
        InitChannelTransport(hChannel, channelId);
    }
    void PubSend(uint32_t channelId, uint8_t *buf, int size) { Send(channelId, buf, size); }
    void PubSendChannel(HChannel h, uint8_t *buf, int size, uint16_t cmd = 0)
    {
        SendChannel(h, buf, size, cmd);
    }
    void PubSendChannelWithCmd(HChannel h, uint16_t cmd, uint8_t *buf, int size)
    {
        SendChannelWithCmd(h, cmd, buf, size);
    }
    void PubEchoToClient(HChannel h, uint8_t *buf, int size) { EchoToClient(h, buf, size); }
};

// ===== AdminChannel 各 op 分支 =====
// OP_QUERY：不存在 channelId → 返回 nullptr
HWTEST_F(HdcChannelBaseTest, AdminChannel_OP_QUERY_NotFound_ReturnsNull, TestSize.Level0)
{
    HdcChannelBase ch(true, "127.0.0.1:5055", &loop);
    EXPECT_EQ(ch.AdminChannel(OP_QUERY, 9999, nullptr), nullptr);
}

// OP_QUERY_REF：不存在 channelId → 返回 nullptr（ref 不递增）
HWTEST_F(HdcChannelBaseTest, AdminChannel_OP_QUERY_REF_NotFound_ReturnsNull, TestSize.Level0)
{
    HdcChannelBase ch(true, "127.0.0.1:5055", &loop);
    EXPECT_EQ(ch.AdminChannel(OP_QUERY_REF, 9999, nullptr), nullptr);
}

// OP_REMOVE：移除不存在的 channelId → 不崩溃
HWTEST_F(HdcChannelBaseTest, AdminChannel_OP_REMOVE_NotExist_NoCrash, TestSize.Level0)
{
    HdcChannelBase ch(true, "127.0.0.1:5055", &loop);
    EXPECT_NO_FATAL_FAILURE(ch.AdminChannel(OP_REMOVE, 8888, nullptr));
}

// OP_PRINT：不存在 channelId → 不崩溃（HDC_HOST 走 PrintChannel，非 HDC_HOST 走 default break）
HWTEST_F(HdcChannelBaseTest, AdminChannel_OP_PRINT_NoCrash, TestSize.Level0)
{
    HdcChannelBase ch(true, "127.0.0.1:5055", &loop);
    EXPECT_NO_FATAL_FAILURE(ch.AdminChannel(OP_PRINT, 7777, nullptr));
}

// default：未知 op → 不崩溃
HWTEST_F(HdcChannelBaseTest, AdminChannel_OP_Default_UnknownOp_NoCrash, TestSize.Level0)
{
    HdcChannelBase ch(true, "127.0.0.1:5055", &loop);
    EXPECT_NO_FATAL_FAILURE(ch.AdminChannel(200, 1234, nullptr));
}

// OP_ADD + OP_QUERY：添加后查询能找到
HWTEST_F(HdcChannelBaseTest, AdminChannel_OP_ADD_ThenQuery_Found, TestSize.Level0)
{
    HdcChannelBase ch(true, "127.0.0.1:5055", &loop);
    auto hChannel = new HdcChannel();
    hChannel->channelId = 42;
    hChannel->ref.store(0);
    hChannel->isDead = false;
    ch.AdminChannel(OP_ADD, 42, hChannel);
    HChannel found = ch.AdminChannel(OP_QUERY, 42, nullptr);
    EXPECT_NE(found, nullptr);
    EXPECT_EQ(found->channelId, 42u);
    ch.AdminChannel(OP_REMOVE, 42, nullptr);
    delete hChannel;
}

// OP_QUERY_REF：找到后 ref 递增
HWTEST_F(HdcChannelBaseTest, AdminChannel_OP_QUERY_REF_IncrementsRef, TestSize.Level0)
{
    HdcChannelBase ch(true, "127.0.0.1:5055", &loop);
    auto hChannel = new HdcChannel();
    hChannel->channelId = 100;
    hChannel->ref.store(0);
    hChannel->isDead = false;
    ch.AdminChannel(OP_ADD, 100, hChannel);
    HChannel found = ch.AdminChannel(OP_QUERY_REF, 100, nullptr);
    EXPECT_NE(found, nullptr);
    EXPECT_EQ(found->ref.load(), 1u);
    --found->ref;
    ch.AdminChannel(OP_REMOVE, 100, nullptr);
    delete hChannel;
}

// OP_UPDATE：更新后查询返回新 channel
HWTEST_F(HdcChannelBaseTest, AdminChannel_OP_UPDATE_UpdatesChannel, TestSize.Level0)
{
    HdcChannelBase ch(true, "127.0.0.1:5055", &loop);
    auto oldCh = new HdcChannel();
    oldCh->channelId = 200;
    oldCh->ref.store(0);
    oldCh->isDead = false;
    ch.AdminChannel(OP_ADD, 200, oldCh);
    auto newCh = new HdcChannel();
    newCh->channelId = 201;
    newCh->ref.store(0);
    newCh->isDead = false;
    ch.AdminChannel(OP_UPDATE, 200, newCh);
    HChannel found = ch.AdminChannel(OP_QUERY, 201, nullptr);
    EXPECT_NE(found, nullptr);
    EXPECT_EQ(found->channelId, 201u);
    ch.AdminChannel(OP_REMOVE, 201, nullptr);
    delete oldCh;
    delete newCh;
}

// ===== AllocCallback 各分支 =====
// AllocCallback：context 为 nullptr → buf.base=null, buf.len=0
HWTEST_F(HdcChannelBaseTest, AllocCallback_NullContext_ReturnsNullBuf, TestSize.Level0)
{
    uv_handle_t handle;
    handle.data = nullptr;
    uv_buf_t buf;
    EXPECT_NO_FATAL_FAILURE(HdcChannelBase::AllocCallback(&handle, 1024, &buf));
    EXPECT_EQ(buf.base, nullptr);
    EXPECT_EQ(buf.len, 0u);
}

// AllocCallback：有效 context → 返回可用 buf
HWTEST_F(HdcChannelBaseTest, AllocCallback_ValidContext_ReturnsValidBuf, TestSize.Level0)
{
    auto ctx = new HdcChannel();
    ctx->ioBuf = new uint8_t[1024];
    ctx->bufSize = 1024;
    ctx->availTailIndex = 0;
    uv_handle_t handle;
    handle.data = ctx;
    uv_buf_t buf;
    EXPECT_NO_FATAL_FAILURE(HdcChannelBase::AllocCallback(&handle, 512, &buf));
    EXPECT_NE(buf.base, nullptr);
    EXPECT_GT(buf.len, 0u);
    delete[] ctx->ioBuf;
    delete ctx;
}

// AllocCallback：availSize <= 0 → 返回空 buf
HWTEST_F(HdcChannelBaseTest, AllocCallback_AvailSizeZero_ReturnsNullBuf, TestSize.Level0)
{
    auto ctx = new HdcChannel();
    ctx->ioBuf = new uint8_t[64];
    ctx->bufSize = 64;
    ctx->availTailIndex = 64;  // bufSize - availTailIndex = 0
    uv_handle_t handle;
    handle.data = ctx;
    uv_buf_t buf;
    EXPECT_NO_FATAL_FAILURE(HdcChannelBase::AllocCallback(&handle, 128, &buf));
    EXPECT_EQ(buf.base, nullptr);
    EXPECT_EQ(buf.len, 0u);
    delete[] ctx->ioBuf;
    delete ctx;
}

// ===== ReadStream 各 nread 分支 =====
// ReadStream：nread == UV_ENOBUFS → 走 nobufs 早返回分支
HWTEST_F(HdcChannelBaseTest, ReadStream_NreadEnobufs_NoCrash, TestSize.Level0)
{
    TestableChannel ch(true, "127.0.0.1:5055", &loop);
    HChannel hOut = nullptr;
    uint32_t cid = ch.PubMallocChannel(&hOut);
    ASSERT_NE(hOut, nullptr);
    uv_stream_t *stream = reinterpret_cast<uv_stream_t *>(&hOut->hWorkTCP);
    uv_buf_t buf = uv_buf_init(const_cast<char *>(""), 0);
    EXPECT_NO_FATAL_FAILURE(HdcChannelBase::ReadStream(stream, UV_ENOBUFS, &buf));
    ch.AdminChannel(OP_REMOVE, cid, nullptr);
    delete hOut;
}

// ReadStream：nread == 0 → 走 idle 分支
HWTEST_F(HdcChannelBaseTest, ReadStream_NreadZero_NoCrash, TestSize.Level0)
{
    TestableChannel ch(true, "127.0.0.1:5055", &loop);
    HChannel hOut = nullptr;
    uint32_t cid = ch.PubMallocChannel(&hOut);
    ASSERT_NE(hOut, nullptr);
    uv_stream_t *stream = reinterpret_cast<uv_stream_t *>(&hOut->hWorkTCP);
    uv_buf_t buf = uv_buf_init(const_cast<char *>(""), 0);
    EXPECT_NO_FATAL_FAILURE(HdcChannelBase::ReadStream(stream, 0, &buf));
    ch.AdminChannel(OP_REMOVE, cid, nullptr);
    delete hOut;
}

// ReadStream：nread > 0 且无完整包 → 走 while 循环不进入分支（availTailIndex <= DWORD_SERIALIZE_SIZE）
HWTEST_F(HdcChannelBaseTest, ReadStream_NreadPositive_NoFullPacket_NoCrash, TestSize.Level0)
{
    TestableChannel ch(true, "127.0.0.1:5055", &loop);
    HChannel hOut = nullptr;
    uint32_t cid = ch.PubMallocChannel(&hOut);
    ASSERT_NE(hOut, nullptr);
    uv_stream_t *stream = reinterpret_cast<uv_stream_t *>(&hOut->hWorkTCP);
    const char *data = "abc";
    uv_buf_t buf = uv_buf_init(const_cast<char *>(data), 3);
    // nread=3 → availTailIndex=3 ≤ DWORD_SERIALIZE_SIZE(4) → while 不执行，不访问 ioBuf
    EXPECT_NO_FATAL_FAILURE(HdcChannelBase::ReadStream(stream, 3, &buf));
    ch.AdminChannel(OP_REMOVE, cid, nullptr);
    delete hOut;
}

// ReadStream：nread > 0 且 size==0（magic 错/size 字段为 0）→ 走 size 校验分支
HWTEST_F(HdcChannelBaseTest, ReadStream_NreadPositive_ZeroSizeField_NoCrash, TestSize.Level0)
{
    TestableChannel ch(true, "127.0.0.1:5055", &loop);
    HChannel hOut = nullptr;
    uint32_t cid = ch.PubMallocChannel(&hOut);
    ASSERT_NE(hOut, nullptr);
    // 分配 ioBuf 并填充全 0 的 size 字段（模拟 libuv 已读入数据）
    hOut->ioBuf = new uint8_t[64]();
    hOut->bufSize = 64;
    hOut->availTailIndex = 0;
    uv_stream_t *stream = reinterpret_cast<uv_stream_t *>(&hOut->hWorkTCP);
    uv_buf_t buf = uv_buf_init(reinterpret_cast<char *>(hOut->ioBuf), 8);
    EXPECT_NO_FATAL_FAILURE(HdcChannelBase::ReadStream(stream, 8, &buf));
    delete[] hOut->ioBuf;
    hOut->ioBuf = nullptr;
    ch.AdminChannel(OP_REMOVE, cid, nullptr);
    delete hOut;
}

// ===== PushAsyncMessage 各 method =====

// PushAsyncMessage：method = 0（未知）→ 不崩溃
HWTEST_F(HdcChannelBaseTest, PushAsyncMessage_MethodZero_NoCrash, TestSize.Level0)
{
    HdcChannelBase ch(true, "127.0.0.1:5055", &loop);
    uint8_t d = 1;
    EXPECT_NO_FATAL_FAILURE(ch.PushAsyncMessage(123, 0, &d, sizeof(d)));
}

// PushAsyncMessage：method = ASYNC_FREE_CHANNEL → 不崩溃
HWTEST_F(HdcChannelBaseTest, PushAsyncMessage_AsyncFreeChannel_NoCrash, TestSize.Level0)
{
    HdcChannelBase ch(true, "127.0.0.1:5055", &loop);
    EXPECT_NO_FATAL_FAILURE(ch.PushAsyncMessage(456, ASYNC_FREE_CHANNEL, nullptr, 0));
}

// PushAsyncMessage：带数据 → 不崩溃
HWTEST_F(HdcChannelBaseTest, PushAsyncMessage_WithData_NoCrash, TestSize.Level0)
{
    HdcChannelBase ch(true, "127.0.0.1:5055", &loop);
    uint8_t data[16] = {0};
    EXPECT_NO_FATAL_FAILURE(ch.PushAsyncMessage(789, 1, data, sizeof(data)));
}

// PushAsyncMessage：dataSize = 0 → 不崩溃
HWTEST_F(HdcChannelBaseTest, PushAsyncMessage_ZeroData_NoCrash, TestSize.Level0)
{
    HdcChannelBase ch(true, "127.0.0.1:5055", &loop);
    EXPECT_NO_FATAL_FAILURE(ch.PushAsyncMessage(111, ASYNC_FREE_CHANNEL, nullptr, 0));
}

// PushAsyncMessage：data 为 nullptr 但 dataSize > 0 → 不崩溃（走 memcpy_s 失败分支）
HWTEST_F(HdcChannelBaseTest, PushAsyncMessage_NullData_NoCrash, TestSize.Level0)
{
    HdcChannelBase ch(true, "127.0.0.1:5055", &loop);
    EXPECT_NO_FATAL_FAILURE(ch.PushAsyncMessage(222, 1, nullptr, 16));
}

// ===== SendWithCmd 各参数 =====
// SendWithCmd：size = 0 → 不崩溃
HWTEST_F(HdcChannelBaseTest, SendWithCmd_ZeroSize_NoCrash, TestSize.Level0)
{
    HdcChannelBase ch(true, "127.0.0.1:5055", &loop);
    uint8_t d = 0;
    EXPECT_NO_FATAL_FAILURE(ch.SendWithCmd(4321, 0, &d, 0));
}

// SendWithCmd：buf 为 nullptr → 不崩溃
HWTEST_F(HdcChannelBaseTest, SendWithCmd_NullBuf_NoCrash, TestSize.Level0)
{
    HdcChannelBase ch(true, "127.0.0.1:5055", &loop);
    EXPECT_NO_FATAL_FAILURE(ch.SendWithCmd(4321, 0, nullptr, 4));
}

// ===== Send 各参数 =====
// Send：未知 channelId → 不崩溃
HWTEST_F(HdcChannelBaseTest, Send_UnknownChannel_NoCrash, TestSize.Level0)
{
    TestableChannel ch(true, "127.0.0.1:5055", &loop);
    uint8_t d = 0;
    EXPECT_NO_FATAL_FAILURE(ch.PubSend(9999, &d, sizeof(d)));
}

// Send：size = 0 → 不崩溃
HWTEST_F(HdcChannelBaseTest, Send_ZeroSize_NoCrash, TestSize.Level0)
{
    TestableChannel ch(true, "127.0.0.1:5055", &loop);
    uint8_t d = 0;
    EXPECT_NO_FATAL_FAILURE(ch.PubSend(9999, &d, 0));
}

// ===== SendChannel 各参数 =====
// SendChannel：size < 0 → 走 invalid size 分支
HWTEST_F(HdcChannelBaseTest, SendChannel_NegativeSize_NoCrash, TestSize.Level0)
{
    TestableChannel ch(true, "127.0.0.1:5055", &loop);
    auto hChannel = new HdcChannel();
    hChannel->ref.store(0);
    uint8_t d = 0;
    EXPECT_NO_FATAL_FAILURE(ch.PubSendChannel(hChannel, &d, -1));
    delete hChannel;
}

// SendChannel：size = 0 → 走 0 长度分支
HWTEST_F(HdcChannelBaseTest, SendChannel_ZeroSize_NoCrash, TestSize.Level0)
{
    TestableChannel ch(true, "127.0.0.1:5055", &loop);
    auto hChannel = new HdcChannel();
    hChannel->ref.store(0);
    uint8_t d = 0;
    EXPECT_NO_FATAL_FAILURE(ch.PubSendChannel(hChannel, &d, 0));
    delete hChannel;
}

// SendChannel：有效 channel 但未连接 → 走 else 分支 delete data
HWTEST_F(HdcChannelBaseTest, SendChannel_ValidChannel_NotConnected_NoCrash, TestSize.Level0)
{
    TestableChannel ch(true, "127.0.0.1:5055", &loop);
    HChannel hOut = nullptr;
    uint32_t cid = ch.PubMallocChannel(&hOut);
    ASSERT_NE(hOut, nullptr);
    uint8_t data[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    EXPECT_NO_FATAL_FAILURE(ch.PubSendChannel(hOut, data, sizeof(data)));
    ch.AdminChannel(OP_REMOVE, cid, nullptr);
    delete hOut;
}

// ===== SendChannelWithCmd 各参数 =====
// SendChannelWithCmd：size < 0 → 走早返回
HWTEST_F(HdcChannelBaseTest, SendChannelWithCmd_NegativeSize_NoCrash, TestSize.Level0)
{
    TestableChannel ch(true, "127.0.0.1:5055", &loop);
    auto hChannel = new HdcChannel();
    hChannel->ref.store(0);
    uint8_t d = 0;
    EXPECT_NO_FATAL_FAILURE(ch.PubSendChannelWithCmd(hChannel, 0, &d, -1));
    delete hChannel;
}

// SendChannelWithCmd：size = 0 → 只写 commandFlag
HWTEST_F(HdcChannelBaseTest, SendChannelWithCmd_ZeroSize_NoCrash, TestSize.Level0)
{
    TestableChannel ch(true, "127.0.0.1:5055", &loop);
    auto hChannel = new HdcChannel();
    hChannel->ref.store(0);
    uint8_t d = 0;
    EXPECT_NO_FATAL_FAILURE(ch.PubSendChannelWithCmd(hChannel, CMD_KERNEL_ECHO, &d, 0));
    delete hChannel;
}

// ===== EchoToClient 各参数 =====
// EchoToClient：size = 0 → 不崩溃
HWTEST_F(HdcChannelBaseTest, EchoToClient_ZeroSize_NoCrash, TestSize.Level0)
{
    TestableChannel ch(true, "127.0.0.1:5055", &loop);
    auto hChannel = new HdcChannel();
    hChannel->ref.store(0);
    uint8_t d = 0;
    EXPECT_NO_FATAL_FAILURE(ch.PubEchoToClient(hChannel, &d, 0));
    delete hChannel;
}

// EchoToClient：有效 channel 但 hChildWorkTCP 未初始化 → 走 else 分支
HWTEST_F(HdcChannelBaseTest, EchoToClient_ValidChannel_NoCrash, TestSize.Level0)
{
    TestableChannel ch(true, "127.0.0.1:5055", &loop);
    HChannel hOut = nullptr;
    uint32_t cid = ch.PubMallocChannel(&hOut);
    ASSERT_NE(hOut, nullptr);
    uint8_t data[4] = {'t', 'e', 's', 't'};
    EXPECT_NO_FATAL_FAILURE(ch.PubEchoToClient(hOut, data, sizeof(data)));
    ch.AdminChannel(OP_REMOVE, cid, nullptr);
    delete hOut;
}

// ===== EchoToAllChannelsViaSessionId =====

// EchoToAll：有 channel 但 targetSessionId 不匹配 → 不崩溃
HWTEST_F(HdcChannelBaseTest, EchoToAll_NoMatchingSid_NoCrash, TestSize.Level0)
{
    HdcChannelBase ch(true, "127.0.0.1:5055", &loop);
    auto hChannel = new HdcChannel();
    hChannel->channelId = 55;
    hChannel->isDead = false;
    hChannel->targetSessionId = 100;
    hChannel->ref.store(0);
    ch.AdminChannel(OP_ADD, 55, hChannel);
    EXPECT_NO_FATAL_FAILURE(ch.EchoToAllChannelsViaSessionId(999, "hello"));
    ch.AdminChannel(OP_REMOVE, 55, nullptr);
    delete hChannel;
}

// ===== GetChannelHandshake =====
// GetChannelHandshake：带 key → 返回非空，key 被填充
HWTEST_F(HdcChannelBaseTest, GetChannelHandshake_WithKey_ReturnsValid, TestSize.Level0)
{
    HdcChannelBase ch(true, "127.0.0.1:5055", &loop);
    string key = "127.0.0.1:5055";
    auto v = ch.GetChannelHandshake(key);
    EXPECT_FALSE(v.empty());
    // banner 为 HANDSHAKE_MESSAGE，长度不超过 12
    size_t bannerLen = HANDSHAKE_MESSAGE.size();
    ASSERT_GE(v.size(), bannerLen);
    EXPECT_EQ(string(reinterpret_cast<const char *>(v.data()), bannerLen), HANDSHAKE_MESSAGE);
}

// GetChannelHandshake：key 过长 → strcpy_s 失败 → 返回空
HWTEST_F(HdcChannelBaseTest, GetChannelHandshake_OverlongKey_ReturnsEmpty, TestSize.Level0)
{
    HdcChannelBase ch(true, "127.0.0.1:5055", &loop);
    string key(MAX_CONNECTKEY_SIZE + 10, 'x');
    auto v = ch.GetChannelHandshake(key);
    EXPECT_TRUE(v.empty());
}

// ===== FreeChannel =====
// FreeChannel：已有 channel → 调用 FreeChannel 标记 isDead
HWTEST_F(HdcChannelBaseTest, FreeChannel_ExistingChannel_NoCrash, TestSize.Level0)
{
    TestableChannel ch(true, "127.0.0.1:5055", &loop);
    HChannel hOut = nullptr;
    uint32_t cid = ch.PubMallocChannel(&hOut);
    ASSERT_NE(hOut, nullptr);
    EXPECT_NO_FATAL_FAILURE(ch.FreeChannel(cid));
    // channel is now marked dead, remove from map to prevent double-free in destructor
    ch.AdminChannel(OP_REMOVE, cid, nullptr);
    delete hOut;
}

// ===== MallocChannel =====
// MallocChannel：成功 → 返回 >0，hOutChannel 被填充
HWTEST_F(HdcChannelBaseTest, MallocChannel_Success_ReturnsChannelId, TestSize.Level0)
{
    TestableChannel ch(true, "127.0.0.1:5055", &loop);
    HChannel hOut = nullptr;
    uint32_t cid = ch.PubMallocChannel(&hOut);
    EXPECT_GT(cid, 0u);
    EXPECT_NE(hOut, nullptr);
    EXPECT_EQ(hOut->channelId, cid);
    ch.AdminChannel(OP_REMOVE, cid, nullptr);
    delete hOut;
}

// MallocChannel：client 模式（isServerOrClient=false）→ channelId 不递增
HWTEST_F(HdcChannelBaseTest, MallocChannel_ClientMode_ReturnsChannelId, TestSize.Level0)
{
    TestableChannel ch(false, "127.0.0.1:5055", &loop);
    HChannel hOut = nullptr;
    uint32_t cid = ch.PubMallocChannel(&hOut);
    EXPECT_GT(cid, 0u);
    EXPECT_NE(hOut, nullptr);
    ch.AdminChannel(OP_REMOVE, cid, nullptr);
    delete hOut;
}

// ===== Constructor 各参数 =====
// 构造：IPv6 地址 → 不崩溃
HWTEST_F(HdcChannelBaseTest, Constructor_IPv6Addr_NoCrash, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(HdcChannelBase ch(true, "::1:5055", &loop));
}

// 构造：非法端口（非数字）→ SetChannelTCPString 失败 → 不崩溃
HWTEST_F(HdcChannelBaseTest, Constructor_InvalidPort_NoCrash, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(HdcChannelBase ch(true, "127.0.0.1:abc", &loop));
}

// 构造：端口为 0 → SetChannelTCPString 失败 → 不崩溃
HWTEST_F(HdcChannelBaseTest, Constructor_ZeroPort_NoCrash, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(HdcChannelBase ch(true, "127.0.0.1:0", &loop));
}
}  // namespace Hdc
