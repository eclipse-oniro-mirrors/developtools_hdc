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

#include <uv.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "tcp.h"

using namespace testing::ext;
using namespace testing;

namespace Hdc {
class HdcTCPBaseTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HdcTCPBaseTest::SetUpTestCase() {}
void HdcTCPBaseTest::TearDownTestCase() {}
void HdcTCPBaseTest::SetUp() {}
void HdcTCPBaseTest::TearDown() {}

// 构造：server/daemon 两种模式均不崩溃
HWTEST_F(HdcTCPBaseTest, Constructor_ServerAndDaemon, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(HdcTCPBase t(true, nullptr));
    ASSERT_NO_FATAL_FAILURE(HdcTCPBase t(false, nullptr));
}

#ifdef HDC_SUPPORT_ENCRYPT_TCP
// WriteUvSslFd：未初始化 tcp → 返回 false（覆盖 SSL 写失败分支）
HWTEST_F(HdcTCPBaseTest, WriteUvSslFd_UninitTcp_ReturnsError, TestSize.Level0)
{
    HdcTCPBase t(true, nullptr);
    uv_tcp_t tcp{};
    uint8_t buf[8] = {0};
    int cnt = 0;
    bool r = t.WriteUvSslFd(&tcp, buf, sizeof(buf), cnt);
    EXPECT_FALSE(r);
}
#endif

// ===== TestableTCP：暴露 protected 静态方法 =====
class TestableTCP : public HdcTCPBase {
public:
    using HdcTCPBase::HdcTCPBase;
    static void PubRecvUDP(uv_udp_t *handle, ssize_t nread, const uv_buf_t *rcvbuf,
                           const struct sockaddr *addr, unsigned flags)
    {
        RecvUDP(handle, nread, rcvbuf, addr, flags);
    }
    static void PubAllocStreamUDP(uv_handle_t *handle, size_t sizeWanted, uv_buf_t *buf)
    {
        AllocStreamUDP(handle, sizeWanted, buf);
    }
    static void PubSendUDPFinish(uv_udp_send_t *req, int status) { SendUDPFinish(req, status); }
    void PubInitialChildClass(bool serverOrDaemonIn, void *ptrMainBase)
    {
        InitialChildClass(serverOrDaemonIn, ptrMainBase);
    }
    bool PubIsServerOrDaemon() const { return serverOrDaemon; }
    void *PubClsMainBase() const { return clsMainBase; }
};

// WriteUvSslFd：tcp 为 nullptr → 返回 false（覆盖 null tcp 校验）
HWTEST_F(HdcTCPBaseTest, WriteUvSslFd_NullTcp_ReturnsFalse, TestSize.Level0)
{
    HdcTCPBase t(true, nullptr);
    uint8_t buf[8] = {0};
    int cnt = 0;
    EXPECT_FALSE(t.WriteUvSslFd(nullptr, buf, sizeof(buf), cnt));
}

// WriteUvSslFd：buf 为 nullptr → 返回 false（覆盖 null buf 校验）
HWTEST_F(HdcTCPBaseTest, WriteUvSslFd_NullBuf_ReturnsFalse, TestSize.Level0)
{
    HdcTCPBase t(true, nullptr);
    uv_tcp_t tcp{};
    int cnt = 0;
    EXPECT_FALSE(t.WriteUvSslFd(&tcp, nullptr, 8, cnt));
}

// WriteUvSslFd：size < 0 → 返回 false（覆盖负 size 校验）
HWTEST_F(HdcTCPBaseTest, WriteUvSslFd_NegativeSize_ReturnsFalse, TestSize.Level0)
{
    HdcTCPBase t(true, nullptr);
    uv_tcp_t tcp{};
    uint8_t buf[8] = {0};
    int cnt = 0;
    EXPECT_FALSE(t.WriteUvSslFd(&tcp, buf, -1, cnt));
}

// WriteUvSslFd：cnt < 0 → 返回 false（覆盖负 cnt 校验）
HWTEST_F(HdcTCPBaseTest, WriteUvSslFd_NegativeCnt_ReturnsFalse, TestSize.Level0)
{
    HdcTCPBase t(true, nullptr);
    uv_tcp_t tcp{};
    uint8_t buf[8] = {0};
    int cnt = -1;
    EXPECT_FALSE(t.WriteUvSslFd(&tcp, buf, sizeof(buf), cnt));
}

// RecvUDP：handle 为 nullptr → 走 null handle 早返回分支
HWTEST_F(HdcTCPBaseTest, RecvUDP_NullHandle_NoCrash, TestSize.Level0)
{
    EXPECT_NO_FATAL_FAILURE(
        TestableTCP::PubRecvUDP(nullptr, 0, nullptr, nullptr, 0));
}

// RecvUDP：handle->data 为 nullptr → 走 null data 早返回分支
HWTEST_F(HdcTCPBaseTest, RecvUDP_NullHandleData_NoCrash, TestSize.Level0)
{
    uv_udp_t udp{};
    udp.data = nullptr;
    EXPECT_NO_FATAL_FAILURE(
        TestableTCP::PubRecvUDP(&udp, 0, nullptr, nullptr, 0));
}

// AllocStreamUDP：返回有效 buf（static thread_local 缓冲）
HWTEST_F(HdcTCPBaseTest, AllocStreamUDP_ReturnsValidBuf, TestSize.Level0)
{
    uv_handle_t handle;
    uv_buf_t buf;
    EXPECT_NO_FATAL_FAILURE(TestableTCP::PubAllocStreamUDP(&handle, 1024, &buf));
    EXPECT_NE(buf.base, nullptr);
    EXPECT_GT(buf.len, 0u);
}

// SendUDPFinish：传入动态分配的 req → delete 不崩溃
HWTEST_F(HdcTCPBaseTest, SendUDPFinish_DeletesReq_NoCrash, TestSize.Level0)
{
    auto req = new uv_udp_send_t;
    EXPECT_NO_FATAL_FAILURE(TestableTCP::PubSendUDPFinish(req, 0));
}

// InitialChildClass：设置 serverOrDaemon 和 clsMainBase
HWTEST_F(HdcTCPBaseTest, InitialChildClass_SetsFields, TestSize.Level0)
{
    TestableTCP t(true, nullptr);
    int sentinel = 42;
    EXPECT_NO_FATAL_FAILURE(t.PubInitialChildClass(false, &sentinel));
    EXPECT_FALSE(t.PubIsServerOrDaemon());
    EXPECT_EQ(t.PubClsMainBase(), &sentinel);
}

// WriteUvTcpFd：nullptr tcp → 走 WriteUvSslFd false → delete buf 返回错误，不崩溃
HWTEST_F(HdcTCPBaseTest, WriteUvTcpFd_NullTcp_NoCrash, TestSize.Level0)
{
    HdcTCPBase t(true, nullptr);
    auto data = new uint8_t[8];
    for (int i = 0; i < 8; ++i) { data[i] = 0; }
    EXPECT_NO_FATAL_FAILURE(t.WriteUvTcpFd(nullptr, data, 8));
}

}  // namespace Hdc
