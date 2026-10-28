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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "daemon_tcp.h"

using namespace testing::ext;
using namespace testing;

namespace Hdc {
class HdcDaemonTCPTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HdcDaemonTCPTest::SetUpTestCase() {}
void HdcDaemonTCPTest::TearDownTestCase() {}
void HdcDaemonTCPTest::SetUp() {}
void HdcDaemonTCPTest::TearDown() {}

// 构造：server/daemon 两模式不崩溃
HWTEST_F(HdcDaemonTCPTest, Constructor_BothModes, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(HdcDaemonTCP t(true, nullptr));
    ASSERT_NO_FATAL_FAILURE(HdcDaemonTCP t(false, nullptr));
}

// BuildUDPReplyPayload：构建应答载荷，不崩溃
HWTEST_F(HdcDaemonTCPTest, BuildUDPReplyPayload_NoCrash, TestSize.Level0)
{
    HdcDaemonTCP t(true, nullptr);
    EXPECT_NO_FATAL_FAILURE(t.BuildUDPReplyPayload());
}

// 构造：daemon 模式（serverOrDaemon=false），persist.hdc.port 为空 → tcpListenPort=0
HWTEST_F(HdcDaemonTCPTest, Constructor_DaemonMode_DefaultPort, TestSize.Level0)
{
    HdcDaemonTCP t(false, nullptr);
    EXPECT_EQ(t.tcpListenPort, 0u);
}

// TransmitConfig：addrSrc=nullptr → 早返回，不崩溃
HWTEST_F(HdcDaemonTCPTest, TransmitConfig_NullAddr_NoCrash, TestSize.Level0)
{
    HdcDaemonTCP t(true, nullptr);
    EXPECT_NO_FATAL_FAILURE(t.TransmitConfig(nullptr, nullptr));
}

// TransmitConfig：addrSrc 非空但 handle=nullptr → 早返回
HWTEST_F(HdcDaemonTCPTest, TransmitConfig_NullHandle_NoCrash, TestSize.Level0)
{
    HdcDaemonTCP t(true, nullptr);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    EXPECT_NO_FATAL_FAILURE(t.TransmitConfig(reinterpret_cast<sockaddr *>(&addr), nullptr));
}

// TransmitConfig：sa_family=AF_INET6 → 不支持，早返回
HWTEST_F(HdcDaemonTCPTest, TransmitConfig_NonInetFamily_NoCrash, TestSize.Level0)
{
    HdcDaemonTCP t(true, nullptr);
    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    uv_udp_t handle{};
    EXPECT_NO_FATAL_FAILURE(t.TransmitConfig(reinterpret_cast<sockaddr *>(&addr), &handle));
}

// RecvUDPEntry：packetLen != HANDSHAKE_MESSAGE.size() → 早返回（不调用 TransmitConfig）
HWTEST_F(HdcDaemonTCPTest, RecvUDPEntry_WrongPacketLen_NoOp, TestSize.Level0)
{
    HdcDaemonTCP t(true, nullptr);
    EXPECT_NO_FATAL_FAILURE(t.RecvUDPEntry(nullptr, nullptr, nullptr, 0));
}
}  // namespace Hdc
