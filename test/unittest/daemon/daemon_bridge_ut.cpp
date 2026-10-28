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

#include <uv.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "daemon_bridge.h"

using namespace testing::ext;
using namespace testing;

namespace Hdc {
class HdcDaemonBridgeTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HdcDaemonBridgeTest::SetUpTestCase() {}
void HdcDaemonBridgeTest::TearDownTestCase() {}
void HdcDaemonBridgeTest::SetUp() {}
void HdcDaemonBridgeTest::TearDown() {}

// 构造：读取 persist.hdc.port（host 侧 GetDevItem 返回空→port=0），不崩溃
HWTEST_F(HdcDaemonBridgeTest, Constructor_NoCrash, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(HdcDaemonBridge b(true, nullptr));
}

// Stop：未初始化 servPipe，TryCloseHandle 安全，不崩溃
HWTEST_F(HdcDaemonBridgeTest, Stop_Uninitialized_NoCrash, TestSize.Level0)
{
    HdcDaemonBridge b(true, nullptr);
    EXPECT_NO_FATAL_FAILURE(b.Stop());
}

// AllocBufferCallback：分配 SOCKET_FD_LEN 长度缓冲，base 非 null
HWTEST_F(HdcDaemonBridgeTest, AllocBufferCallback_Allocates, TestSize.Level0)
{
    uv_buf_t buf{};
    HdcDaemonBridge::AllocBufferCallback(nullptr, 0, &buf);
    ASSERT_NE(buf.base, nullptr);
    delete[] buf.base;
}

// Initial：host 侧无 /dev/express_bridge → SetBridgeListen 失败 → 返回 ERR_GENERIC
HWTEST_F(HdcDaemonBridgeTest, Initial_NoBridgeDevice_ReturnsError, TestSize.Level0)
{
    HdcDaemonBridge b(true, nullptr);
    EXPECT_NE(b.Initial(), 0);
}

// SetBridgeListen：无 /dev/express_bridge → open 失败 → 返回 ERR_FILE_OPEN（覆盖失败早返回）
HWTEST_F(HdcDaemonBridgeTest, SetBridgeListen_NoDevice_ReturnsError, TestSize.Level0)
{
    HdcDaemonBridge b(true, nullptr);
    EXPECT_NE(b.SetBridgeListen(), 0);
}
}  // namespace Hdc
