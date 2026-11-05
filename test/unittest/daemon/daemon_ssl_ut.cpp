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

#ifdef HDC_SUPPORT_ENCRYPT_TCP
#include "daemon_ssl.h"
#endif

using namespace testing::ext;
using namespace testing;

namespace Hdc {
// daemon_ssl.cpp 整体由 HDC_SUPPORT_ENCRYPT_TCP 宏守护；宏未开启时源文件为空、无符号，
// 测试用例同样以该宏守护，避免未定义引用。
#ifdef HDC_SUPPORT_ENCRYPT_TCP
class HdcDaemonSSLTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HdcDaemonSSLTest::SetUpTestCase() {}
void HdcDaemonSSLTest::TearDownTestCase() {}
void HdcDaemonSSLTest::SetUp() {}
void HdcDaemonSSLTest::TearDown() {}

// SetSSLMethod：返回 TLS_server_method()，非空（该方法不访问成员，构造即可调用）
HWTEST_F(HdcDaemonSSLTest, SetSSLMethod_ReturnsServerMethod, TestSize.Level0)
{
    HdcSSLInfo info{};
    HdcDaemonSSL ssl(&info);
    EXPECT_NE(ssl.SetSSLMethod(), nullptr);
}

// SetSSLState / SetPskCallback：需 InitSSL 成功后 sslCtx/ssl 才有效；InitSSL 失败时跳过
HWTEST_F(HdcDaemonSSLTest, SetSSLState_And_PskCallback_AfterInit, TestSize.Level0)
{
    HdcSSLInfo info{};
    HdcDaemonSSL ssl(&info);
    if (ssl.InitSSL() != 0) {
        GTEST_SKIP() << "InitSSL unavailable in ut env, skip SetSSLState/SetPskCallback";
    }
    EXPECT_NO_FATAL_FAILURE(ssl.SetSSLState());
    EXPECT_TRUE(ssl.SetPskCallback());
}
#endif  // HDC_SUPPORT_ENCRYPT_TCP
}  // namespace Hdc
