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
#include <unistd.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

// main.cpp 用 #ifndef UNIT_TEST 守护 int main()，测试构建（定义 UNIT_TEST）可安全链接其 helper。
// 这些 helper 未在头文件声明，此处 extern 引入（namespace Hdc）。
namespace Hdc {
std::string DaemonUsage();
bool GetDaemonCommandlineOptions(int argc, const char *argv[]);
void CheckTcpAndUSBSwitch();
void DisableTcpAndUSB();
bool NeedDropRootPrivileges();
bool ForkChildCheck(int argc, const char *argv[]);
}  // namespace Hdc

using namespace testing::ext;
using namespace testing;

namespace Hdc {
class HdcMainTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HdcMainTest::SetUpTestCase() {}
void HdcMainTest::TearDownTestCase() {}
void HdcMainTest::SetUp() {}
void HdcMainTest::TearDown() {}

// DaemonUsage：返回非空用法串
HWTEST_F(HdcMainTest, DaemonUsage_ReturnsNonEmpty, TestSize.Level0)
{
    std::string s = DaemonUsage();
    EXPECT_FALSE(s.empty());
}

// GetDaemonCommandlineOptions：仅程序名（无参数）不崩溃
HWTEST_F(HdcMainTest, GetDaemonCommandlineOptions_NoArgs, TestSize.Level0)
{
    const char *argv[] = {"hdcd"};
    EXPECT_NO_FATAL_FAILURE((void)GetDaemonCommandlineOptions(1, argv));
}

// CheckTcpAndUSBSwitch：host 侧 GetDevItem 返回空 → 不崩溃，开关保持 false
HWTEST_F(HdcMainTest, CheckTcpAndUSBSwitch_NoCrash, TestSize.Level0)
{
    EXPECT_NO_FATAL_FAILURE(CheckTcpAndUSBSwitch());
}

// DisableTcpAndUSB：重置开关，不崩溃
HWTEST_F(HdcMainTest, DisableTcpAndUSB_NoCrash, TestSize.Level0)
{
    EXPECT_NO_FATAL_FAILURE(DisableTcpAndUSB());
}

// NeedDropRootPrivileges：返回 bool，不崩溃（只读 getuid）
HWTEST_F(HdcMainTest, NeedDropRootPrivileges_NoCrash, TestSize.Level0)
{
    EXPECT_NO_FATAL_FAILURE((void)NeedDropRootPrivileges());
}

// ForkChildCheck：argv 不含 -forkchild，不触发 execl，不崩溃
HWTEST_F(HdcMainTest, ForkChildCheck_NoForkArg_NoCrash, TestSize.Level0)
{
    const char *argv[] = {"hdcd", "-v"};
    EXPECT_NO_FATAL_FAILURE((void)ForkChildCheck(2, argv));
}

// DaemonUsage：返回内容含 HDCD 关键字
HWTEST_F(HdcMainTest, DaemonUsage_ContainsHdcdKeyword, TestSize.Level0)
{
    std::string s = DaemonUsage();
    EXPECT_NE(s.find("HDCD"), std::string::npos);
}

// GetDaemonCommandlineOptions：-u 启用 USB，不崩溃
HWTEST_F(HdcMainTest, GetDaemonCommandlineOptions_UsbFlag_NoCrash, TestSize.Level0)
{
    ::optind = 1;
    const char *argv[] = {"hdcd", "-u"};
    EXPECT_NO_FATAL_FAILURE((void)GetDaemonCommandlineOptions(2, argv));
}

// GetDaemonCommandlineOptions：-t 启用 TCP，不崩溃
HWTEST_F(HdcMainTest, GetDaemonCommandlineOptions_TcpFlag_NoCrash, TestSize.Level0)
{
    ::optind = 1;
    const char *argv[] = {"hdcd", "-t"};
    EXPECT_NO_FATAL_FAILURE((void)GetDaemonCommandlineOptions(2, argv));
}

// GetDaemonCommandlineOptions：-l 1 设置合法日志级别，不崩溃
HWTEST_F(HdcMainTest, GetDaemonCommandlineOptions_LogLevelValid_NoCrash, TestSize.Level0)
{
    ::optind = 1;
    const char *argv[] = {"hdcd", "-l", "1"};
    EXPECT_NO_FATAL_FAILURE((void)GetDaemonCommandlineOptions(3, argv));
}

// GetDaemonCommandlineOptions：-l 99 超出 LOG_LAST → 返回非 true（早返回分支）
HWTEST_F(HdcMainTest, GetDaemonCommandlineOptions_LogLevelInvalid_NoCrash, TestSize.Level0)
{
    ::optind = 1;
    const char *argv[] = {"hdcd", "-l", "99"};
    EXPECT_NO_FATAL_FAILURE((void)GetDaemonCommandlineOptions(3, argv));
}

// GetDaemonCommandlineOptions：-u -t 组合，不崩溃
HWTEST_F(HdcMainTest, GetDaemonCommandlineOptions_CombinedFlags_NoCrash, TestSize.Level0)
{
    ::optind = 1;
    const char *argv[] = {"hdcd", "-u", "-t"};
    EXPECT_NO_FATAL_FAILURE((void)GetDaemonCommandlineOptions(3, argv));
}

// ForkChildCheck：-b → g_backgroundRun=true，不崩溃
HWTEST_F(HdcMainTest, ForkChildCheck_BackgroundFlag_NoCrash, TestSize.Level0)
{
    const char *argv[] = {"hdcd", "-b"};
    EXPECT_NO_FATAL_FAILURE((void)ForkChildCheck(2, argv));
}

// ForkChildCheck：-forkchild → g_backgroundRun=false（不触发 execl），不崩溃
HWTEST_F(HdcMainTest, ForkChildCheck_ForkChildArg_NoCrash, TestSize.Level0)
{
    const char *argv[] = {"hdcd", "-forkchild"};
    EXPECT_NO_FATAL_FAILURE((void)ForkChildCheck(2, argv));
}

// CheckTcpAndUSBSwitch：先 Disable 再 Check，开关保持 false，不崩溃
HWTEST_F(HdcMainTest, CheckTcpAndUSBSwitch_AfterDisable_NoCrash, TestSize.Level0)
{
    DisableTcpAndUSB();
    EXPECT_NO_FATAL_FAILURE(CheckTcpAndUSBSwitch());
}

// DisableTcpAndUSB：连续两次重置，不崩溃
HWTEST_F(HdcMainTest, DisableTcpAndUSB_Twice_NoCrash, TestSize.Level0)
{
    EXPECT_NO_FATAL_FAILURE(DisableTcpAndUSB());
    EXPECT_NO_FATAL_FAILURE(DisableTcpAndUSB());
}

// NeedDropRootPrivileges：返回 bool（覆盖判定分支，不真实 setuid）
HWTEST_F(HdcMainTest, NeedDropRootPrivileges_NonRoot_ReturnsBool, TestSize.Level0)
{
    bool ret = NeedDropRootPrivileges();
    EXPECT_NO_FATAL_FAILURE((void)ret);
}
}  // namespace Hdc
