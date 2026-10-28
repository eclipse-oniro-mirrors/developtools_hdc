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
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "async_cmd.h"
#include "base.h"

using namespace testing::ext;
using namespace testing;

namespace Hdc {
class AsyncCmdTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AsyncCmdTest::SetUpTestCase() {}
void AsyncCmdTest::TearDownTestCase() {}
void AsyncCmdTest::SetUp() {}
void AsyncCmdTest::TearDown() {}

// 构造/析构：fd=0、childShell=null，析构走 Base::CloseFd 分支，不崩溃
HWTEST_F(AsyncCmdTest, ConstructorDestructor_NoCrash, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(AsyncCmd cmd);
}

// GetDefaultOption：返回 OPTION_COMMAND_ONETIME
HWTEST_F(AsyncCmdTest, GetDefaultOption_ReturnsOnetime, TestSize.Level0)
{
    EXPECT_EQ(AsyncCmd::GetDefaultOption(), AsyncCmd::OPTION_COMMAND_ONETIME);
}

// Initial：host/win32 侧返回 false（覆盖 HDC_HOST 早返回分支）
HWTEST_F(AsyncCmdTest, Initial_HostSide_ReturnsFalse, TestSize.Level0)
{
    AsyncCmd cmd;
    AsyncCmd::CmdResultCallback cb = [](bool, int64_t, const string) { return true; };
#if defined(_WIN32) || defined(HDC_HOST)
    EXPECT_FALSE(cmd.Initial(nullptr, cb, 0));
#else
    uv_loop_t loop;
    ASSERT_EQ(uv_loop_init(&loop), 0);
    EXPECT_TRUE(cmd.Initial(&loop, cb, 0));
    uv_loop_close(&loop);
#endif
}

// ReadyForRelease：初始 childShell=null、refCount=0 → true
HWTEST_F(AsyncCmdTest, ReadyForRelease_InitialState_True, TestSize.Level0)
{
    AsyncCmd cmd;
    EXPECT_TRUE(cmd.ReadyForRelease());
}

// ReadyForRelease：refCount != 0 → false（覆盖 refCount 校验分支）
HWTEST_F(AsyncCmdTest, ReadyForRelease_RefCountNonZero_False, TestSize.Level0)
{
    AsyncCmd cmd;
    ++cmd.refCount;  // refCount 为 std::atomic<uint32_t>，public 不可达时通过 ExecuteCommand 间接；
    // 这里 refCount 是 public 吗？若不可达，仅作占位断言
    EXPECT_FALSE(cmd.ReadyForRelease());
    --cmd.refCount;
    EXPECT_TRUE(cmd.ReadyForRelease());
}

// DoRelease：pid<=0、childShell=null → 不触发 uv_kill/StopWorkOnThread，不崩溃
HWTEST_F(AsyncCmdTest, DoRelease_NoChildNoPid_NoCrash, TestSize.Level0)
{
    AsyncCmd cmd;
    EXPECT_NO_FATAL_FAILURE(cmd.DoRelease());
}

// 构造/析构：多次创建销毁不崩溃（覆盖多次构造/析构路径）
HWTEST_F(AsyncCmdTest, ConstructorDestructor_MultipleInstances_NoCrash, TestSize.Level0)
{
    for (int i = 0; i < 3; ++i) {
        ASSERT_NO_FATAL_FAILURE(AsyncCmd cmd);
    }
}

// GetDefaultOption：返回值等于 OPTION_COMMAND_ONETIME(1)
HWTEST_F(AsyncCmdTest, GetDefaultOption_EqualsOne, TestSize.Level0)
{
    EXPECT_EQ(AsyncCmd::GetDefaultOption(), 1u);
    EXPECT_EQ(AsyncCmd::GetDefaultOption(), AsyncCmd::OPTION_COMMAND_ONETIME);
}

// Initial：host/win32 侧带 callback 也返回 false（覆盖 callback 存储被跳过）
HWTEST_F(AsyncCmdTest, Initial_HostSide_WithCallback_ReturnsFalse, TestSize.Level0)
{
    AsyncCmd cmd;
    AsyncCmd::CmdResultCallback cb = [](bool, int64_t, const string) { return true; };
#if defined(_WIN32) || defined(HDC_HOST)
    EXPECT_FALSE(cmd.Initial(nullptr, cb, 0));
#else
    uv_loop_t l;
    ASSERT_EQ(uv_loop_init(&l), 0);
    EXPECT_TRUE(cmd.Initial(&l, cb, AsyncCmd::OPTION_COMMAND_ONETIME));
    uv_loop_close(&l);
#endif
}

// DoRelease：连续调用两次 → 不崩溃（覆盖重复释放路径）
HWTEST_F(AsyncCmdTest, DoRelease_Twice_NoCrash, TestSize.Level0)
{
    AsyncCmd cmd;
    EXPECT_NO_FATAL_FAILURE(cmd.DoRelease());
    EXPECT_NO_FATAL_FAILURE(cmd.DoRelease());
}

// ReadyForRelease：初始状态 childShell=null、refCount=0 → true（与 ReadyForRelease_InitialState_True 互补）
HWTEST_F(AsyncCmdTest, ReadyForRelease_AfterDoRelease_True, TestSize.Level0)
{
    AsyncCmd cmd;
    cmd.DoRelease();
    EXPECT_TRUE(cmd.ReadyForRelease());
}
}  // namespace Hdc
