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

#include "system_depend.h"
#include "base.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <string>

using namespace testing::ext;

namespace Hdc {
namespace {
constexpr const char *NONEXISTENT_KEY = "hdc.unit.test.nonexistent.key";
constexpr const char *HARMLESS_SET_KEY = "hdc.unit.test.smoke.key";
constexpr size_t MAX_REBOOT_ARG_LEN = 12;
}

class SystemDependTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void SystemDependTest::SetUpTestCase()
{
#ifdef UT_DEBUG
    Base::SetLogLevel(LOG_ALL);
#else
    Base::SetLogLevel(LOG_OFF);
#endif
}

void SystemDependTest::TearDownTestCase() {}

void SystemDependTest::SetUp() {}

void SystemDependTest::TearDown() {}

HWTEST_F(SystemDependTest, SetDevItem_Normal_001, TestSize.Level0)
{
    EXPECT_NO_FATAL_FAILURE(SystemDepend::SetDevItem(HARMLESS_SET_KEY, "1"));
}

HWTEST_F(SystemDependTest, GetDevItem_WithDefault_001, TestSize.Level0)
{
    string out = "original";
    bool ret = SystemDepend::GetDevItem(NONEXISTENT_KEY, out, "fallbackValue");
    EXPECT_TRUE(ret);
    EXPECT_EQ(out, "fallbackValue");
}

HWTEST_F(SystemDependTest, GetDevItem_WithoutDefault_002, TestSize.Level0)
{
    string out = "original";
    bool ret = SystemDepend::GetDevItem(NONEXISTENT_KEY, out, nullptr);
    EXPECT_FALSE(ret);
    EXPECT_EQ(out, "original");
}

HWTEST_F(SystemDependTest, GetDevUint_Default_001, TestSize.Level0)
{
    uint32_t ret = SystemDepend::GetDevUint(NONEXISTENT_KEY, 42);
    EXPECT_EQ(ret, 42);
}

HWTEST_F(SystemDependTest, RebootDevice_CmdTooLong_003, TestSize.Level0)
{
    const string tooLongCmd = "thisiswaytoolongcmd";
    ASSERT_GT(tooLongCmd.size(), MAX_REBOOT_ARG_LEN);
    bool ret = SystemDepend::RebootDevice(tooLongCmd);
    EXPECT_FALSE(ret);
}

HWTEST_F(SystemDependTest, RebootDevice_UnauthorizedCmd_002, TestSize.Level0)
{
    bool ret = SystemDepend::RebootDevice("evilcmd");
    EXPECT_FALSE(ret);
}

} // namespace Hdc
