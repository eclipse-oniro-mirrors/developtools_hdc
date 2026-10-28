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

#include "system_depend.h"

using namespace testing::ext;
using namespace testing;

namespace Hdc {
class SystemDependUTTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void SystemDependUTTest::SetUpTestCase() {}
void SystemDependUTTest::TearDownTestCase() {}
void SystemDependUTTest::SetUp() {}
void SystemDependUTTest::TearDown() {}

// 安全说明：RebootDevice/CallDoReboot 在设备上会真实触发重启，禁止用合法 cmd 调用。
// 仅测试校验失败分支（长度超限 / 非法目标），它们在调用 CallDoReboot 之前即返回 false。

// cmd 长度超过上限(12)：走长度校验失败分支，确定返回 false，不触发重启
HWTEST_F(SystemDependUTTest, RebootDevice_CmdTooLong_ReturnsFalse, TestSize.Level0)
{
    EXPECT_FALSE(SystemDepend::RebootDevice("abcdefghijklm"));  // 13 chars > 12
}

// cmd 为非法重启目标：走白名单校验失败分支，确定返回 false，不触发重启
HWTEST_F(SystemDependUTTest, RebootDevice_UnauthorizedTarget_ReturnsFalse, TestSize.Level0)
{
    EXPECT_FALSE(SystemDepend::RebootDevice("foobar"));
}

// 多个非法目标：覆盖白名单 != 比较的各分支
HWTEST_F(SystemDependUTTest, RebootDevice_OtherUnauthorizedTargets, TestSize.Level0)
{
    EXPECT_FALSE(SystemDepend::RebootDevice("xyz"));
    EXPECT_FALSE(SystemDepend::RebootDevice("recovery2"));
    EXPECT_FALSE(SystemDepend::RebootDevice("BOOTLOADER"));  // 大小写敏感
}

// 边界：恰好 12 字符的非法 cmd（长度等于上限，走白名单分支而非长度分支）
HWTEST_F(SystemDependUTTest, RebootDevice_MaxLenUnauthorized, TestSize.Level0)
{
    EXPECT_FALSE(SystemDepend::RebootDevice("123456789012"));  // 12 chars，非法值
}

#if defined(HARMONY_PROJECT)
// 参数读写往返：覆盖 SetDevItem / GetDevItem 正常与回退分支（设备侧）
HWTEST_F(SystemDependUTTest, DevItem_SetGetRoundtrip, TestSize.Level0)
{
    const char *key = "persist.hdc.test.str";
    const char *val = "hdc_ut_value";
    EXPECT_TRUE(SystemDepend::SetDevItem(key, val));
    std::string out;
    EXPECT_TRUE(SystemDepend::GetDevItem(key, out, nullptr));
    EXPECT_EQ(out, val);
}

// GetDevItem 缺省值回退：key 不存在时返回 preDefine
HWTEST_F(SystemDependUTTest, DevItem_GetWithPreDefine, TestSize.Level0)
{
    std::string out;
    const char *preDefine = "fallback";
    EXPECT_TRUE(SystemDepend::GetDevItem("persist.hdc.test.notexist", out, preDefine));
    EXPECT_EQ(out, std::string(preDefine));
}

// GetDevUint：覆盖默认值分支
HWTEST_F(SystemDependUTTest, DevUint_DefaultValue, TestSize.Level0)
{
    EXPECT_EQ(SystemDepend::GetDevUint("persist.hdc.test.uint.notexist", 42), 42u);
}
#endif  // HARMONY_PROJECT
}  // namespace Hdc
