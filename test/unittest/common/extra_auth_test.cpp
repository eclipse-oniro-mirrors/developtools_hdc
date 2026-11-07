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

#include "extra_auth.h"

#include <gtest/gtest.h>

#include "base.h"

using namespace testing::ext;

namespace Hdc {

class ExtraAuthTest : public testing::Test {};

HWTEST_F(ExtraAuthTest, ClientVersionCompatibility, TestSize.Level0)
{
    EXPECT_FALSE(HdcExtraAuth::IsClientVersionSupported("Ver: 3.2.0fTEST"));
    EXPECT_FALSE(HdcExtraAuth::IsClientVersionSupported("Ver: 3.3.0"));
    EXPECT_TRUE(HdcExtraAuth::IsClientVersionSupported(HdcExtraAuth::MIN_CLIENT_VERSION));
    EXPECT_TRUE(HdcExtraAuth::IsClientVersionSupported("Ver: 3.3.0aTEST"));
    EXPECT_TRUE(HdcExtraAuth::IsClientVersionSupported("Ver: 3.3.0bTEST"));
    EXPECT_TRUE(HdcExtraAuth::IsClientVersionSupported("Ver: 3.10.0aTEST"));
    EXPECT_TRUE(HdcExtraAuth::IsClientVersionSupported("Ver: 3.4.0aTEST"));
    EXPECT_FALSE(HdcExtraAuth::IsClientVersionSupported("invalid"));
    EXPECT_NE(std::string(HdcExtraAuth::UNSUPPORTED_CLIENT_MESSAGE).find("3.3.0a"), std::string::npos);
}

HWTEST_F(ExtraAuthTest, Hex2BytesRoundTrip, TestSize.Level0)
{
    std::vector<uint8_t> out;
    ASSERT_TRUE(HdcExtraAuth::Hex2Bytes("4d4f43", out));
    ASSERT_EQ(out.size(), 3u);
    EXPECT_EQ(out[0], 0x4d);
    EXPECT_EQ(out[1], 0x4f);
    EXPECT_EQ(out[2], 0x43);

    ASSERT_TRUE(HdcExtraAuth::Hex2Bytes("4D4F43", out));  // uppercase ok
    EXPECT_EQ(out[0], 0x4d);

    ASSERT_TRUE(HdcExtraAuth::Hex2Bytes("", out));  // empty -> empty
    EXPECT_TRUE(out.empty());

    EXPECT_FALSE(HdcExtraAuth::Hex2Bytes("abc", out));  // odd length
    EXPECT_FALSE(HdcExtraAuth::Hex2Bytes("4g", out));   // invalid char
}

#ifdef HDC_HOST
HWTEST_F(ExtraAuthTest, ApplyPdaRejectsEmptyRpm, TestSize.Level0)
{
    // Empty input is rejected before any external call (deterministic, no
    // dependency on java / jar / network).
    std::string pda = "stale";
    EXPECT_FALSE(HdcExtraAuth::ApplyPda(std::string{}, pda));
    EXPECT_TRUE(pda.empty());
    // The success path invokes device-auth-tool.jar (network round-trip to the
    // PKI server) and is covered by the integration test checklist, not here.
}
#else
HWTEST_F(ExtraAuthTest, GetRpmFailsWithoutDhaSo, TestSize.Level0)
{
    // 测试环境无 DHA SO，GetRpm 优雅失败（dlopen 失败 → 返回 false）。
    std::string payload;
    EXPECT_FALSE(HdcExtraAuth::GetRpm(payload));
}

HWTEST_F(ExtraAuthTest, StoreAndVerifyPdaFailsWithoutDhaSo, TestSize.Level0)
{
    // 测试环境无 DHA SO，StoreAndVerifyPda 优雅失败。
    EXPECT_FALSE(HdcExtraAuth::StoreAndVerifyPda("any-pda-bytes"));
}
#endif
}  // namespace Hdc
