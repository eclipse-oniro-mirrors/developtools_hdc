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

#include "connect_validation.h"
#include "define_enum.h"

using namespace testing::ext;
using namespace testing;

namespace Hdc {
class ConnectValidationTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ConnectValidationTest::SetUpTestCase() {}
void ConnectValidationTest::TearDownTestCase() {}
void ConnectValidationTest::SetUp() {}
void ConnectValidationTest::TearDown() {}

// GetConnectValidationParam：参数未设置（空）→ VALIDATION_CLOSE（覆盖空值早返回分支）
HWTEST_F(ConnectValidationTest, GetConnectValidationParam_NotSet_ReturnsClose, TestSize.Level0)
{
    // persist.hdc.control.enterprise_connect_validation 默认未设置 → 返回 VALIDATION_CLOSE
    int r = HdcValidation::GetConnectValidationParam();
    EXPECT_EQ(r, VALIDATION_CLOSE);
}

#ifdef HDC_HOST
// RsaSignAndBase64：非法 PEM → StringToEVP 返回 null → 返回 false（覆盖 evp 为空分支）
HWTEST_F(ConnectValidationTest, RsaSignAndBase64_InvalidPem_ReturnsFalse, TestSize.Level0)
{
    std::string buf = "hdc-ut-token";
    std::string badPem = "not a pem";
    EXPECT_FALSE(HdcValidation::RsaSignAndBase64(buf, Hdc::AuthVerifyType::RSA_2048, badPem));
}

// RsaSignAndBase64：空 PEM → 返回 false
HWTEST_F(ConnectValidationTest, RsaSignAndBase64_EmptyPem_ReturnsFalse, TestSize.Level0)
{
    std::string buf = "hdc-ut-token";
    std::string emptyPem;
    EXPECT_FALSE(HdcValidation::RsaSignAndBase64(buf, Hdc::AuthVerifyType::RSA_3072_SHA512, emptyPem));
}

// GetPublicKeyHashInfo：无 server 在线 → GetPubKeyHash 失败 → 返回 false（覆盖失败分支）
HWTEST_F(ConnectValidationTest, GetPublicKeyHashInfo_NoServer_ReturnsFalse, TestSize.Level0)
{
    std::string buf;
    EXPECT_FALSE(HdcValidation::GetPublicKeyHashInfo(buf));
}

// GetPrivateKeyInfo：无 server 在线 → 返回 false
HWTEST_F(ConnectValidationTest, GetPrivateKeyInfo_NoServer_ReturnsFalse, TestSize.Level0)
{
    std::string buf;
    EXPECT_FALSE(HdcValidation::GetPrivateKeyInfo(buf));
}
#else
// CheckAuthPubKeyIsValid：daemon 侧，公钥文件不存在 → 返回 false（覆盖打开失败分支）
HWTEST_F(ConnectValidationTest, CheckAuthPubKeyIsValid_NoKeyFile_ReturnsFalse, TestSize.Level0)
{
    // 默认 keyfile 路径 /data/service/el2/public/hdc_service/daemon_public_key.pem 在测试环境通常不存在
    std::string key(625, 'A');
    EXPECT_FALSE(HdcValidation::CheckAuthPubKeyIsValid(key));
}
#endif

// GetConnectValidationParam：返回值在合法枚举范围内
HWTEST_F(ConnectValidationTest, GetConnectValidationParam_ReturnsInRange, TestSize.Level0)
{
    int r = HdcValidation::GetConnectValidationParam();
    EXPECT_GE(r, VALIDATION_CLOSE);
    EXPECT_LE(r, VALIDATION_HDC_HOST_AND_DAEMON);
}

#ifdef HDC_HOST
// RsaSignAndBase64：RSA_ENCRYPT 类型 + 非法 PEM → false（走 evp=null 早返回）
HWTEST_F(ConnectValidationTest, RsaSignAndBase64_RsaEncrypt_InvalidPem_ReturnsFalse, TestSize.Level0)
{
    std::string buf = "hdc-ut-token";
    std::string badPem = "not a pem";
    EXPECT_FALSE(HdcValidation::RsaSignAndBase64(buf, Hdc::AuthVerifyType::RSA_ENCRYPT, badPem));
}

// RsaSignAndBase64：UNKNOWN 类型 + 空 PEM → false
HWTEST_F(ConnectValidationTest, RsaSignAndBase64_UnknownType_EmptyPem_ReturnsFalse, TestSize.Level0)
{
    std::string buf = "hdc-ut-token";
    std::string emptyPem;
    EXPECT_FALSE(HdcValidation::RsaSignAndBase64(buf, Hdc::AuthVerifyType::UNKNOWN, emptyPem));
}

// GetPublicKeyHashInfo：buf 已预填内容 → 不崩溃，返回 false（无 server）
HWTEST_F(ConnectValidationTest, GetPublicKeyHashInfo_PrefilledBuf_NoCrash, TestSize.Level0)
{
    std::string buf = "prefilled-content";
    EXPECT_FALSE(HdcValidation::GetPublicKeyHashInfo(buf));
}

// GetPrivateKeyInfo：buf 已预填内容 → 不崩溃，返回 false（无 server）
HWTEST_F(ConnectValidationTest, GetPrivateKeyInfo_PrefilledBuf_NoCrash, TestSize.Level0)
{
    std::string buf = "prefilled-content";
    EXPECT_FALSE(HdcValidation::GetPrivateKeyInfo(buf));
}
#else
// CheckAuthPubKeyIsValid：空 key → false（key.size() != 625）
HWTEST_F(ConnectValidationTest, CheckAuthPubKeyIsValid_EmptyKey_ReturnsFalse, TestSize.Level0)
{
    std::string key;
    EXPECT_FALSE(HdcValidation::CheckAuthPubKeyIsValid(key));
}

// CheckAuthPubKeyIsValid：短 key（长度 < 625）→ false
HWTEST_F(ConnectValidationTest, CheckAuthPubKeyIsValid_ShortKey_ReturnsFalse, TestSize.Level0)
{
    std::string key(100, 'A');
    EXPECT_FALSE(HdcValidation::CheckAuthPubKeyIsValid(key));
}

// CheckAuthPubKeyIsValid：长 key（长度 > 625）→ false
HWTEST_F(ConnectValidationTest, CheckAuthPubKeyIsValid_LongKey_ReturnsFalse, TestSize.Level0)
{
    std::string key(1000, 'A');
    EXPECT_FALSE(HdcValidation::CheckAuthPubKeyIsValid(key));
}

// CheckAuthPubKeyIsValid：合法长度（625）但不在文件中 → false
HWTEST_F(ConnectValidationTest, CheckAuthPubKeyIsValid_ValidLengthNotInFile_ReturnsFalse, TestSize.Level0)
{
    std::string key(625, 'B');
    EXPECT_FALSE(HdcValidation::CheckAuthPubKeyIsValid(key));
}
#endif
}  // namespace Hdc
