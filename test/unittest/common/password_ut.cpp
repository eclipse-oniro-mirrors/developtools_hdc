/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "password_ut.h"
#include "securec.h"

using namespace testing::ext;
namespace Hdc {

#define TEST_KEY_ALIAS "test_password_alias"
void HdcPasswordTest::SetUpTestCase() {}
void HdcPasswordTest::TearDownTestCase() {}
void HdcPasswordTest::SetUp() {}
void HdcPasswordTest::TearDown() {}

bool HdcPasswordTest::CheckPasswordFormat(std::pair<const uint8_t*, int> pwdInfo)
{
    std::string specialChar = "~!@#$%^&*()-_=+\\|[{}];:'\",<.>/?";
    if (pwdInfo.first == nullptr || pwdInfo.second != PASSWORD_LENGTH) {
        return false;
    }
    
    if (specialChar.find(pwdInfo.first[0]) == std::string::npos) {
        return false;
    }
    
    if (pwdInfo.first[1] < 'a' || pwdInfo.first[1] > 'z') {
        return false;
    }
    for (int i = 2; i < pwdInfo.second; i++) {
        if (pwdInfo.first[i] < '0' || pwdInfo.first[i] > '9') {
            return false;
        }
    }
    return true;
}

HWTEST_F(HdcPasswordTest, TestGeneratePassword, TestSize.Level0)
{
    HdcPassword pwd(TEST_KEY_ALIAS);
    pwd.GeneratePassword();
    std::pair<const uint8_t*, int> pwdInfo = pwd.GetPassword();
    ASSERT_EQ(CheckPasswordFormat(pwdInfo), true);
}

HWTEST_F(HdcPasswordTest, TestGetEncryptPwdLength, TestSize.Level0)
{
    // (12 bytes nonce value  + 10 bytes pwd length  + 16 bytes tag length ) * 2 (byte to hex)
    #define ENCRYPT_LENGTH 76
    HdcPassword pwd(TEST_KEY_ALIAS);
    int len = pwd.GetEncryptPwdLength();
    ASSERT_EQ(len, ENCRYPT_LENGTH);
}

HWTEST_F(HdcPasswordTest, TestGetPassword, TestSize.Level0)
{
    HdcPassword pwd(TEST_KEY_ALIAS);
    pwd.GeneratePassword();
    auto pwdInfo = pwd.GetPassword();
    ASSERT_NE(pwdInfo.first, nullptr);
    ASSERT_EQ(pwdInfo.second, PASSWORD_LENGTH);
    ASSERT_TRUE(CheckPasswordFormat(pwdInfo));
}

HWTEST_F(HdcPasswordTest, TestGetEncryptPassword, TestSize.Level0)
{
    HdcPassword pwd(TEST_KEY_ALIAS);
    pwd.GeneratePassword();
    
    auto rawPwd = pwd.GetPassword();
    std::vector<uint8_t> pwdVec(rawPwd.first, rawPwd.first + rawPwd.second);
    
    pwd.ByteToHex(pwdVec);
    
    std::string encryptPwd = pwd.GetEncryptPassword();
    for (char c : encryptPwd) {
        ASSERT_TRUE((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'));
    }
}

#ifdef HDC_FEATURE_SUPPORT_CREDENTIAL
HWTEST_F(HdcPasswordTest, TestEncryptAndDecrypt, TestSize.Level0)
{
    HdcPassword pwd(TEST_KEY_ALIAS);
    std::pair<const uint8_t*, int> plainPwd = pwd.GetPassword();
    (void)memset_s(plainPwd.first, plainPwd.second, '1', plainPwd.second);
    ASSERT_EQ(pwd.ResetPwdKey(), true);
    ASSERT_EQ(pwd.EncryptPwd(), true);
    std::string encryptPwd = pwd.GetEncryptPassword();
    std::vector<uint8_t> encryptData(encryptPwd.data(), encryptPwd.data() + encryptPwd.length());
    ASSERT_EQ(pwd.DecryptPwd(encryptData), true);
    plainPwd = pwd.GetPassword();
    ASSERT_EQ(memcmp(plainPwd.first, "1111111111", plainPwd.second), 0);
}
#endif

// GetHexChar：0~9 → '0'~'9'
HWTEST_F(HdcPasswordTest, TestGetHexChar_0to9, TestSize.Level0)
{
    HdcPassword pwd(TEST_KEY_ALIAS);
    for (uint8_t i = 0; i <= 9; ++i) {
        EXPECT_EQ(pwd.GetHexChar(i), static_cast<char>('0' + i));
    }
}

// GetHexChar：10~15 → 'A'~'F'
HWTEST_F(HdcPasswordTest, TestGetHexChar_10to15, TestSize.Level0)
{
    HdcPassword pwd(TEST_KEY_ALIAS);
    const char *hex = "ABCDEF";
    for (uint8_t i = 0; i < 6; ++i) {
        EXPECT_EQ(pwd.GetHexChar(static_cast<uint8_t>(10 + i)), hex[i]);
    }
}

// GeneratePassword：生成后 GetPassword 返回非空且长度为 PASSWORD_LENGTH
HWTEST_F(HdcPasswordTest, TestGeneratePassword_NonEmpty, TestSize.Level0)
{
    HdcPassword pwd(TEST_KEY_ALIAS);
    pwd.GeneratePassword();
    auto p = pwd.GetPassword();
    ASSERT_NE(p.first, nullptr);
    EXPECT_EQ(p.second, PASSWORD_LENGTH);
}

// GetEncryptPwdLength：生成密码后返回正数
HWTEST_F(HdcPasswordTest, TestGetEncryptPwdLength_Positive, TestSize.Level0)
{
    HdcPassword pwd(TEST_KEY_ALIAS);
    pwd.GeneratePassword();
    EXPECT_GT(pwd.GetEncryptPwdLength(), 0);
}

// ResetPwdKey：返回 true
HWTEST_F(HdcPasswordTest, TestResetPwdKey_True, TestSize.Level0)
{
    HdcPassword pwd(TEST_KEY_ALIAS);
    EXPECT_TRUE(pwd.ResetPwdKey());
}

// DecryptPwd：非法数据 → 返回 false（覆盖解密失败分支）
HWTEST_F(HdcPasswordTest, TestDecryptPwd_InvalidData_ReturnsFalse, TestSize.Level0)
{
    HdcPassword pwd(TEST_KEY_ALIAS);
    std::vector<uint8_t> bad = {0x00, 0x01, 0x02};
    EXPECT_FALSE(pwd.DecryptPwd(bad));
}

// GetEncryptPassword：未加密时返回空串
HWTEST_F(HdcPasswordTest, TestGetEncryptPassword_InitialEmpty, TestSize.Level0)
{
    HdcPassword pwd(TEST_KEY_ALIAS);
    EXPECT_TRUE(pwd.GetEncryptPassword().empty());
}

// GetHexChar：非法值（>15）不崩溃
HWTEST_F(HdcPasswordTest, TestGetHexChar_Invalid_NoCrash, TestSize.Level0)
{
    HdcPassword pwd(TEST_KEY_ALIAS);
    EXPECT_NO_FATAL_FAILURE(pwd.GetHexChar(16));
    EXPECT_NO_FATAL_FAILURE(pwd.GetHexChar(255));
}

// ByteToHex/HexToByte 往返一致 + GetEncryptPassword 加密后非空
HWTEST_F(HdcPasswordTest, TestByteToHex_HexToByte_RoundTrip, TestSize.Level0)
{
    HdcPassword pwd(TEST_KEY_ALIAS);
    // 原始字节序列（含边界值 0x00 / 0xFF / 高低 nibble 混合）
    std::vector<uint8_t> raw = {0x12, 0x34, 0xAB, 0xFF, 0x00, 0x5C};

    // ByteToHex → encryptPwd 应为非空十六进制字符串，长度为 raw.size() * 2
    pwd.ByteToHex(raw);
    std::string hexStr = pwd.GetEncryptPassword();
    EXPECT_FALSE(hexStr.empty());
    EXPECT_EQ(hexStr.size(), raw.size() * 2);
    for (char c : hexStr) {
        EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'));
    }

    // 清空后 HexToByte 往返 → encryptPwd 还原为原始字节
    pwd.ClearEncryptPwd();
    std::vector<uint8_t> hexVec(hexStr.begin(), hexStr.end());
    EXPECT_TRUE(pwd.HexToByte(hexVec));
    std::string roundTrip = pwd.GetEncryptPassword();
    EXPECT_FALSE(roundTrip.empty());
    EXPECT_EQ(roundTrip.size(), raw.size());
    ASSERT_EQ(memcmp(roundTrip.data(), raw.data(), raw.size()), 0);
}
} // namespace Hdc