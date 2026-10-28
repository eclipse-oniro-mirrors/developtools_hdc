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

#include <list>
#include <string>
#include <unistd.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "auth.h"
#include "common.h"

using namespace testing::ext;
using namespace testing;

namespace Hdc {
class HdcAuthTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static std::string workDir;
};

std::string HdcAuthTest::workDir;

void HdcAuthTest::SetUpTestCase()
{
    char tmpl[] = "/data/local/tmp/hdc_auth_ut_XXXXXX";
    workDir = mkdtemp(tmpl) ? std::string(tmpl) : "/tmp";
}
void HdcAuthTest::TearDownTestCase()
{
    if (!workDir.empty() && workDir != "/tmp") {
        std::string cmd = "rm -rf " + workDir;
        (void)system(cmd.c_str());
    }
}
void HdcAuthTest::SetUp() {}
void HdcAuthTest::TearDown() {}

#ifdef HDC_HOST
// GetHostName：返回 true 且主机名非空（host 侧，uv_os_gethostname）
HWTEST_F(HdcAuthTest, GetHostName_ReturnsNonEmpty, TestSize.Level0)
{
    std::string host;
    EXPECT_TRUE(HdcAuth::GetHostName(host));
    EXPECT_FALSE(host.empty());
}
#endif

// KeylistIncrement：空 list + index=0 → 加载后仍空则返回 false（覆盖 all finish 分支）
HWTEST_F(HdcAuthTest, KeylistIncrement_EmptyList_ReturnsFalse, TestSize.Level0)
{
    std::list<void *> keys;
    uint8_t index = 0;
    void *out = nullptr;
    bool r = HdcAuth::KeylistIncrement(&keys, index, &out);
    EXPECT_FALSE(r);
    HdcAuth::FreeKey(true, &keys);
}

// FreeKey：空 list 不崩溃
HWTEST_F(HdcAuthTest, FreeKey_EmptyList_NoCrash, TestSize.Level0)
{
    std::list<void *> keys;
    EXPECT_NO_FATAL_FAILURE(HdcAuth::FreeKey(false, &keys));
    EXPECT_NO_FATAL_FAILURE(HdcAuth::FreeKey(true, &keys));
}

// GenerateKey：合法路径生成 4096 位 RSA 私钥文件 → true（host 侧，较慢）
#ifdef HDC_HOST
HWTEST_F(HdcAuthTest, GenerateKey_ValidPath_ReturnsTrue, TestSize.Level0)
{
    std::string keyfile = workDir + "/ut_rsa_key";
    bool r = HdcAuth::GenerateKey(keyfile.c_str());
    EXPECT_TRUE(r);
    (void)unlink(keyfile.c_str());
    (void)unlink((keyfile + ".pub").c_str());
}
#endif

// GenerateKey：不可写路径 → false（覆盖 fopen 失败分支）
HWTEST_F(HdcAuthTest, GenerateKey_BadPath_ReturnsFalse, TestSize.Level0)
{
    bool r = HdcAuth::GenerateKey("/nonexist_dir/ut_key");
    EXPECT_FALSE(r);
}

#ifndef HDC_HOST
// AuthVerify：daemon 侧，空签名 → false（覆盖校验失败分支）
HWTEST_F(HdcAuthTest, AuthVerify_BadSig_ReturnsFalse, TestSize.Level0)
{
    uint8_t token[HdcAuth::RSA_TOKEN_SIZE] = {0};
    uint8_t sig[1] = {0};
    EXPECT_FALSE(HdcAuth::AuthVerify(token, sig, sizeof(sig)));
}
#endif
}  // namespace Hdc

// auth.cpp 内部函数前向声明（未在 auth.h 导出，host 侧定义）
namespace HdcAuth {
#ifdef HDC_HOST
bool ReadKey(const char *file, std::list<void *> *listPrivateKey);
bool GetUserKeyPath(std::string &path);
bool LoadHostUserKey(std::list<void *> *listPrivateKey);
int GetUserInfo(char *buf, size_t len);
int WritePublicKeyfile(RSA *private_key, const char *private_key_path);
bool TryLoadPublicKey(std::string &pubkey);
bool LoadPublicKey(const std::string &pubkey_filename, std::string &pubkey);
bool GenerateKeyPair(const std::string &prikey_filename, const std::string &pubkey_filename);
#ifdef HDC_SUPPORT_ENCRYPT_PRIVATE_KEY
int IsEncryptedPEM(const std::string &prikeyFileName);
bool ReadEncryptKeyFile(const std::string &privateKeyFile, std::vector<uint8_t> &fileData, int needFileLength);
#endif
#endif
}  // namespace HdcAuth

namespace Hdc {
// 生成小位 RSA 密钥（测试用，避免 4096 位耗时）
static RSA *UtGenRSA(int bits)
{
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(rsa, bits, e, nullptr);
    BN_free(e);
    return rsa;
}

static __attribute__((unused)) EVP_PKEY *UtRSAToEVP(RSA *rsa)
{
    EVP_PKEY *evp = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(evp, rsa);
    return evp;
}

#ifdef HDC_HOST
// GetHostName：两次调用结果一致
HWTEST_F(HdcAuthTest, GetHostName_TwiceConsistent, TestSize.Level0)
{
    std::string a;
    std::string b;
    EXPECT_TRUE(HdcAuth::GetHostName(a));
    EXPECT_TRUE(HdcAuth::GetHostName(b));
    EXPECT_EQ(a, b);
}
#endif

// KeylistIncrement：预填 2 项、index=0 → 返回 true，out 非空
HWTEST_F(HdcAuthTest, KeylistIncrement_PrefilledList, TestSize.Level0)
{
    std::list<void *> keys;
    keys.push_back(reinterpret_cast<void *>(0x1));
    keys.push_back(reinterpret_cast<void *>(0x2));
    uint8_t idx = 0;
    void *out = nullptr;
    EXPECT_TRUE(HdcAuth::KeylistIncrement(&keys, idx, &out));
    EXPECT_NE(out, nullptr);
    keys.clear();  // 桩指针，不走 FreeKey
}

// KeylistIncrement：index==size → all finish 返回 false
HWTEST_F(HdcAuthTest, KeylistIncrement_AllFinish, TestSize.Level0)
{
    std::list<void *> keys;
    keys.push_back(reinterpret_cast<void *>(0x1));
    keys.push_back(reinterpret_cast<void *>(0x2));
    uint8_t idx = 2;
    void *out = nullptr;
    EXPECT_FALSE(HdcAuth::KeylistIncrement(&keys, idx, &out));
    keys.clear();
}

// FreeKey：private 模式释放真实 RSA* 项
HWTEST_F(HdcAuthTest, FreeKey_PrivateWithItem, TestSize.Level0)
{
    std::list<void *> keys;
    RSA *rsa = UtGenRSA(1024);
    keys.push_back(rsa);
    EXPECT_NO_FATAL_FAILURE(HdcAuth::FreeKey(false, &keys));
    EXPECT_TRUE(keys.empty());
}

#ifdef HDC_HOST
// ReadKey：文件不存在 → false
HWTEST_F(HdcAuthTest, ReadKey_NotExist, TestSize.Level0)
{
    std::list<void *> keys;
    EXPECT_FALSE(HdcAuth::ReadKey("/nonexist/hdc_ut_key.pem", &keys));
}

// ReadKey：null 参数 → false
HWTEST_F(HdcAuthTest, ReadKey_NullParams, TestSize.Level0)
{
    std::list<void *> keys;
    EXPECT_FALSE(HdcAuth::ReadKey(nullptr, &keys));
    EXPECT_FALSE(HdcAuth::ReadKey("/tmp/x", nullptr));
}

// ReadKey：非法 PEM → false
HWTEST_F(HdcAuthTest, ReadKey_BadPEM, TestSize.Level0)
{
    std::string path = workDir + "/ut_badpem.pem";
    FILE *f = fopen(path.c_str(), "w");
    ASSERT_NE(f, nullptr);
    fputs("not a pem", f);
    fclose(f);
    std::list<void *> keys;
    EXPECT_FALSE(HdcAuth::ReadKey(path.c_str(), &keys));
    unlink(path.c_str());
}

// ReadKey：空文件 → false
HWTEST_F(HdcAuthTest, ReadKey_EmptyFile, TestSize.Level0)
{
    std::string path = workDir + "/ut_emptypem.pem";
    FILE *f = fopen(path.c_str(), "w");
    ASSERT_NE(f, nullptr);
    fclose(f);
    std::list<void *> keys;
    EXPECT_FALSE(HdcAuth::ReadKey(path.c_str(), &keys));
    unlink(path.c_str());
}

// ReadKey：合法 RSA 私钥 PEM → true，list 含 1 项
HWTEST_F(HdcAuthTest, ReadKey_Valid, TestSize.Level0)
{
    std::string path = workDir + "/ut_valid.pem";
    RSA *rsa = UtGenRSA(1024);
    FILE *f = fopen(path.c_str(), "w");
    ASSERT_NE(f, nullptr);
    PEM_write_RSAPrivateKey(f, rsa, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(f);
    RSA_free(rsa);
    std::list<void *> keys;
    EXPECT_TRUE(HdcAuth::ReadKey(path.c_str(), &keys));
    EXPECT_EQ(keys.size(), 1u);
    HdcAuth::FreeKey(false, &keys);
    unlink(path.c_str());
}

// GetUserKeyPath：返回 true 且路径非空
HWTEST_F(HdcAuthTest, GetUserKeyPath_ReturnsNonEmpty, TestSize.Level0)
{
    std::string path;
    EXPECT_TRUE(HdcAuth::GetUserKeyPath(path));
    EXPECT_FALSE(path.empty());
}

// GetUserInfo：充足缓冲 → RET_SUCCESS
HWTEST_F(HdcAuthTest, GetUserInfo_Normal, TestSize.Level0)
{
    char buf[4096] = {0};
    EXPECT_EQ(HdcAuth::GetUserInfo(buf, sizeof(buf)), RET_SUCCESS);
}

// GetUserInfo：缓冲过小 → ERR_BUF_OVERFLOW
HWTEST_F(HdcAuthTest, GetUserInfo_TinyBuf, TestSize.Level0)
{
    char buf[2] = {0};
    EXPECT_EQ(HdcAuth::GetUserInfo(buf, sizeof(buf)), ERR_BUF_OVERFLOW);
}

// WritePublicKeyfile：小密钥（RSA_size != 512）→ RSA2RSAPublicKey 返回 0 → 返回 0
HWTEST_F(HdcAuthTest, WritePublicKeyfile_SmallKey, TestSize.Level0)
{
    RSA *rsa = UtGenRSA(1024);
    EXPECT_EQ(HdcAuth::WritePublicKeyfile(rsa, (workDir + "/ut_wp").c_str()), 0);
    RSA_free(rsa);
}

// RsaSign：signKey 为 null → false
HWTEST_F(HdcAuthTest, RsaSign_NullKey, TestSize.Level0)
{
    std::string buf = "hello";
    EXPECT_FALSE(HdcAuth::RsaSign(buf, nullptr));
}

// RsaSign：2048 位真实密钥 → true
HWTEST_F(HdcAuthTest, RsaSign_RealKeySuccess, TestSize.Level0)
{
    RSA *rsa = UtGenRSA(2048);
    EVP_PKEY *evp = UtRSAToEVP(rsa);
    std::string buf = "hdc-ut-sign";
    EXPECT_TRUE(HdcAuth::RsaSign(buf, evp));
    EVP_PKEY_free(evp);
    RSA_free(rsa);
}

// RsaEncrypt：buf 过大 → RSA_private_encrypt 失败 → false
HWTEST_F(HdcAuthTest, RsaEncrypt_BufTooLarge, TestSize.Level0)
{
    RSA *rsa = UtGenRSA(1024);
    std::string buf(200, 'a');  // 超过 RSA_size(128)-11
    EXPECT_FALSE(HdcAuth::RsaEncrypt(buf, rsa));
    RSA_free(rsa);
}

// RsaEncrypt：小 buf → true
HWTEST_F(HdcAuthTest, RsaEncrypt_Success, TestSize.Level0)
{
    RSA *rsa = UtGenRSA(1024);
    std::string buf = "hdc-ut-enc";
    EXPECT_TRUE(HdcAuth::RsaEncrypt(buf, rsa));
    RSA_free(rsa);
}

// RsaSignAndBase64：RSA_3072_SHA512 类型，无 key 文件不崩溃
HWTEST_F(HdcAuthTest, RsaSignAndBase64_NoCrash_RSA3072, TestSize.Level0)
{
    std::string buf = "hdc-ut";
    bool r = false;
    EXPECT_NO_FATAL_FAILURE(r = HdcAuth::RsaSignAndBase64(buf, AuthVerifyType::RSA_3072_SHA512));
    (void)r;
}

// RsaSignAndBase64：RSA_ENCRYPT 类型，无 key 文件不崩溃
HWTEST_F(HdcAuthTest, RsaSignAndBase64_NoCrash_RsaEncrypt, TestSize.Level0)
{
    std::string buf = "hdc-ut";
    bool r = false;
    EXPECT_NO_FATAL_FAILURE(r = HdcAuth::RsaSignAndBase64(buf, AuthVerifyType::RSA_ENCRYPT));
    (void)r;
}

// RsaPrikeyDecryptPsk：in 为 null → -1
HWTEST_F(HdcAuthTest, RsaPrikeyDecryptPsk_NullIn, TestSize.Level0)
{
    unsigned char out[256] = {0};
    EXPECT_EQ(HdcAuth::RsaPrikeyDecryptPsk(nullptr, 4, out, sizeof(out)), -1);
}

// RsaPrikeyDecryptPsk：out 为 null → -1
HWTEST_F(HdcAuthTest, RsaPrikeyDecryptPsk_NullOut, TestSize.Level0)
{
    unsigned char in[4] = {1, 2, 3, 4};
    EXPECT_EQ(HdcAuth::RsaPrikeyDecryptPsk(in, 4, nullptr, 256), -1);
}

// RsaPrikeyDecryptPsk：inLen=0 → -1
HWTEST_F(HdcAuthTest, RsaPrikeyDecryptPsk_InLenZero, TestSize.Level0)
{
    unsigned char in[4] = {0};
    unsigned char out[256] = {0};
    EXPECT_EQ(HdcAuth::RsaPrikeyDecryptPsk(in, 0, out, sizeof(out)), -1);
}

// RsaPrikeyDecryptPsk：inLen 为负 → -1
HWTEST_F(HdcAuthTest, RsaPrikeyDecryptPsk_InLenNegative, TestSize.Level0)
{
    unsigned char in[4] = {0};
    unsigned char out[256] = {0};
    EXPECT_EQ(HdcAuth::RsaPrikeyDecryptPsk(in, -1, out, sizeof(out)), -1);
}

// RsaPrikeyDecryptPsk：inLen 超过 BUF_SIZE_DEFAULT2 → -1
HWTEST_F(HdcAuthTest, RsaPrikeyDecryptPsk_InLenTooLarge, TestSize.Level0)
{
    unsigned char in[4] = {0};
    unsigned char out[256] = {0};
    EXPECT_EQ(HdcAuth::RsaPrikeyDecryptPsk(in, BUF_SIZE_DEFAULT2 + 1, out, sizeof(out)), -1);
}

// RsaPrikeyDecryptPsk：outBufSize=0 → -1
HWTEST_F(HdcAuthTest, RsaPrikeyDecryptPsk_OutBufTooSmall, TestSize.Level0)
{
    unsigned char in[4] = {1, 2, 3, 4};
    unsigned char out[256] = {0};
    EXPECT_EQ(HdcAuth::RsaPrikeyDecryptPsk(in, 4, out, 0), -1);
}

// GetPublicKeyinfo：调用不崩溃（可能生成密钥）
HWTEST_F(HdcAuthTest, GetPublicKeyinfo_NoCrash, TestSize.Level0)
{
    std::string info;
    EXPECT_NO_FATAL_FAILURE(HdcAuth::GetPublicKeyinfo(info));
}

// TryLoadPublicKey：调用不崩溃（可能生成密钥）
HWTEST_F(HdcAuthTest, TryLoadPublicKey_NoCrash, TestSize.Level0)
{
    std::string pubkey;
    EXPECT_NO_FATAL_FAILURE(HdcAuth::TryLoadPublicKey(pubkey));
}

// LoadPublicKey：文件不存在 → false
HWTEST_F(HdcAuthTest, LoadPublicKey_NotExist, TestSize.Level0)
{
    std::string pubkey;
    EXPECT_FALSE(HdcAuth::LoadPublicKey("/nonexist/hdc_pub.pem", pubkey));
}

// GenerateKeyPair：tmpdir 内生成 3072 位密钥对 → true
HWTEST_F(HdcAuthTest, GenerateKeyPair_Success, TestSize.Level0)
{
    std::string pri = workDir + "/ut_kp_pri";
    std::string pub = workDir + "/ut_kp_pub";
    EXPECT_TRUE(HdcAuth::GenerateKeyPair(pri, pub));
    EXPECT_EQ(access(pri.c_str(), F_OK), 0);
    EXPECT_EQ(access(pub.c_str(), F_OK), 0);
    unlink(pri.c_str());
    unlink(pub.c_str());
}

// GenerateKeyPair：非法路径 → false
HWTEST_F(HdcAuthTest, GenerateKeyPair_BadPath, TestSize.Level0)
{
    EXPECT_FALSE(HdcAuth::GenerateKeyPair("/nonexist_dir/pri", "/nonexist_dir/pub"));
}

#ifdef HDC_SUPPORT_ENCRYPT_PRIVATE_KEY
// IsEncryptedPEM：空文件名 → -1
HWTEST_F(HdcAuthTest, IsEncryptedPEM_EmptyName, TestSize.Level0)
{
    EXPECT_EQ(HdcAuth::IsEncryptedPEM(""), -1);
}

// IsEncryptedPEM：文件不存在 → 1
HWTEST_F(HdcAuthTest, IsEncryptedPEM_NotExist, TestSize.Level0)
{
    EXPECT_EQ(HdcAuth::IsEncryptedPEM("/nonexist/hdc_enc.pem"), 1);
}

// IsEncryptedPEM：非 PEM 文本 → 1（已加密）
HWTEST_F(HdcAuthTest, IsEncryptedPEM_NotPEM, TestSize.Level0)
{
    std::string path = workDir + "/ut_notpem.txt";
    FILE *f = fopen(path.c_str(), "w");
    ASSERT_NE(f, nullptr);
    fputs("garbage line\n", f);
    fclose(f);
    EXPECT_EQ(HdcAuth::IsEncryptedPEM(path), 1);
    unlink(path.c_str());
}

// IsEncryptedPEM：未加密 PEM（BEGIN PRIVATE KEY）→ 0
HWTEST_F(HdcAuthTest, IsEncryptedPEM_ValidPEM, TestSize.Level0)
{
    std::string path = workDir + "/ut_plainpem.pem";
    RSA *rsa = UtGenRSA(1024);
    EVP_PKEY *evp = UtRSAToEVP(rsa);
    FILE *f = fopen(path.c_str(), "w");
    ASSERT_NE(f, nullptr);
    PEM_write_PrivateKey(f, evp, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(f);
    EVP_PKEY_free(evp);
    RSA_free(rsa);
    EXPECT_EQ(HdcAuth::IsEncryptedPEM(path), 0);
    unlink(path.c_str());
}

// ReadEncryptKeyFile：文件不存在 → false
HWTEST_F(HdcAuthTest, ReadEncryptKeyFile_NotExist, TestSize.Level0)
{
    std::vector<uint8_t> data;
    EXPECT_FALSE(HdcAuth::ReadEncryptKeyFile("/nonexist/hdc_enc.key", data, 16));
}

// CheckPrivateKeyFile：调用不崩溃
HWTEST_F(HdcAuthTest, CheckPrivateKeyFile_NoCrash, TestSize.Level0)
{
    bool r = false;
    EXPECT_NO_FATAL_FAILURE(r = HdcAuth::CheckPrivateKeyFile());
    (void)r;
}
#endif

// PostUIConfirm：host 侧返回 false
HWTEST_F(HdcAuthTest, PostUIConfirm_HostReturnsFalse, TestSize.Level0)
{
#ifdef HDC_HOST
    EXPECT_FALSE(HdcAuth::PostUIConfirm("pub"));
#else
    GTEST_SUCCEED();
#endif
}
#endif  // HDC_HOST

#ifndef HDC_HOST
// PostUIConfirm：daemon 侧返回 true
HWTEST_F(HdcAuthTest, PostUIConfirm_DaemonReturnsTrue, TestSize.Level0)
{
    EXPECT_TRUE(HdcAuth::PostUIConfirm("pub"));
}

// RsaPubkeyEncryptPsk：in 为 null → -1
HWTEST_F(HdcAuthTest, RsaPubkeyEncryptPsk_NullIn, TestSize.Level0)
{
    unsigned char out[256] = {0};
    EXPECT_EQ(HdcAuth::RsaPubkeyEncryptPsk(nullptr, 4, out, sizeof(out), "pub"), -1);
}

// RsaPubkeyEncryptPsk：out 为 null → -1
HWTEST_F(HdcAuthTest, RsaPubkeyEncryptPsk_NullOut, TestSize.Level0)
{
    unsigned char in[4] = {1, 2, 3, 4};
    EXPECT_EQ(HdcAuth::RsaPubkeyEncryptPsk(in, 4, nullptr, 256, "pub"), -1);
}

// RsaPubkeyEncryptPsk：非法 pubkey → -1
HWTEST_F(HdcAuthTest, RsaPubkeyEncryptPsk_BadPubkey, TestSize.Level0)
{
    unsigned char in[4] = {1, 2, 3, 4};
    unsigned char out[256] = {0};
    EXPECT_EQ(HdcAuth::RsaPubkeyEncryptPsk(in, 4, out, sizeof(out), "garbage"), -1);
}

// RsaPubkeyEncryptPsk：空 pubkey → -1
HWTEST_F(HdcAuthTest, RsaPubkeyEncryptPsk_EmptyPubkey, TestSize.Level0)
{
    unsigned char in[4] = {1, 2, 3, 4};
    unsigned char out[256] = {0};
    EXPECT_EQ(HdcAuth::RsaPubkeyEncryptPsk(in, 4, out, sizeof(out), ""), -1);
}

// AuthVerify：siglen=0 → false（无 key 加载）
HWTEST_F(HdcAuthTest, AuthVerify_EmptySig, TestSize.Level0)
{
    uint8_t token[HdcAuth::RSA_TOKEN_SIZE] = {0};
    uint8_t sig[1] = {0};
    EXPECT_FALSE(HdcAuth::AuthVerify(token, sig, 0));
}

// AuthVerify：完整 token/sig 但无 key → false
HWTEST_F(HdcAuthTest, AuthVerify_NoKeysReturnsFalse, TestSize.Level0)
{
    uint8_t token[HdcAuth::RSA_TOKEN_SIZE] = {0};
    uint8_t sig[HdcAuth::RSA_TOKEN_SIZE] = {0};
    EXPECT_FALSE(HdcAuth::AuthVerify(token, sig, sizeof(sig)));
}
#endif  // HDC_HOST
}  // namespace Hdc
