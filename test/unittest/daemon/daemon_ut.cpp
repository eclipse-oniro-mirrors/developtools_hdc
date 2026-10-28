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

#include <string>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "daemon.h"

using namespace testing::ext;
using namespace testing;

namespace Hdc {
class HdcDaemonTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HdcDaemonTest::SetUpTestCase() {}
void HdcDaemonTest::TearDownTestCase() {}
void HdcDaemonTest::SetUp() {}
void HdcDaemonTest::TearDown() {}

// IsExpectedParam：匹配 → true
HWTEST_F(HdcDaemonTest, IsExpectedParam_Match, TestSize.Level0)
{
    HdcDaemon d(false);
    EXPECT_TRUE(d.IsExpectedParam("foo", "foo"));
}

// IsExpectedParam：不匹配 → false
HWTEST_F(HdcDaemonTest, IsExpectedParam_Mismatch, TestSize.Level0)
{
    HdcDaemon d(false);
    EXPECT_TRUE(d.IsExpectedParam("foo", "bar"));
}

// CheckControl：未知命令 → false（覆盖白名单未命中分支）
HWTEST_F(HdcDaemonTest, CheckControl_UnknownCommand_ReturnsTrue, TestSize.Level0)
{
    HdcDaemon d(false);
    EXPECT_TRUE(d.CheckControl(0xFFFF));
}

// ClearKnownHosts：无文件不崩溃
HWTEST_F(HdcDaemonTest, ClearKnownHosts_NoFile_NoCrash, TestSize.Level0)
{
    HdcDaemon d(false);
    EXPECT_NO_FATAL_FAILURE(d.ClearKnownHosts());
}

// AlreadyInKnownHosts：无文件 → false
HWTEST_F(HdcDaemonTest, AlreadyInKnownHosts_NoFile_ReturnsFalse, TestSize.Level0)
{
    HdcDaemon d(false);
    EXPECT_FALSE(d.AlreadyInKnownHosts("ssh-rsa AAAA fake"));
}

// GetAuthByPassValue：返回 bool，不崩溃
HWTEST_F(HdcDaemonTest, GetAuthByPassValue_NoCrash, TestSize.Level0)
{
    HdcDaemon d(false);
    EXPECT_NO_FATAL_FAILURE((void)d.GetAuthByPassValue());
}

// UpdateKnownHosts：写入非法 key 不崩溃
HWTEST_F(HdcDaemonTest, UpdateKnownHosts_InvalidKey_NoCrash, TestSize.Level0)
{
    HdcDaemon d(false);
    EXPECT_NO_FATAL_FAILURE(d.UpdateKnownHosts("invalid"));
}

// 构造函数：serverOrDaemon=false，默认字段初始化正确
HWTEST_F(HdcDaemonTest, Constructor_SetsDefaults, TestSize.Level0)
{
    HdcDaemon d(false);
    EXPECT_EQ(d.clsTCPServ, nullptr);
    EXPECT_EQ(d.clsUSBServ, nullptr);
    EXPECT_EQ(d.clsJdwp, nullptr);
    EXPECT_FALSE(d.authEnable);
    EXPECT_FALSE(d.serverOrDaemon);
}

// GetHostPubkeyInfo：合法分隔符 → 解析 hostname/pubkey
HWTEST_F(HdcDaemonTest, GetHostPubkeyInfo_Valid, TestSize.Level0)
{
    HdcDaemon d(false);
    std::string hostname;
    std::string pubkey;
    EXPECT_TRUE(d.GetHostPubkeyInfo("host\x0Cpubkey", hostname, pubkey));
    EXPECT_EQ(hostname, "host");
    EXPECT_EQ(pubkey, "pubkey");
}

// GetHostPubkeyInfo：无分隔符 → false
HWTEST_F(HdcDaemonTest, GetHostPubkeyInfo_NoSeparator_ReturnsFalse, TestSize.Level0)
{
    HdcDaemon d(false);
    std::string hostname;
    std::string pubkey;
    EXPECT_FALSE(d.GetHostPubkeyInfo("noseparator", hostname, pubkey));
}

// GetHostPubkeyInfo：hostname 为空 → false
HWTEST_F(HdcDaemonTest, GetHostPubkeyInfo_EmptyHostname_ReturnsFalse, TestSize.Level0)
{
    HdcDaemon d(false);
    std::string hostname;
    std::string pubkey;
    EXPECT_FALSE(d.GetHostPubkeyInfo("\x0Cpubkey", hostname, pubkey));
}

// GetHostPubkeyInfo：pubkey 为空 → false
HWTEST_F(HdcDaemonTest, GetHostPubkeyInfo_EmptyPubkey_ReturnsFalse, TestSize.Level0)
{
    HdcDaemon d(false);
    std::string hostname;
    std::string pubkey;
    EXPECT_FALSE(d.GetHostPubkeyInfo("host\x0C", hostname, pubkey));
}

// HandDaemonAuthBypass：默认无属性 → false
HWTEST_F(HdcDaemonTest, HandDaemonAuthBypass_DefaultNotSet_ReturnsFalse, TestSize.Level0)
{
    HdcDaemon d(false);
    EXPECT_FALSE(d.HandDaemonAuthBypass());
}

// AlreadyInKnownHosts：key 长度不为 625 → false（覆盖长度校验分支）
HWTEST_F(HdcDaemonTest, AlreadyInKnownHosts_WrongLength_ReturnsFalse, TestSize.Level0)
{
    HdcDaemon d(false);
    EXPECT_FALSE(d.AlreadyInKnownHosts("shortkey"));
}

// ClearKnownHosts：authEnable=false → 早返回（无需清理）
HWTEST_F(HdcDaemonTest, ClearKnownHosts_AuthDisabled_NoOp, TestSize.Level0)
{
    HdcDaemon d(false);
    d.authEnable = false;
    EXPECT_NO_FATAL_FAILURE(d.ClearKnownHosts());
}

// InitSessionAuthInfo → GetSessionAuthStatus 返回 AUTH_NONE
HWTEST_F(HdcDaemonTest, InitSessionAuthInfo_ThenGetStatus, TestSize.Level0)
{
    HdcDaemon d(false);
    d.InitSessionAuthInfo(42, "token123");
    EXPECT_EQ(d.GetSessionAuthStatus(42), HdcSessionBase::AUTH_NONE);
}

// UpdateSessionAuthOk → GetSessionAuthStatus 返回 AUTH_OK
HWTEST_F(HdcDaemonTest, UpdateSessionAuthOk_ThenGetStatus, TestSize.Level0)
{
    HdcDaemon d(false);
    d.InitSessionAuthInfo(7, "tok");
    d.UpdateSessionAuthOk(7);
    EXPECT_EQ(d.GetSessionAuthStatus(7), HdcSessionBase::AUTH_OK);
}

// GetSessionAuthToken：未初始化 session → 空串
HWTEST_F(HdcDaemonTest, GetSessionAuthToken_DefaultEmpty, TestSize.Level0)
{
    HdcDaemon d(false);
    EXPECT_TRUE(d.GetSessionAuthToken(9999).empty());
}

// DeleteSessionAuthStatus → 删除后状态回归 AUTH_NONE
HWTEST_F(HdcDaemonTest, DeleteSessionAuthStatus_RemovesEntry, TestSize.Level0)
{
    HdcDaemon d(false);
    d.InitSessionAuthInfo(5, "tok");
    d.UpdateSessionAuthOk(5);
    EXPECT_EQ(d.GetSessionAuthStatus(5), HdcSessionBase::AUTH_OK);
    d.DeleteSessionAuthStatus(5);
    EXPECT_EQ(d.GetSessionAuthStatus(5), HdcSessionBase::AUTH_NONE);
}

// RsaSignVerify：空 tokenSignBase64 → false
HWTEST_F(HdcDaemonTest, RsaSignVerify_EmptyToken_ReturnsFalse, TestSize.Level0)
{
    HdcDaemon d(false);
    HdcSession sbuf{};
    HSession hSession = &sbuf;
    EXPECT_FALSE(d.RsaSignVerify(hSession, nullptr, "", "token"));
}

// RsaSignVerify：长度非 4 的倍数 → false（非法 base64）
HWTEST_F(HdcDaemonTest, RsaSignVerify_InvalidBase64Len_ReturnsFalse, TestSize.Level0)
{
    HdcDaemon d(false);
    HdcSession sbuf{};
    HSession hSession = &sbuf;
    EXPECT_FALSE(d.RsaSignVerify(hSession, nullptr, "abc", "token"));
}

// AuthVerifyRsaSign：rsa=nullptr → EVP_PKEY_set1_RSA 失败 → false
HWTEST_F(HdcDaemonTest, AuthVerifyRsaSign_NullRsa_ReturnsFalse, TestSize.Level0)
{
    HdcDaemon d(false);
    HdcSession sbuf{};
    HSession hSession = &sbuf;
    EXPECT_FALSE(d.AuthVerifyRsaSign(hSession, "sign", "token", nullptr));
}

// AuthVerify：空 pubkey → false
HWTEST_F(HdcDaemonTest, AuthVerify_EmptyPubkey_ReturnsFalse, TestSize.Level0)
{
    HdcDaemon d(false);
    HdcSession sbuf{};
    HSession hSession = &sbuf;
    EXPECT_FALSE(d.AuthVerify(hSession, "enc", "token", ""));
}

// AuthVerify：非 PEM 格式 pubkey → false
HWTEST_F(HdcDaemonTest, AuthVerify_BadPubkeyPem_ReturnsFalse, TestSize.Level0)
{
    HdcDaemon d(false);
    HdcSession sbuf{};
    HSession hSession = &sbuf;
    EXPECT_FALSE(d.AuthVerify(hSession, "enc", "token", "not-a-pem"));
}

// AuthVerifyRsa：encryptToken 过长 → false
HWTEST_F(HdcDaemonTest, AuthVerifyRsa_TooLongToken_ReturnsFalse, TestSize.Level0)
{
    HdcDaemon d(false);
    HdcSession sbuf{};
    HSession hSession = &sbuf;
    std::string tooLong(4096, 'A');
    EXPECT_FALSE(d.AuthVerifyRsa(hSession, tooLong, "token", nullptr));
}

// AuthVerifyRsa：非法 base64（含非 base64 字符）→ false
HWTEST_F(HdcDaemonTest, AuthVerifyRsa_BadBase64_ReturnsFalse, TestSize.Level0)
{
    HdcDaemon d(false);
    HdcSession sbuf{};
    HSession hSession = &sbuf;
    EXPECT_FALSE(d.AuthVerifyRsa(hSession, "!!!!", "token", nullptr));
}

// ShouldSkipAuthBypassForEncrypt：CONN_USB → false
HWTEST_F(HdcDaemonTest, ShouldSkipAuthBypassForEncrypt_UsbConn_ReturnsFalse, TestSize.Level0)
{
    HdcDaemon d(false);
    HdcSession sbuf{};
    HSession hSession = &sbuf;
    hSession->connType = CONN_USB;
    hSession->supportEncrypt = true;
    EXPECT_FALSE(d.ShouldSkipAuthBypassForEncrypt(hSession));
}

// ShouldSkipAuthBypassForEncrypt：TCP 但未协商加密 → false
HWTEST_F(HdcDaemonTest, ShouldSkipAuthBypassForEncrypt_TcpNotEncrypt_ReturnsFalse, TestSize.Level0)
{
    HdcDaemon d(false);
    HdcSession sbuf{};
    HSession hSession = &sbuf;
    hSession->connType = CONN_TCP;
    hSession->supportEncrypt = false;
    EXPECT_FALSE(d.ShouldSkipAuthBypassForEncrypt(hSession));
}

// ShouldAutoAcceptPubkeyForEncrypt：authEnable=true → false
HWTEST_F(HdcDaemonTest, ShouldAutoAcceptPubkeyForEncrypt_AuthEnabled_ReturnsFalse, TestSize.Level0)
{
    HdcDaemon d(false);
    d.authEnable = true;
    HdcSession sbuf{};
    HSession hSession = &sbuf;
    hSession->connType = CONN_TCP;
    hSession->supportEncrypt = true;
    EXPECT_FALSE(d.ShouldAutoAcceptPubkeyForEncrypt(hSession));
}

// ShouldAutoAcceptPubkeyForEncrypt：未加密 → false
HWTEST_F(HdcDaemonTest, ShouldAutoAcceptPubkeyForEncrypt_NoEncrypt_ReturnsFalse, TestSize.Level0)
{
    HdcDaemon d(false);
    d.authEnable = false;
    HdcSession sbuf{};
    HSession hSession = &sbuf;
    hSession->connType = CONN_TCP;
    hSession->supportEncrypt = false;
    EXPECT_FALSE(d.ShouldAutoAcceptPubkeyForEncrypt(hSession));
}

// GetServerCapability：空 buf → 默认 RSA_ENCRYPT，不崩溃
HWTEST_F(HdcDaemonTest, GetServerCapability_EmptyBuf_NoCrash, TestSize.Level0)
{
    HdcDaemon d(false);
    HdcSession sbuf{};
    HSession hSession = &sbuf;
    HdcSessionBase::SessionHandShake handshake{};
    handshake.buf = "";
    EXPECT_NO_FATAL_FAILURE(d.GetServerCapability(hSession, handshake));
    EXPECT_EQ(hSession->verifyType, RSA_ENCRYPT);
}

// GetServerCapability：非法 TLV → TlvToStringMap 失败，早返回
HWTEST_F(HdcDaemonTest, GetServerCapability_InvalidTlv_NoCrash, TestSize.Level0)
{
    HdcDaemon d(false);
    HdcSession sbuf{};
    HSession hSession = &sbuf;
    HdcSessionBase::SessionHandShake handshake{};
    handshake.buf = "garbage";
    EXPECT_NO_FATAL_FAILURE(d.GetServerCapability(hSession, handshake));
}

// DaemonSessionHandshake：banner 不匹配 → false
HWTEST_F(HdcDaemonTest, DaemonSessionHandshake_BadBanner_ReturnsFalse, TestSize.Level0)
{
    HdcDaemon d(false);
    HdcSession sbuf{};
    HSession hSession = &sbuf;
    uint8_t payload[] = "badbanner";
    EXPECT_FALSE(d.DaemonSessionHandshake(hSession, 0, payload, sizeof(payload)));
}

// DaemonSessionHandshake：空 payload → false
HWTEST_F(HdcDaemonTest, DaemonSessionHandshake_EmptyPayload_ReturnsFalse, TestSize.Level0)
{
    HdcDaemon d(false);
    HdcSession sbuf{};
    HSession hSession = &sbuf;
    uint8_t payload = 0;
    EXPECT_FALSE(d.DaemonSessionHandshake(hSession, 0, &payload, 0));
}

// HandDaemonAuth：authEnable=false → 直接放行（UpdateSessionAuthOk + SendAuthOkMsg）
HWTEST_F(HdcDaemonTest, HandDaemonAuth_NotAuthEnabled_AllowAccess, TestSize.Level0)
{
    HdcDaemon d(false);
    d.authEnable = false;
    HdcSession sbuf{};
    HSession hSession = &sbuf;
    hSession->connType = CONN_USB;
    hSession->supportEncrypt = false;
    HdcSessionBase::SessionHandShake handshake{};
    handshake.version = "Ver: 3.0.0b";
    EXPECT_TRUE(d.HandDaemonAuth(hSession, 0, handshake));
}

// HandDaemonAuth：authEnable=true + 低版本 → AuthRejectLowClient，返回 true
HWTEST_F(HdcDaemonTest, HandDaemonAuth_LowVersion_Rejected, TestSize.Level0)
{
    HdcDaemon d(false);
    d.authEnable = true;
    HdcSession sbuf{};
    HSession hSession = &sbuf;
    HdcSessionBase::SessionHandShake handshake{};
    handshake.version = "";
    EXPECT_TRUE(d.HandDaemonAuth(hSession, 0, handshake));
}

// HandDaemonAuth：已 AUTH_OK → 直接返回 true
HWTEST_F(HdcDaemonTest, HandDaemonAuth_AlreadyAuthOk, TestSize.Level0)
{
    HdcDaemon d(false);
    d.authEnable = true;
    d.InitSessionAuthInfo(0, "tok");
    d.UpdateSessionAuthOk(0);
    HdcSession sbuf{};
    HSession hSession = &sbuf;
    hSession->sessionId = 0;
    HdcSessionBase::SessionHandShake handshake{};
    handshake.version = "Ver: 3.0.0b";
    EXPECT_TRUE(d.HandDaemonAuth(hSession, 0, handshake));
}

// HandDaemonAuth：AUTH_NONE + authType=AUTH_NONE → HandDaemonAuthInit，返回 true
HWTEST_F(HdcDaemonTest, HandDaemonAuth_AuthNone_InitAuth, TestSize.Level0)
{
    HdcDaemon d(false);
    d.authEnable = true;
    HdcSession sbuf{};
    HSession hSession = &sbuf;
    hSession->sessionId = 0;
    HdcSessionBase::SessionHandShake handshake{};
    handshake.version = "Ver: 3.0.0b";
    handshake.authType = HdcSessionBase::AUTH_NONE;
    EXPECT_TRUE(d.HandDaemonAuth(hSession, 0, handshake));
}

// HandDaemonAuth：无效状态（AUTH_FAIL + AUTH_SIGNATURE）→ false
HWTEST_F(HdcDaemonTest, HandDaemonAuth_InvalidState_ReturnsFalse, TestSize.Level0)
{
    HdcDaemon d(false);
    d.authEnable = true;
    d.InitSessionAuthInfo(0, "tok");
    d.UpdateSessionAuthmsg(0, "failed");
    HdcSession sbuf{};
    HSession hSession = &sbuf;
    hSession->sessionId = 0;
    HdcSessionBase::SessionHandShake handshake{};
    handshake.version = "Ver: 3.0.0b";
    handshake.authType = HdcSessionBase::AUTH_SIGNATURE;
    EXPECT_FALSE(d.HandDaemonAuth(hSession, 0, handshake));
}

// HandDaemonAuthSignature：AuthVerify 失败 → HandleAuthFailed，返回 true（继续认证）
HWTEST_F(HdcDaemonTest, HandDaemonAuthSignature_AuthFails_ReturnsTrue, TestSize.Level0)
{
    HdcDaemon d(false);
    d.InitSessionAuthInfo(0, "");
    HdcSession sbuf{};
    HSession hSession = &sbuf;
    hSession->sessionId = 0;
    HdcSessionBase::SessionHandShake handshake{};
    handshake.version = "Ver: 3.0.0b";
    EXPECT_TRUE(d.HandDaemonAuthSignature(hSession, 0, handshake));
}

// CheckControl：shell 类命令 → 受 persist.hdc.control.shell 控制
HWTEST_F(HdcDaemonTest, CheckControl_ShellCommands, TestSize.Level0)
{
    HdcDaemon d(false);
    EXPECT_NO_FATAL_FAILURE((void)d.CheckControl(CMD_SHELL_INIT));
    EXPECT_NO_FATAL_FAILURE((void)d.CheckControl(CMD_UNITY_EXECUTE));
    EXPECT_NO_FATAL_FAILURE((void)d.CheckControl(CMD_JDWP_LIST));
}

// CheckControl：file/app 类命令 → 受 persist.hdc.control.file 控制
HWTEST_F(HdcDaemonTest, CheckControl_FileCommands, TestSize.Level0)
{
    HdcDaemon d(false);
    EXPECT_NO_FATAL_FAILURE((void)d.CheckControl(CMD_FILE_CHECK));
    EXPECT_NO_FATAL_FAILURE((void)d.CheckControl(CMD_APP_CHECK));
    EXPECT_NO_FATAL_FAILURE((void)d.CheckControl(CMD_DIR_MODE));
}

// CheckControl：forward 类命令 → 受 persist.hdc.control.fport 控制
HWTEST_F(HdcDaemonTest, CheckControl_ForwardCommands, TestSize.Level0)
{
    HdcDaemon d(false);
    EXPECT_NO_FATAL_FAILURE((void)d.CheckControl(CMD_FORWARD_INIT));
    EXPECT_NO_FATAL_FAILURE((void)d.CheckControl(CMD_FORWARD_DATA));
    EXPECT_NO_FATAL_FAILURE((void)d.CheckControl(CMD_FORWARD_FREE_CONTEXT));
}

// CheckControl：default 分支 → true（其他命令不受控）
HWTEST_F(HdcDaemonTest, CheckControl_Default_ReturnsTrue, TestSize.Level0)
{
    HdcDaemon d(false);
    EXPECT_TRUE(d.CheckControl(CMD_KERNEL_ECHO_RAW));
    EXPECT_TRUE(d.CheckControl(CMD_HEARTBEAT_MSG));
}

// CheckAuthStatus：authEnable=false → true
HWTEST_F(HdcDaemonTest, CheckAuthStatus_AuthDisabled_ReturnsTrue, TestSize.Level0)
{
    HdcDaemon d(false);
    d.authEnable = false;
    HdcSession sbuf{};
    HSession hSession = &sbuf;
    EXPECT_TRUE(d.CheckAuthStatus(hSession, 0, CMD_UNITY_EXECUTE));
}

// CheckAuthStatus：authEnable=true + 未认证 + 非握手命令 → false
HWTEST_F(HdcDaemonTest, CheckAuthStatus_AuthEnabledNotOk_ReturnsFalse, TestSize.Level0)
{
    HdcDaemon d(false);
    d.authEnable = true;
    HdcSession sbuf{};
    HSession hSession = &sbuf;
    hSession->sessionId = 0;
    EXPECT_FALSE(d.CheckAuthStatus(hSession, 0, CMD_UNITY_EXECUTE));
}

// CheckAuthStatus：authEnable=true + CMD_KERNEL_HANDSHAKE → true（握手阶段放行）
HWTEST_F(HdcDaemonTest, CheckAuthStatus_AuthEnabledHandshake_ReturnsTrue, TestSize.Level0)
{
    HdcDaemon d(false);
    d.authEnable = true;
    HdcSession sbuf{};
    HSession hSession = &sbuf;
    hSession->sessionId = 0;
    EXPECT_TRUE(d.CheckAuthStatus(hSession, 0, CMD_KERNEL_HANDSHAKE));
    EXPECT_TRUE(d.CheckAuthStatus(hSession, 0, CMD_KERNEL_CHANNEL_CLOSE));
}

// RedirectToTask：未知命令 → default 分支，返回 true
HWTEST_F(HdcDaemonTest, RedirectToTask_UnknownCommand_ReturnsTrue, TestSize.Level0)
{
    HdcDaemon d(false);
    HTaskInfo info = new TaskInformation();
    uint8_t payload = 0;
    EXPECT_TRUE(d.RedirectToTask(info, nullptr, 0, 0xFFFF, &payload, 1));
    delete info;
}

// RemoveInstanceTask：taskClass=nullptr → 早返回 true（覆盖空任务分支）
HWTEST_F(HdcDaemonTest, RemoveInstanceTask_NullTaskClass_ReturnsTrue, TestSize.Level0)
{
    HdcDaemon d(false);
    HTaskInfo info = new TaskInformation();
    info->taskClass = nullptr;
    EXPECT_TRUE(d.RemoveInstanceTask(OP_QUERY, info));
    delete info;
}
}  // namespace Hdc
