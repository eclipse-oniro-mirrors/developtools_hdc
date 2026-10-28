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
#include <gtest/gtest.h>
#include <new>

#include "session.h"
#include "define_plus.h"

using namespace testing::ext;
using namespace testing;

namespace Hdc {
class SessionBaseTest : public ::testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    HdcSessionBase *sessionBase = nullptr;
};

void SessionBaseTest::SetUpTestCase() {}
void SessionBaseTest::TearDownTestCase() {}
void SessionBaseTest::SetUp()
{
    sessionBase = new HdcSessionBase(false);
}
void SessionBaseTest::TearDown()
{
    delete sessionBase;
    sessionBase = nullptr;
}

HWTEST_F(SessionBaseTest, BuildCtrlString_CopyData, TestSize.Level0) {
    uint8_t data[4] = { 1, 2, 3, 4 };
    vector<uint8_t> ret = HdcSessionBase::BuildCtrlString(static_cast<InnerCtrlCommand>(CMD_KERNEL_ECHO), 0x1234,
                                                          data, sizeof(data));
    EXPECT_EQ(ret.size(), sizeof(HdcSessionBase::CtrlStruct));
    HdcSessionBase::CtrlStruct *ctrl = reinterpret_cast<HdcSessionBase::CtrlStruct *>(ret.data());
    EXPECT_EQ(ctrl->command, static_cast<InnerCtrlCommand>(CMD_KERNEL_ECHO));
    EXPECT_EQ(ctrl->channelId, 0x1234);
    EXPECT_EQ(ctrl->dataSize, sizeof(data));
    EXPECT_EQ(ctrl->data[0], 1);
    EXPECT_EQ(ctrl->data[3], 4);
}

HWTEST_F(SessionBaseTest, BuildCtrlString_ZeroData, TestSize.Level0) {
    vector<uint8_t> ret = HdcSessionBase::BuildCtrlString(SP_START_SESSION, 0, nullptr, 0);
    EXPECT_EQ(ret.size(), sizeof(HdcSessionBase::CtrlStruct));
    HdcSessionBase::CtrlStruct *ctrl = reinterpret_cast<HdcSessionBase::CtrlStruct *>(ret.data());
    EXPECT_EQ(ctrl->command, SP_START_SESSION);
    EXPECT_EQ(ctrl->channelId, 0);
    EXPECT_EQ(ctrl->dataSize, 0);
    for (int i = 0; i < BUF_SIZE_MICRO; ++i) {
        EXPECT_EQ(ctrl->data[i], 0);
    }
}

HWTEST_F(SessionBaseTest, BuildCtrlString_DataSizeExceed, TestSize.Level0) {
    uint8_t data[BUF_SIZE_MICRO + 1] = { 0 };
    vector<uint8_t> ret = HdcSessionBase::BuildCtrlString(SP_STOP_SESSION, 0, data, sizeof(data));
    EXPECT_TRUE(ret.empty());
}

HWTEST_F(SessionBaseTest, BuildCtrlString_NullDataWithSize, TestSize.Level0) {
    vector<uint8_t> ret = HdcSessionBase::BuildCtrlString(SP_ATTACH_CHANNEL, 5, nullptr, 4);
    EXPECT_EQ(ret.size(), sizeof(HdcSessionBase::CtrlStruct));
    HdcSessionBase::CtrlStruct *ctrl = reinterpret_cast<HdcSessionBase::CtrlStruct *>(ret.data());
    EXPECT_EQ(ctrl->command, SP_ATTACH_CHANNEL);
    EXPECT_EQ(ctrl->channelId, 5);
    EXPECT_EQ(ctrl->dataSize, 4);
    for (int i = 0; i < BUF_SIZE_MICRO; ++i) {
        EXPECT_EQ(ctrl->data[i], 0);
    }
}

HWTEST_F(SessionBaseTest, NeedNewTaskInfo_ServerMasterTask, TestSize.Level0) {
    HdcSessionBase *server = new HdcSessionBase(true);
    bool masterTask = false;
    EXPECT_TRUE(server->NeedNewTaskInfo(CMD_FILE_INIT, masterTask));
    EXPECT_TRUE(masterTask);
    EXPECT_TRUE(server->NeedNewTaskInfo(CMD_FORWARD_INIT, masterTask));
    EXPECT_TRUE(masterTask);
    EXPECT_TRUE(server->NeedNewTaskInfo(CMD_APP_INIT, masterTask));
    EXPECT_TRUE(masterTask);
    EXPECT_TRUE(server->NeedNewTaskInfo(CMD_FLASHD_UPDATE_INIT, masterTask));
    EXPECT_TRUE(masterTask);
    EXPECT_TRUE(server->NeedNewTaskInfo(CMD_FLASHD_FLASH_INIT, masterTask));
    EXPECT_TRUE(masterTask);
    EXPECT_TRUE(server->NeedNewTaskInfo(CMD_FLASHD_ERASE, masterTask));
    EXPECT_TRUE(masterTask);
    EXPECT_TRUE(server->NeedNewTaskInfo(CMD_FLASHD_FORMAT, masterTask));
    EXPECT_TRUE(masterTask);
    EXPECT_TRUE(server->NeedNewTaskInfo(CMD_APP_UNINSTALL, masterTask));
    EXPECT_TRUE(masterTask);
    EXPECT_TRUE(server->NeedNewTaskInfo(CMD_APP_SIDELOAD, masterTask));
    EXPECT_TRUE(masterTask);
    delete server;
}

HWTEST_F(SessionBaseTest, NeedNewTaskInfo_ServerCommon, TestSize.Level0) {
    HdcSessionBase *server = new HdcSessionBase(true);
    bool masterTask = true;
    EXPECT_TRUE(server->NeedNewTaskInfo(CMD_KERNEL_WAKEUP_SLAVETASK, masterTask));
    EXPECT_FALSE(masterTask);
    EXPECT_TRUE(server->NeedNewTaskInfo(CMD_UNITY_BUGREPORT_INIT, masterTask));
    EXPECT_FALSE(masterTask);
    EXPECT_FALSE(server->NeedNewTaskInfo(CMD_KERNEL_HANDSHAKE, masterTask));
    EXPECT_FALSE(server->NeedNewTaskInfo(CMD_SHELL_INIT, masterTask));
    delete server;
}

HWTEST_F(SessionBaseTest, NeedNewTaskInfo_Daemon, TestSize.Level0) {
    bool masterTask = true;
    EXPECT_TRUE(sessionBase->NeedNewTaskInfo(CMD_SHELL_INIT, masterTask));
    EXPECT_FALSE(masterTask);
    EXPECT_TRUE(sessionBase->NeedNewTaskInfo(CMD_UNITY_EXECUTE, masterTask));
    EXPECT_FALSE(masterTask);
    EXPECT_TRUE(sessionBase->NeedNewTaskInfo(CMD_UNITY_EXECUTE_EX, masterTask));
    EXPECT_FALSE(masterTask);
    EXPECT_FALSE(sessionBase->NeedNewTaskInfo(CMD_KERNEL_HANDSHAKE, masterTask));
}

HWTEST_F(SessionBaseTest, GetOs_KnownValue, TestSize.Level0) {
    std::string os = sessionBase->GetOs();
    EXPECT_TRUE(os == "win" || os == "linux" || os == "mac" || os == "oh" || os.empty());
}

HWTEST_F(SessionBaseTest, SetFeature_WithHeartbeat, TestSize.Level0) {
    bool savedSwitch = Base::g_heartbeatSwitch;
    Base::g_heartbeatSwitch = true;
    HdcSessionBase::SessionHandShake handshake = {};
    sessionBase->SetFeature(handshake, CONN_USB);
    EXPECT_TRUE(handshake.buf.find(TAG_SUPPORT_FEATURE) != std::string::npos);
    EXPECT_TRUE(handshake.buf.find(conTypeDetail[CONN_USB]) != std::string::npos);
    EXPECT_TRUE(handshake.buf.find(FEATURE_HEARTBEAT) != std::string::npos);
    Base::g_heartbeatSwitch = savedSwitch;
}

HWTEST_F(SessionBaseTest, SetFeature_WithoutHeartbeat, TestSize.Level0) {
    bool savedSwitch = Base::g_heartbeatSwitch;
    Base::g_heartbeatSwitch = false;
    HdcSessionBase::SessionHandShake handshake = {};
    sessionBase->SetFeature(handshake, CONN_UNKNOWN);
    EXPECT_TRUE(handshake.buf.find(TAG_SUPPORT_FEATURE) != std::string::npos);
    EXPECT_TRUE(handshake.buf.find(conTypeDetail[CONN_UNKNOWN]) != std::string::npos);
    EXPECT_TRUE(handshake.buf.find(FEATURE_HEARTBEAT) == std::string::npos);
    Base::g_heartbeatSwitch = savedSwitch;
}

HWTEST_F(SessionBaseTest, WorkThreadInitSession_NotCheck, TestSize.Level0) {
    HSession hSession = new HdcSession();
    hSession->sessionId = 0x1111;
    hSession->connectKey = "key1111";
    hSession->isCheck = false;
    hSession->connType = CONN_USB;
    hSession->classInstance = sessionBase;
    HdcSessionBase::SessionHandShake handshake = {};
    sessionBase->WorkThreadInitSession(hSession, handshake);
    EXPECT_EQ(handshake.banner, HANDSHAKE_MESSAGE);
    EXPECT_EQ(handshake.sessionId, 0x1111);
    EXPECT_EQ(handshake.connectKey, "key1111");
    EXPECT_EQ(handshake.authType, HdcSessionBase::AUTH_NONE);
    EXPECT_EQ(handshake.version, Base::GetVersion() + "TEST");
    EXPECT_TRUE(handshake.buf.find(TAG_AUTH_TYPE) != std::string::npos);
    delete hSession;
}

HWTEST_F(SessionBaseTest, WorkThreadInitSession_Check, TestSize.Level0) {
    HSession hSession = new HdcSession();
    hSession->sessionId = 0x2222;
    hSession->isCheck = true;
    hSession->connType = CONN_USB;
    hSession->classInstance = sessionBase;
    HdcSessionBase::SessionHandShake handshake = {};
    sessionBase->WorkThreadInitSession(hSession, handshake);
    EXPECT_EQ(handshake.banner, HANDSHAKE_MESSAGE);
    EXPECT_EQ(handshake.sessionId, 0x2222);
    EXPECT_TRUE(handshake.version.empty());
    EXPECT_TRUE(handshake.buf.find(TAG_AUTH_TYPE) != std::string::npos);
    delete hSession;
}

HWTEST_F(SessionBaseTest, ParsePeerSupportFeatures_WithHeartbeat, TestSize.Level0) {
    HSession hSession = new HdcSession();
    std::map<std::string, std::string> tlvMap;
    tlvMap[TAG_SUPPORT_FEATURE] = std::string("heartbeat,encrypt_tcp,conn_validation");
    HdcSessionBase::ParsePeerSupportFeatures(hSession, tlvMap);
    EXPECT_TRUE(hSession->heartbeat.GetSupportHeartbeat());
    delete hSession;
}

HWTEST_F(SessionBaseTest, ParsePeerSupportFeatures_WithoutHeartbeat, TestSize.Level0) {
    HSession hSession = new HdcSession();
    std::map<std::string, std::string> tlvMap;
    tlvMap[TAG_SUPPORT_FEATURE] = std::string("encrypt_tcp,conn_validation");
    HdcSessionBase::ParsePeerSupportFeatures(hSession, tlvMap);
    EXPECT_FALSE(hSession->heartbeat.GetSupportHeartbeat());
    delete hSession;
}

HWTEST_F(SessionBaseTest, ParsePeerSupportFeatures_NullSession, TestSize.Level0) {
    HSession hSession = nullptr;
    std::map<std::string, std::string> tlvMap;
    tlvMap[TAG_SUPPORT_FEATURE] = std::string("heartbeat");
    HdcSessionBase::ParsePeerSupportFeatures(hSession, tlvMap);
    EXPECT_EQ(hSession, nullptr);
}

HWTEST_F(SessionBaseTest, AdminSession_AllOps, TestSize.Level0) {
    HSession hSession = new HdcSession();
    hSession->sessionId = 0x3333;
    sessionBase->AdminSession(OP_ADD, 0x3333, hSession);
    EXPECT_EQ(sessionBase->AdminSession(OP_QUERY, 0x3333, nullptr), hSession);
    EXPECT_EQ(sessionBase->AdminSession(OP_QUERY, 0x9999, nullptr), nullptr);
    HSession queried = sessionBase->AdminSession(OP_QUERY_REF, 0x3333, nullptr);
    EXPECT_EQ(queried, hSession);
    EXPECT_EQ(queried->ref.load(), 1);
    hSession->sessionId = 0x4444;
    sessionBase->AdminSession(OP_UPDATE, 0x3333, hSession);
    EXPECT_EQ(sessionBase->AdminSession(OP_QUERY, 0x3333, nullptr), nullptr);
    EXPECT_EQ(sessionBase->AdminSession(OP_QUERY, 0x4444, nullptr), hSession);
    sessionBase->AdminSession(OP_REMOVE, 0x4444, nullptr);
    EXPECT_EQ(sessionBase->AdminSession(OP_QUERY, 0x4444, nullptr), nullptr);
    EXPECT_EQ(sessionBase->AdminSession(OP_VOTE_RESET, 0x4444, nullptr), nullptr);
    EXPECT_EQ(sessionBase->AdminSession(OP_PRINT, 0x4444, nullptr), nullptr);
    delete hSession;
}

HWTEST_F(SessionBaseTest, AdminTask_AllOps, TestSize.Level0) {
    HSession hSession = new HdcSession();
    hSession->sessionId = 0x5555;
    hSession->mapTask = new std::map<uint32_t, HTaskInfo>();
    HTaskInfo task1 = new TaskInformation();
    task1->channelId = 0x10;
    HTaskInfo task2 = new TaskInformation();
    task2->channelId = 0x10;
    EXPECT_EQ(sessionBase->AdminTask(OP_ADD, hSession, 0x10, task1), task1);
    EXPECT_EQ(hSession->mapTask->size(), 1);
    EXPECT_EQ(sessionBase->AdminTask(OP_QUERY, hSession, 0x10, nullptr), task1);
    EXPECT_EQ(sessionBase->AdminTask(OP_ADD, hSession, 0x10, task2), task2);
    EXPECT_EQ(hSession->mapTask->size(), 1);
    EXPECT_EQ(sessionBase->AdminTask(OP_QUERY, hSession, 0x10, nullptr), task2);
    EXPECT_EQ(sessionBase->AdminTask(OP_QUERY, hSession, 0x20, nullptr), nullptr);
    sessionBase->AdminTask(OP_REMOVE, hSession, 0x10, nullptr);
    EXPECT_EQ(hSession->mapTask->size(), 0);
    EXPECT_EQ(sessionBase->AdminTask(OP_QUERY, hSession, 0x10, nullptr), nullptr);
    delete hSession->mapTask;
    hSession->mapTask = nullptr;
    delete hSession;
}

HWTEST_F(SessionBaseTest, SendByProtocol_DeadSession, TestSize.Level0) {
    HSession hSession = new HdcSession();
    hSession->isDead = true;
    uint8_t *buf = new uint8_t[4]();
    EXPECT_EQ(sessionBase->SendByProtocol(hSession, buf, 4), ERR_SESSION_NOFOUND);
    delete hSession;
}

HWTEST_F(SessionBaseTest, SendByProtocol_NullModule, TestSize.Level0) {
    HSession hSession = new HdcSession();
    hSession->isDead = false;
    hSession->classModule = nullptr;
    uint8_t *buf = new uint8_t[4]();
    EXPECT_EQ(sessionBase->SendByProtocol(hSession, buf, 4), ERR_SESSION_NOFOUND);
    delete hSession;
}

HWTEST_F(SessionBaseTest, SendByProtocol_DefaultConnType, TestSize.Level0) {
    HSession hSession = new HdcSession();
    hSession->isDead = false;
    hSession->connType = CONN_BT;
    hSession->classModule = reinterpret_cast<void *>(1);
    uint8_t *buf = new uint8_t[4]();
    EXPECT_EQ(sessionBase->SendByProtocol(hSession, buf, 4), ERR_GENERIC);
    delete hSession;
}

HWTEST_F(SessionBaseTest, Send_NoSession, TestSize.Level0) {
    EXPECT_EQ(sessionBase->Send(0x7FFFFFF0, 1, CMD_KERNEL_ECHO, nullptr, 0), ERR_SESSION_NOFOUND);
}

HWTEST_F(SessionBaseTest, DispatchMainThreadCommand_AttachDetachOnDaemon, TestSize.Level0) {
    HSession hSession = new HdcSession();
    HdcSessionBase::CtrlStruct ctrl = {};
    ctrl.channelId = 7;
    ctrl.command = SP_ATTACH_CHANNEL;
    EXPECT_TRUE(sessionBase->DispatchMainThreadCommand(hSession, &ctrl));
    ctrl.command = SP_DEATCH_CHANNEL;
    EXPECT_TRUE(sessionBase->DispatchMainThreadCommand(hSession, &ctrl));
    ctrl.command = static_cast<InnerCtrlCommand>(0xFF);
    EXPECT_FALSE(sessionBase->DispatchMainThreadCommand(hSession, &ctrl));
    delete hSession;
}

HWTEST_F(SessionBaseTest, DispatchMainThreadCommand_AttachOnServer, TestSize.Level0) {
    HdcSessionBase *server = new HdcSessionBase(true);
    HSession hSession = new HdcSession();
    HdcSessionBase::CtrlStruct ctrl = {};
    ctrl.channelId = 8;
    ctrl.command = SP_ATTACH_CHANNEL;
    EXPECT_TRUE(server->DispatchMainThreadCommand(hSession, &ctrl));
    ctrl.command = SP_DEATCH_CHANNEL;
    EXPECT_TRUE(server->DispatchMainThreadCommand(hSession, &ctrl));
    delete hSession;
    delete server;
}

HWTEST_F(SessionBaseTest, MallocSessionByConnectType_Tcp, TestSize.Level0) {
    HSession hSession = new HdcSession();
    hSession->connType = CONN_TCP;
    EXPECT_EQ(sessionBase->MallocSessionByConnectType(hSession), 0);
    EXPECT_EQ(hSession->uvHandleRef, 1);
    EXPECT_EQ(hSession->hWorkTCP.data, hSession);
    delete hSession;
}

HWTEST_F(SessionBaseTest, MallocSessionByConnectType_Usb, TestSize.Level0) {
    HSession hSession = new HdcSession();
    hSession->connType = CONN_USB;
    EXPECT_EQ(sessionBase->MallocSessionByConnectType(hSession), 0);
    EXPECT_NE(hSession->hUSB, nullptr);
    EXPECT_EQ(hSession->hUSB->wMaxPacketSizeSend, MAX_PACKET_SIZE_HISPEED);
    delete hSession;
}

HWTEST_F(SessionBaseTest, MallocSessionByConnectType_Unknown, TestSize.Level0) {
    HSession hSession = new HdcSession();
    hSession->connType = CONN_BT;
    EXPECT_EQ(sessionBase->MallocSessionByConnectType(hSession), -1);
    delete hSession;
}

HWTEST_F(SessionBaseTest, MallocSession_Usb, TestSize.Level0) {
    HSession hSession = sessionBase->MallocSession(false, CONN_USB, nullptr, 0x1234);
    EXPECT_NE(hSession, nullptr);
    EXPECT_EQ(hSession->sessionId, 0x1234);
    EXPECT_EQ(hSession->connType, CONN_USB);
    EXPECT_EQ(hSession->classInstance, sessionBase);
    EXPECT_NE(hSession->mapTask, nullptr);
    EXPECT_NE(hSession->hUSB, nullptr);
    EXPECT_EQ(sessionBase->AdminSession(OP_QUERY, 0x1234, nullptr), hSession);
    sessionBase->AdminSession(OP_REMOVE, 0x1234, nullptr);
    delete hSession;
}

HWTEST_F(SessionBaseTest, MallocSession_SessionIdZero, TestSize.Level0) {
    HSession hSession = sessionBase->MallocSession(false, CONN_USB, nullptr, 0);
    EXPECT_NE(hSession, nullptr);
    EXPECT_NE(hSession->sessionId, 0);
    sessionBase->AdminSession(OP_REMOVE, hSession->sessionId, nullptr);
    delete hSession;
}

HWTEST_F(SessionBaseTest, MallocSession_UnknownConnType, TestSize.Level0) {
    HSession hSession = sessionBase->MallocSession(false, CONN_BT, nullptr, 0x5678);
    EXPECT_EQ(hSession, nullptr);
}

HWTEST_F(SessionBaseTest, PushAsyncMessage_NoData, TestSize.Level0) {
    sessionBase->PushAsyncMessage(0x11, ASYNC_STOP_MAINLOOP, nullptr, 0);
    ASSERT_EQ(sessionBase->lstMainThreadOP.size(), 1);
    AsyncParam *param = static_cast<AsyncParam *>(sessionBase->lstMainThreadOP.front());
    EXPECT_EQ(param->sid, 0x11);
    EXPECT_EQ(param->method, ASYNC_STOP_MAINLOOP);
}

HWTEST_F(SessionBaseTest, PushAsyncMessage_WithData, TestSize.Level0) {
    uint8_t data[3] = { 0xAA, 0xBB, 0xCC };
    sessionBase->PushAsyncMessage(0x22, 0x99, data, sizeof(data));
    ASSERT_EQ(sessionBase->lstMainThreadOP.size(), 1);
    AsyncParam *param = static_cast<AsyncParam *>(sessionBase->lstMainThreadOP.front());
    EXPECT_EQ(param->sid, 0x22);
    EXPECT_EQ(param->method, 0x99);
    EXPECT_EQ(param->dataSize, 3);
    uint8_t *payload = static_cast<uint8_t *>(param->data);
    EXPECT_EQ(payload[0], 0xAA);
    EXPECT_EQ(payload[1], 0xBB);
    EXPECT_EQ(payload[2], 0xCC);
}

HWTEST_F(SessionBaseTest, PostStopInstanceMessage_WantRestart, TestSize.Level0) {
    EXPECT_FALSE(sessionBase->WantRestart());
    sessionBase->PostStopInstanceMessage(true);
    EXPECT_TRUE(sessionBase->WantRestart());
    ASSERT_EQ(sessionBase->lstMainThreadOP.size(), 1);
    AsyncParam *param = static_cast<AsyncParam *>(sessionBase->lstMainThreadOP.front());
    EXPECT_EQ(param->sid, 0);
    EXPECT_EQ(param->method, ASYNC_STOP_MAINLOOP);
}
}  // namespace Hdc
