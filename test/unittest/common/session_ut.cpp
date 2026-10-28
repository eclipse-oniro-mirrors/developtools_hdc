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
#include <gmock/gmock.h>
#include <new>
#include <string>

#include "session.h"
#include "define_plus.h"

using namespace testing::ext;
using namespace testing;

namespace Hdc {
namespace {
int g_enumUsbCallbackCount = 0;
EnumCallbackResult TestEnumUsbCallback(HSession hSession)
{
    ++g_enumUsbCallbackCount;
    EnumCallbackResult result;
    result.sessionId = hSession->sessionId;
    result.classInstance = reinterpret_cast<HdcSessionBase *>(hSession->classInstance);
    result.needFreeSession = false;
    return result;
}
}  // namespace
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

HWTEST_F(SessionBaseTest, TryRemoveTask_AlreadyFree, TestSize.Level0) {
    HTaskInfo hTask = new TaskInformation();
    hTask->taskFree = true;
    EXPECT_TRUE(sessionBase->TryRemoveTask(hTask));
    delete hTask;
}

HWTEST_F(SessionBaseTest, TryRemoveTask_RemoveSuccess, TestSize.Level0) {
    HTaskInfo hTask = new TaskInformation();
    hTask->taskFree = false;
    EXPECT_TRUE(sessionBase->TryRemoveTask(hTask));
    EXPECT_TRUE(hTask->taskFree);
    delete hTask;
}

HWTEST_F(SessionBaseTest, GetSessionPseudoUid_NotRegistered, TestSize.Level0) {
    uint32_t uid = sessionBase->GetSessionPseudoUid();
    EXPECT_EQ(sessionBase->AdminSession(OP_QUERY, uid, nullptr), nullptr);
}

HWTEST_F(SessionBaseTest, BeginRemoveTask_NullTask, TestSize.Level0) {
    EXPECT_NO_FATAL_FAILURE(sessionBase->BeginRemoveTask(nullptr));
}

HWTEST_F(SessionBaseTest, BeginRemoveTask_AlreadyStop, TestSize.Level0) {
    HTaskInfo hTask = new TaskInformation();
    hTask->taskStop = true;
    hTask->taskFree = false;
    sessionBase->BeginRemoveTask(hTask);
    EXPECT_TRUE(hTask->taskStop);
    EXPECT_FALSE(hTask->taskFree);
    delete hTask;
}

HWTEST_F(SessionBaseTest, BeginRemoveTask_AlreadyFree, TestSize.Level0) {
    HTaskInfo hTask = new TaskInformation();
    hTask->taskStop = false;
    hTask->taskFree = true;
    sessionBase->BeginRemoveTask(hTask);
    EXPECT_FALSE(hTask->taskStop);
    EXPECT_TRUE(hTask->taskFree);
    delete hTask;
}

HWTEST_F(SessionBaseTest, ClearOwnTasks_SingleTask, TestSize.Level0) {
    HSession hSession = new HdcSession();
    hSession->sessionId = 0xAAAA;
    hSession->mapTask = new std::map<uint32_t, HTaskInfo>();
    HTaskInfo task1 = new TaskInformation();
    task1->channelId = 0x100;
    task1->taskStop = true;
    HTaskInfo task2 = new TaskInformation();
    task2->channelId = 0x200;
    task2->taskStop = true;
    (*hSession->mapTask)[0x100] = task1;
    (*hSession->mapTask)[0x200] = task2;

    sessionBase->ClearOwnTasks(hSession, 0x200);

    EXPECT_EQ(hSession->mapTask->size(), 1u);
    EXPECT_NE(hSession->mapTask->find(0x100), hSession->mapTask->end());
    EXPECT_EQ(hSession->mapTask->find(0x200), hSession->mapTask->end());
    delete task1;
    delete task2;
    delete hSession;
}

HWTEST_F(SessionBaseTest, ClearOwnTasks_MultiTask, TestSize.Level0) {
    HSession hSession = new HdcSession();
    hSession->sessionId = 0xBBBB;
    hSession->mapTask = new std::map<uint32_t, HTaskInfo>();
    HTaskInfo task1 = new TaskInformation();
    task1->channelId = 0x300;
    task1->taskStop = true;
    HTaskInfo task2 = new TaskInformation();
    task2->channelId = 0x400;
    task2->taskStop = true;
    (*hSession->mapTask)[0x300] = task1;
    (*hSession->mapTask)[0x400] = task2;

    sessionBase->ClearOwnTasks(hSession, 0);

    EXPECT_EQ(hSession->mapTask->size(), 0u);
    delete task1;
    delete task2;
    delete hSession;
}

HWTEST_F(SessionBaseTest, QueryUSBDeviceRegister_NonHost, TestSize.Level0) {
    EXPECT_EQ(sessionBase->QueryUSBDeviceRegister(nullptr, 0, 0), nullptr);
}

HWTEST_F(SessionBaseTest, EnumUSBDeviceRegister_NullCallback, TestSize.Level0) {
    EXPECT_NO_FATAL_FAILURE(sessionBase->EnumUSBDeviceRegister(nullptr));
}

HWTEST_F(SessionBaseTest, EnumUSBDeviceRegister_EmptySessionMap, TestSize.Level0) {
    g_enumUsbCallbackCount = 0;
    sessionBase->EnumUSBDeviceRegister(TestEnumUsbCallback);
    EXPECT_EQ(g_enumUsbCallbackCount, 0);
}

HWTEST_F(SessionBaseTest, EnumUSBDeviceRegister_FilterNonUsb, TestSize.Level0) {
    HSession hSession = new HdcSession();
    hSession->sessionId = 0xC001;
    hSession->connType = CONN_TCP;
    sessionBase->AdminSession(OP_ADD, 0xC001, hSession);

    g_enumUsbCallbackCount = 0;
    sessionBase->EnumUSBDeviceRegister(TestEnumUsbCallback);
    EXPECT_EQ(g_enumUsbCallbackCount, 0);

    sessionBase->AdminSession(OP_REMOVE, 0xC001, nullptr);
    delete hSession;
}

HWTEST_F(SessionBaseTest, EnumUSBDeviceRegister_FilterNullUsb, TestSize.Level0) {
    HSession hSession = new HdcSession();
    hSession->sessionId = 0xC002;
    hSession->connType = CONN_USB;
    hSession->hUSB = nullptr;
    sessionBase->AdminSession(OP_ADD, 0xC002, hSession);

    g_enumUsbCallbackCount = 0;
    sessionBase->EnumUSBDeviceRegister(TestEnumUsbCallback);
    EXPECT_EQ(g_enumUsbCallbackCount, 0);

    sessionBase->AdminSession(OP_REMOVE, 0xC002, nullptr);
    delete hSession;
}

HWTEST_F(SessionBaseTest, EnumUSBDeviceRegister_InvokeCallback, TestSize.Level0) {
    HSession hSession = new HdcSession();
    hSession->sessionId = 0xC003;
    hSession->connType = CONN_USB;
    hSession->hUSB = new HdcUSB();
    hSession->classInstance = sessionBase;
    sessionBase->AdminSession(OP_ADD, 0xC003, hSession);

    g_enumUsbCallbackCount = 0;
    sessionBase->EnumUSBDeviceRegister(TestEnumUsbCallback);
    EXPECT_EQ(g_enumUsbCallbackCount, 1);

    sessionBase->AdminSession(OP_REMOVE, 0xC003, nullptr);
    delete hSession->hUSB;
    hSession->hUSB = nullptr;
    delete hSession;
}

class HdcSessionBaseTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HdcSessionBaseTest::SetUpTestCase() {}
void HdcSessionBaseTest::TearDownTestCase() {}
void HdcSessionBaseTest::SetUp() {}
void HdcSessionBaseTest::TearDown() {}

// 构造/析构：daemon 模式、1 线程，不崩溃（构造启动 uv loop，析构清理）
HWTEST_F(HdcSessionBaseTest, ConstructorDaemon_NoCrash, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(HdcSessionBase s(false, 1));
}

// AdminSession：查询不存在的 sessionId → 返回 nullptr（覆盖 OP_QUERY 未命中分支）
HWTEST_F(HdcSessionBaseTest, AdminSession_QueryUnknown_ReturnsNull, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    EXPECT_EQ(s.AdminSession(OP_QUERY, 99999, nullptr), nullptr);
}

#ifdef HDC_HOST
// PrintAllSessionConnection：无会话时不崩溃（空遍历分支）
HWTEST_F(HdcSessionBaseTest, PrintAllSessionConnection_NoSession_NoCrash, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    EXPECT_NO_FATAL_FAILURE(s.PrintAllSessionConnection(99999));
}
#endif

// ClearSessions：初始无会话，不崩溃
HWTEST_F(HdcSessionBaseTest, ClearSessions_Initial_NoCrash, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    EXPECT_NO_FATAL_FAILURE(s.ClearSessions());
}

// WantRestart：初始返回 false
HWTEST_F(HdcSessionBaseTest, WantRestart_Initial_False, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    EXPECT_FALSE(s.WantRestart());
}

// FreeSession：不存在的 sessionId 不崩溃
HWTEST_F(HdcSessionBaseTest, FreeSession_Unknown_NoCrash, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    EXPECT_NO_FATAL_FAILURE(s.FreeSession(99999));
}

// gmock 子类：用于打桩 HdcSessionBase 的 virtual 方法
class MockSession : public HdcSessionBase {
public:
    MockSession(bool srv, size_t n) : HdcSessionBase(srv, n) {}
    MOCK_METHOD2(RemoveInstanceTask, bool(const uint8_t, HTaskInfo));
    MOCK_METHOD6(RedirectToTask, bool(HTaskInfo, HSession, const uint32_t, const uint16_t, uint8_t *, const int));
    MOCK_METHOD5(FetchCommand, bool(HSession, const uint32_t, const uint16_t, uint8_t *, int));
    MOCK_METHOD5(ServerCommand, bool(const uint32_t, const uint32_t, const uint16_t, uint8_t *, const int));
    MOCK_METHOD2(NotifyInstanceSessionFree, void(HSession, bool));
    MOCK_METHOD0(OnUSBDisconnectExit, void());
};

// EnumUSBDeviceRegister 回调桩
static EnumCallbackResult DummyEnumCb(HSession) { return EnumCallbackResult{}; }

// 与 HdcSessionBase::PayloadHead（protected）布局一致的本地结构，便于构造测试包
struct UtPayloadHead {
    uint8_t flag[2];
    uint8_t reserve[2];
    uint8_t protocolVer;
    uint16_t headSize;
    uint32_t dataSize;
} __attribute__((packed));

// 构造：server 模式，不崩溃（host 侧 libusb_init，需 HDC_HOST）
HWTEST_F(HdcSessionBaseTest, Ctor_Server_NoCrash, TestSize.Level0)
{
#ifdef HDC_HOST
    ASSERT_NO_FATAL_FAILURE(HdcSessionBase s(true, 1));
#else
    GTEST_SUCCEED();
#endif
}

// 构造：线程数超上限被钳到 SIZE_THREAD_POOL_MAX，不崩溃
HWTEST_F(HdcSessionBaseTest, Ctor_ThreadPoolClampedMax_NoCrash, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(HdcSessionBase s(false, 99999));
}

// AdminSession：OP_ADD 后 OP_QUERY 命中
HWTEST_F(HdcSessionBaseTest, AdminSession_AddAndQuery, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    HdcSession hs;
    hs.sessionId = 100;
    s.AdminSession(OP_ADD, 100, &hs);
    EXPECT_EQ(s.AdminSession(OP_QUERY, 100, nullptr), &hs);
    s.AdminSession(OP_REMOVE, 100, nullptr);
}

// AdminSession：OP_REMOVE 后 OP_QUERY 未命中
HWTEST_F(HdcSessionBaseTest, AdminSession_Remove, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    HdcSession hs;
    s.AdminSession(OP_ADD, 200, &hs);
    s.AdminSession(OP_REMOVE, 200, nullptr);
    EXPECT_EQ(s.AdminSession(OP_QUERY, 200, nullptr), nullptr);
}

// AdminSession：OP_QUERY_REF 未知 sessionId → null
HWTEST_F(HdcSessionBaseTest, AdminSession_QueryRefUnknown, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    EXPECT_EQ(s.AdminSession(OP_QUERY_REF, 8888, nullptr), nullptr);
}

// AdminSession：OP_QUERY_REF 命中并自增 ref
HWTEST_F(HdcSessionBaseTest, AdminSession_QueryRefKnown, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    HdcSession hs;
    hs.sessionId = 300;
    s.AdminSession(OP_ADD, 300, &hs);
    EXPECT_EQ(s.AdminSession(OP_QUERY_REF, 300, nullptr), &hs);
    EXPECT_EQ(uint32_t(hs.ref), 1u);
    s.AdminSession(OP_REMOVE, 300, nullptr);
}

// AdminSession：OP_UPDATE 用新 session 替换旧 session
HWTEST_F(HdcSessionBaseTest, AdminSession_Update, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    HdcSession old;
    old.sessionId = 400;
    HdcSession now;
    now.sessionId = 401;
    s.AdminSession(OP_ADD, 400, &old);
    s.AdminSession(OP_UPDATE, 400, &now);
    EXPECT_EQ(s.AdminSession(OP_QUERY, 401, nullptr), &now);
    EXPECT_EQ(s.AdminSession(OP_QUERY, 400, nullptr), nullptr);
}

// AdminSession：OP_PRINT（host 侧 PrintSession 空表），不崩溃
HWTEST_F(HdcSessionBaseTest, AdminSession_Print_NoCrash, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    EXPECT_EQ(s.AdminSession(OP_PRINT, 99999, nullptr), nullptr);
}

// AdminSession：OP_VOTE_RESET 未知 sessionId → 跳过 VoteReset，返回 null（不 abort）
HWTEST_F(HdcSessionBaseTest, AdminSession_VoteResetUnknown, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    EXPECT_EQ(s.AdminSession(OP_VOTE_RESET, 7777, nullptr), nullptr);
}

// AdminSession：未覆盖的 op（OP_GET_STRLIST）走 default，返回 null
HWTEST_F(HdcSessionBaseTest, AdminSession_DefaultOp, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    EXPECT_EQ(s.AdminSession(OP_GET_STRLIST, 1, nullptr), nullptr);
}

// Send：未知 sessionId → ERR_SESSION_NOFOUND
HWTEST_F(HdcSessionBaseTest, Send_NoSession, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    uint8_t d[] = {1, 2};
    EXPECT_EQ(s.Send(6666, 0, CMD_KERNEL_ECHO, d, 2), ERR_SESSION_NOFOUND);
}

// SendByProtocol：isDead → 删 buf 并返回 ERR_SESSION_NOFOUND
HWTEST_F(HdcSessionBaseTest, SendByProtocol_DeadSession, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    HdcSession hs;
    hs.isDead = true;
    uint8_t *buf = new uint8_t[4]{1, 2, 3, 4};
    EXPECT_EQ(s.SendByProtocol(&hs, buf, 4), ERR_SESSION_NOFOUND);
}

// SendByProtocol：classModule 为 null → ERR_SESSION_NOFOUND
HWTEST_F(HdcSessionBaseTest, SendByProtocol_NullClassModule, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    HdcSession hs;
    hs.isDead = false;
    hs.classModule = nullptr;
    uint8_t *buf = new uint8_t[4]{1, 2, 3, 4};
    EXPECT_EQ(s.SendByProtocol(&hs, buf, 4), ERR_SESSION_NOFOUND);
}

// SendByProtocol：未知 connType → default 分支返回 ERR_GENERIC
HWTEST_F(HdcSessionBaseTest, SendByProtocol_DefaultConnType, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    HdcSession hs;
    hs.isDead = false;
    int dummy = 0;
    hs.classModule = &dummy;
    hs.connType = CONN_UNKNOWN;
    uint8_t *buf = new uint8_t[4]{1, 2, 3, 4};
    EXPECT_EQ(s.SendByProtocol(&hs, buf, 4), ERR_GENERIC);
}

// OnRead：包头 magic 错误 → ERR_BUF_CHECK
HWTEST_F(HdcSessionBaseTest, OnRead_BadFlag, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    uint8_t buf[32] = {0};
    buf[0] = 'X';
    buf[1] = 'W';
    HdcSession hs;
    EXPECT_EQ(s.OnRead(&hs, buf, sizeof(buf)), ERR_BUF_CHECK);
}

// OnRead：payloadHeadSize==0 → ERR_BUF_CHECK
HWTEST_F(HdcSessionBaseTest, OnRead_ZeroPayloadSize, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    uint8_t buf[32] = {0};
    buf[0] = 'H';
    buf[1] = 'W';
    HdcSession hs;
    EXPECT_EQ(s.OnRead(&hs, buf, sizeof(buf)), ERR_BUF_CHECK);
}

// OnRead：payloadHeadSize 超过 HDC_BUF_MAX_BYTES → ERR_BUF_CHECK
HWTEST_F(HdcSessionBaseTest, OnRead_Oversize, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    uint8_t buf[32] = {0};
    buf[0] = 'H';
    buf[1] = 'W';
    auto *ph = reinterpret_cast<UtPayloadHead *>(buf);
    ph->headSize = htons(1);
    ph->dataSize = htonl(0x7FFFFFFF);  // INT_MAX，加 headSize 后溢出
    HdcSession hs;
    EXPECT_EQ(s.OnRead(&hs, buf, sizeof(buf)), ERR_BUF_CHECK);
}

// OnRead：数据不足一整包 → 返回 0（等待更多数据）
HWTEST_F(HdcSessionBaseTest, OnRead_PartialPacket, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    uint8_t buf[32] = {0};
    buf[0] = 'H';
    buf[1] = 'W';
    auto *ph = reinterpret_cast<UtPayloadHead *>(buf);
    ph->headSize = htons(10);
    ph->dataSize = htonl(0);
    int packetHeadSize = sizeof(UtPayloadHead);
    int bufLen = packetHeadSize + 5;  // 不足 10 字节载荷
    HdcSession hs;
    EXPECT_EQ(s.OnRead(&hs, buf, bufLen), 0);
}

// FetchIOBuf：read<0 → ERR_IO_FAIL
HWTEST_F(HdcSessionBaseTest, FetchIOBuf_NegativeRead, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    HdcSession hs;
    hs.classInstance = &s;
    uint8_t ioBuf[16] = {0};
    EXPECT_EQ(s.FetchIOBuf(&hs, ioBuf, -1), ERR_IO_FAIL);
}

// FetchIOBuf：read=0 且无缓冲数据 → 返回 0
HWTEST_F(HdcSessionBaseTest, FetchIOBuf_NormalEmpty, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    HdcSession hs;
    hs.classInstance = &s;
    uint8_t ioBuf[16] = {0};
    EXPECT_EQ(s.FetchIOBuf(&hs, ioBuf, 0), 0);
}

// FetchIOBuf(isEncrypt=true)：classSSL 为 null → ERR_GENERIC（需 HDC_SUPPORT_ENCRYPT_TCP）
HWTEST_F(HdcSessionBaseTest, FetchIOBuf_EncryptedTrue, TestSize.Level0)
{
#ifdef HDC_SUPPORT_ENCRYPT_TCP
    HdcSessionBase s(false, 1);
    HdcSession hs;
    hs.classInstance = &s;
    hs.classSSL = nullptr;
    uint8_t ioBuf[16] = {0};
    EXPECT_EQ(s.FetchIOBuf(&hs, ioBuf, 0, true), ERR_GENERIC);
#else
    GTEST_SUCCEED();
#endif
}

// FetchIOBuf(isEncrypt=false)：委托给三参重载，read=0 → 0（需 HDC_SUPPORT_ENCRYPT_TCP）
HWTEST_F(HdcSessionBaseTest, FetchIOBuf_EncryptedFalse, TestSize.Level0)
{
#ifdef HDC_SUPPORT_ENCRYPT_TCP
    HdcSessionBase s(false, 1);
    HdcSession hs;
    hs.classInstance = &s;
    uint8_t ioBuf[16] = {0};
    EXPECT_EQ(s.FetchIOBuf(&hs, ioBuf, 0, false), 0);
#else
    GTEST_SUCCEED();
#endif
}

// DispatchSessionThreadCommand：SP_JDWP_NEWFD → 走 JdwpNewFileDescriptor（no-op）
HWTEST_F(HdcSessionBaseTest, DispatchSessionThreadCommand_JdwpNewFd, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    uint8_t b = SP_JDWP_NEWFD;
    EXPECT_TRUE(s.DispatchSessionThreadCommand(&b, 1));
}

// DispatchSessionThreadCommand：SP_ARK_NEWFD
HWTEST_F(HdcSessionBaseTest, DispatchSessionThreadCommand_ArkNewFd, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    uint8_t b = SP_ARK_NEWFD;
    EXPECT_TRUE(s.DispatchSessionThreadCommand(&b, 1));
}

// DispatchSessionThreadCommand：未知 flag → default 分支，返回 true
HWTEST_F(HdcSessionBaseTest, DispatchSessionThreadCommand_Default, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    uint8_t b = 0xFE;
    EXPECT_TRUE(s.DispatchSessionThreadCommand(&b, 1));
}

// DispatchMainThreadCommand：SP_ATTACH_CHANNEL，daemon 侧 → break，返回 true
HWTEST_F(HdcSessionBaseTest, DispatchMainThreadCommand_AttachChannel_Daemon, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    HdcSession hs;
    HdcSessionBase::CtrlStruct ctrl = {};
    ctrl.command = SP_ATTACH_CHANNEL;
    ctrl.channelId = 1;
    EXPECT_TRUE(s.DispatchMainThreadCommand(&hs, &ctrl));
}

// DispatchMainThreadCommand：SP_ATTACH_CHANNEL，server 侧 → AttachChannel（no-op）
HWTEST_F(HdcSessionBaseTest, DispatchMainThreadCommand_AttachChannel_Server, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    s.serverOrDaemon = true;  // 避免 server 构造触发 libusb_init
    HdcSession hs;
    HdcSessionBase::CtrlStruct ctrl = {};
    ctrl.command = SP_ATTACH_CHANNEL;
    ctrl.channelId = 1;
    EXPECT_TRUE(s.DispatchMainThreadCommand(&hs, &ctrl));
}

// DispatchMainThreadCommand：SP_DEATCH_CHANNEL，daemon 侧 → break
HWTEST_F(HdcSessionBaseTest, DispatchMainThreadCommand_DetachChannel_Daemon, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    HdcSession hs;
    HdcSessionBase::CtrlStruct ctrl = {};
    ctrl.command = SP_DEATCH_CHANNEL;
    ctrl.channelId = 1;
    EXPECT_TRUE(s.DispatchMainThreadCommand(&hs, &ctrl));
}

// DispatchMainThreadCommand：SP_DEATCH_CHANNEL，server 侧 → DetachChannel（no-op）
HWTEST_F(HdcSessionBaseTest, DispatchMainThreadCommand_DetachChannel_Server, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    s.serverOrDaemon = true;  // 避免 server 构造触发 libusb_init
    HdcSession hs;
    HdcSessionBase::CtrlStruct ctrl = {};
    ctrl.command = SP_DEATCH_CHANNEL;
    ctrl.channelId = 1;
    EXPECT_TRUE(s.DispatchMainThreadCommand(&hs, &ctrl));
}

// DispatchMainThreadCommand：未知 command → default，返回 false
HWTEST_F(HdcSessionBaseTest, DispatchMainThreadCommand_Default, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    HdcSession hs;
    HdcSessionBase::CtrlStruct ctrl = {};
    ctrl.command = static_cast<InnerCtrlCommand>(0xFE);
    EXPECT_FALSE(s.DispatchMainThreadCommand(&hs, &ctrl));
}

// SetFeature：connType=CONN_USB，buf 非空
HWTEST_F(HdcSessionBaseTest, SetFeature_ConnUsb, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    HdcSessionBase::SessionHandShake hs;
    s.SetFeature(hs, CONN_USB);
    EXPECT_FALSE(hs.buf.empty());
}

// SetFeature：connType=CONN_TCP
HWTEST_F(HdcSessionBaseTest, SetFeature_ConnTcp, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    HdcSessionBase::SessionHandShake hs;
    s.SetFeature(hs, CONN_TCP);
    EXPECT_FALSE(hs.buf.empty());
}

// SetFeature：connType=CONN_UNKNOWN
HWTEST_F(HdcSessionBaseTest, SetFeature_ConnUnknown, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    HdcSessionBase::SessionHandShake hs;
    s.SetFeature(hs, CONN_UNKNOWN);
    EXPECT_FALSE(hs.buf.empty());
}

// SetFeature：connType 超过 CONN_UNKNOWN → 取 CONN_UNKNOWN
HWTEST_F(HdcSessionBaseTest, SetFeature_ConnExceeds, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    HdcSessionBase::SessionHandShake hs;
    s.SetFeature(hs, 255);
    EXPECT_FALSE(hs.buf.empty());
}

// SetFeature：开启心跳开关 → feature 含 FEATURE_HEARTBEAT
HWTEST_F(HdcSessionBaseTest, SetFeature_WithHeartbeat, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    Base::g_heartbeatSwitch = true;
    HdcSessionBase::SessionHandShake hs;
    s.SetFeature(hs, CONN_TCP);
    Base::g_heartbeatSwitch = false;
    EXPECT_FALSE(hs.buf.empty());
}

// WorkThreadInitSession：isCheck=false → version 带 hash
HWTEST_F(HdcSessionBaseTest, WorkThreadInitSession_Normal, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    HdcSession hs;
    hs.classInstance = &s;
    hs.sessionId = 123;
    HdcSessionBase::SessionHandShake shake;
    s.WorkThreadInitSession(&hs, shake);
    EXPECT_EQ(shake.banner, HANDSHAKE_MESSAGE);
    EXPECT_EQ(shake.sessionId, 123u);
    EXPECT_FALSE(shake.version.empty());
}

// WorkThreadInitSession：isCheck=true → version 不设置
HWTEST_F(HdcSessionBaseTest, WorkThreadInitSession_IsCheck, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    HdcSession hs;
    hs.classInstance = &s;
    hs.isCheck = true;
    HdcSessionBase::SessionHandShake shake;
    s.WorkThreadInitSession(&hs, shake);
    EXPECT_TRUE(shake.version.empty());
}

// NeedNewTaskInfo：daemon 侧 CMD_SHELL_INIT → true
HWTEST_F(HdcSessionBaseTest, NeedNewTaskInfo_ShellInitDaemon, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    bool master = false;
    EXPECT_TRUE(s.NeedNewTaskInfo(CMD_SHELL_INIT, master));
    EXPECT_FALSE(master);
}

// NeedNewTaskInfo：CMD_KERNEL_WAKEUP_SLAVETASK → true
HWTEST_F(HdcSessionBaseTest, NeedNewTaskInfo_WakeupSlave, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    bool master = false;
    EXPECT_TRUE(s.NeedNewTaskInfo(CMD_KERNEL_WAKEUP_SLAVETASK, master));
    EXPECT_FALSE(master);
}

// NeedNewTaskInfo：CMD_FILE_INIT → true 且 masterTask=true
HWTEST_F(HdcSessionBaseTest, NeedNewTaskInfo_FileInitMaster, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    bool master = false;
    EXPECT_TRUE(s.NeedNewTaskInfo(CMD_FILE_INIT, master));
    EXPECT_TRUE(master);
}

// NeedNewTaskInfo：未知 command → false
HWTEST_F(HdcSessionBaseTest, NeedNewTaskInfo_Default, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    bool master = false;
    EXPECT_FALSE(s.NeedNewTaskInfo(CMD_KERNEL_HELP, master));
    EXPECT_FALSE(master);
}

// GetOs：返回非空平台串
HWTEST_F(HdcSessionBaseTest, GetOs_NonEmpty, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    EXPECT_FALSE(s.GetOs().empty());
}

// GetSessionPseudoUid：两次调用均非 0
HWTEST_F(HdcSessionBaseTest, GetSessionPseudoUid_NonZero, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    EXPECT_NE(s.GetSessionPseudoUid(), 0u);
    EXPECT_NE(s.GetSessionPseudoUid(), 0u);
}

// BuildCtrlString：正常数据 → 返回 sizeof(CtrlStruct)
HWTEST_F(HdcSessionBaseTest, BuildCtrlString_Normal, TestSize.Level0)
{
    uint8_t d[] = {1, 2, 3};
    auto v = HdcSessionBase::BuildCtrlString(SP_START_SESSION, 1, d, 3);
    EXPECT_EQ(v.size(), sizeof(HdcSessionBase::CtrlStruct));
}

// BuildCtrlString：dataSize=0 → 返回 sizeof(CtrlStruct)
HWTEST_F(HdcSessionBaseTest, BuildCtrlString_DataSizeZero, TestSize.Level0)
{
    auto v = HdcSessionBase::BuildCtrlString(SP_START_SESSION, 1, nullptr, 0);
    EXPECT_EQ(v.size(), sizeof(HdcSessionBase::CtrlStruct));
}

// BuildCtrlString：dataSize 超过 BUF_SIZE_MICRO → 空 vector
HWTEST_F(HdcSessionBaseTest, BuildCtrlString_DataSizeExceeds, TestSize.Level0)
{
    auto v = HdcSessionBase::BuildCtrlString(SP_START_SESSION, 1, nullptr, BUF_SIZE_MICRO + 1);
    EXPECT_TRUE(v.empty());
}

// TryRemoveTask：taskFree=true → 直接返回 true
HWTEST_F(HdcSessionBaseTest, TryRemoveTask_AlreadyFree, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    TaskInformation t{};
    t.taskFree = true;
    EXPECT_TRUE(s.TryRemoveTask(&t));
}

// TryRemoveTask：RemoveInstanceTask 默认返回 true → 置 taskFree 并返回 true
HWTEST_F(HdcSessionBaseTest, TryRemoveTask_RemoveInstanceTrue, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    TaskInformation t{};
    EXPECT_TRUE(s.TryRemoveTask(&t));
    EXPECT_TRUE(t.taskFree);
}

// TryRemoveTask：RemoveInstanceTask 返回 false → 返回 false，taskFree 不变
HWTEST_F(HdcSessionBaseTest, TryRemoveTask_RemoveInstanceFalse, TestSize.Level0)
{
    MockSession s(false, 1);
    EXPECT_CALL(s, RemoveInstanceTask).WillOnce(Return(false));
    TaskInformation t{};
    EXPECT_FALSE(s.TryRemoveTask(&t));
    EXPECT_FALSE(t.taskFree);
}

// BeginRemoveTask：null hTask → 早返回
HWTEST_F(HdcSessionBaseTest, BeginRemoveTask_Null, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    EXPECT_NO_FATAL_FAILURE(s.BeginRemoveTask(nullptr));
}

// BeginRemoveTask：taskFree=true → 早返回
HWTEST_F(HdcSessionBaseTest, BeginRemoveTask_TaskFree, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    TaskInformation t{};
    t.taskFree = true;
    EXPECT_NO_FATAL_FAILURE(s.BeginRemoveTask(&t));
}

// BeginRemoveTask：taskStop=true → 早返回
HWTEST_F(HdcSessionBaseTest, BeginRemoveTask_TaskStop, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    TaskInformation t{};
    t.taskStop = true;
    EXPECT_NO_FATAL_FAILURE(s.BeginRemoveTask(&t));
}

// ClearOwnTasks：空 mapTask，channelIDInput=0 → 无操作
HWTEST_F(HdcSessionBaseTest, ClearOwnTasks_NoTasks, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    HdcSession hs;
    hs.mapTask = new map<uint32_t, HTaskInfo>();
    EXPECT_NO_FATAL_FAILURE(s.ClearOwnTasks(&hs, 0));
    // mapTask 由 HdcSession 析构释放
}

// ClearOwnTasks：空 mapTask，channelIDInput 非零未命中 → 无操作
HWTEST_F(HdcSessionBaseTest, ClearOwnTasks_SingleChannelNotFound, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    HdcSession hs;
    hs.mapTask = new map<uint32_t, HTaskInfo>();
    EXPECT_NO_FATAL_FAILURE(s.ClearOwnTasks(&hs, 5));
}

// AdminTask：OP_ADD 后 OP_QUERY 命中
HWTEST_F(HdcSessionBaseTest, AdminTask_AddAndQuery, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    HdcSession hs;
    hs.mapTask = new map<uint32_t, HTaskInfo>();
    TaskInformation t{};
    EXPECT_EQ(s.AdminTask(OP_ADD, &hs, 100, &t), &t);
    EXPECT_EQ(s.AdminTask(OP_QUERY, &hs, 100, nullptr), &t);
    s.AdminTask(OP_REMOVE, &hs, 100, nullptr);
}

// AdminTask：OP_REMOVE 后 OP_QUERY 未命中
HWTEST_F(HdcSessionBaseTest, AdminTask_Remove, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    HdcSession hs;
    hs.mapTask = new map<uint32_t, HTaskInfo>();
    TaskInformation t{};
    s.AdminTask(OP_ADD, &hs, 100, &t);
    s.AdminTask(OP_REMOVE, &hs, 100, nullptr);
    EXPECT_EQ(s.AdminTask(OP_QUERY, &hs, 100, nullptr), nullptr);
}

// AdminTask：OP_VOTE_RESET → 转发 AdminSession（未知 sid 返回 null）
HWTEST_F(HdcSessionBaseTest, AdminTask_VoteReset, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    HdcSession hs;
    hs.mapTask = new map<uint32_t, HTaskInfo>();
    EXPECT_EQ(s.AdminTask(OP_VOTE_RESET, &hs, 0, nullptr), nullptr);
}

// AdminTask：未知 op → default，返回 null
HWTEST_F(HdcSessionBaseTest, AdminTask_Default, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    HdcSession hs;
    hs.mapTask = new map<uint32_t, HTaskInfo>();
    EXPECT_EQ(s.AdminTask(OP_CLEAR, &hs, 0, nullptr), nullptr);
}

// FreeSessionByConnectType：CONN_USB 且 hUSB 为 null → 早返回
HWTEST_F(HdcSessionBaseTest, FreeSessionByConnectType_UsbNullHUSB, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    HdcSession hs;
    hs.connType = CONN_USB;
    hs.hUSB = nullptr;
    EXPECT_NO_FATAL_FAILURE(s.FreeSessionByConnectType(&hs));
}

// FreeSessionByConnectType：CONN_TCP → 无 USB/UART 分支，直接结束
HWTEST_F(HdcSessionBaseTest, FreeSessionByConnectType_Tcp, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    HdcSession hs;
    hs.connType = CONN_TCP;
    EXPECT_NO_FATAL_FAILURE(s.FreeSessionByConnectType(&hs));
}

// FreeSessionByConnectType：CONN_SERIAL 且 hUART 为 null → 早返回
HWTEST_F(HdcSessionBaseTest, FreeSessionByConnectType_SerialNullHUART, TestSize.Level0)
{
#ifdef HDC_SUPPORT_UART
    HdcSessionBase s(false, 1);
    HdcSession hs;
    hs.connType = CONN_SERIAL;
    hs.hUART = nullptr;
    EXPECT_NO_FATAL_FAILURE(s.FreeSessionByConnectType(&hs));
#else
    GTEST_SUCCEED();
#endif
}

// ParsePeerSupportFeatures：hSession 为 null → 早返回
HWTEST_F(HdcSessionBaseTest, ParsePeerSupportFeatures_NullSession, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    HSession hSession = nullptr;
    std::map<std::string, std::string> tlv;
    EXPECT_NO_FATAL_FAILURE(s.ParsePeerSupportFeatures(hSession, tlv));
}

// ParsePeerSupportFeatures：无 TAG_SUPPORT_FEATURE → 不修改
HWTEST_F(HdcSessionBaseTest, ParsePeerSupportFeatures_NoFeature, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    HdcSession hs;
    HSession hSession = &hs;
    std::map<std::string, std::string> tlv;
    EXPECT_NO_FATAL_FAILURE(s.ParsePeerSupportFeatures(hSession, tlv));
    EXPECT_FALSE(hs.heartbeat.GetSupportHeartbeat());
}

// ParsePeerSupportFeatures：含 heartbeat 特性 → SetSupportHeartbeat(true)
HWTEST_F(HdcSessionBaseTest, ParsePeerSupportFeatures_WithFeature, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    HdcSession hs;
    HSession hSession = &hs;
    std::map<std::string, std::string> tlv;
    tlv[TAG_SUPPORT_FEATURE] = FEATURE_HEARTBEAT;
    s.ParsePeerSupportFeatures(hSession, tlv);
    EXPECT_TRUE(hs.heartbeat.GetSupportHeartbeat());
}

// PostStopInstanceMessage：restart=true → wantRestart=true
HWTEST_F(HdcSessionBaseTest, PostStopInstanceMessage_Restart, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    s.PostStopInstanceMessage(true);
    EXPECT_TRUE(s.WantRestart());
}

// PostStopInstanceMessage：restart=false → wantRestart=false
HWTEST_F(HdcSessionBaseTest, PostStopInstanceMessage_NoRestart, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    s.PostStopInstanceMessage(false);
    EXPECT_FALSE(s.WantRestart());
}

// StopHeartbeatWork：心跳开关关闭 → 仅 SetSupportHeartbeat(false)
HWTEST_F(HdcSessionBaseTest, StopHeartbeatWork_SwitchOff, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    Base::g_heartbeatSwitch = false;
    HdcSession hs;
    EXPECT_NO_FATAL_FAILURE(s.StopHeartbeatWork(&hs));
    EXPECT_FALSE(hs.heartbeat.GetSupportHeartbeat());
}

// StartHeartbeatWork：心跳开关关闭 → 早返回
HWTEST_F(HdcSessionBaseTest, StartHeartbeatWork_SwitchOff, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    Base::g_heartbeatSwitch = false;
    HdcSession hs;
    EXPECT_NO_FATAL_FAILURE(s.StartHeartbeatWork(&hs));
}

// SendHeartbeatMsg：不支持心跳且未握手 → 直接返回
HWTEST_F(HdcSessionBaseTest, SendHeartbeatMsg_NotSupportNotHandshake, TestSize.Level0)
{
    HdcSession hs;
    uv_timer_t t;
    (void)memset_s(&t, sizeof(t), 0, sizeof(t));
    t.data = &hs;
    EXPECT_NO_FATAL_FAILURE(HdcSessionBase::SendHeartbeatMsg(&t));
}

// SendHeartbeatMsg：支持心跳但未握手 → 早返回
HWTEST_F(HdcSessionBaseTest, SendHeartbeatMsg_SupportNotHandshake, TestSize.Level0)
{
    HdcSession hs;
    hs.heartbeat.SetSupportHeartbeat(true);
    uv_timer_t t;
    (void)memset_s(&t, sizeof(t), 0, sizeof(t));
    t.data = &hs;
    EXPECT_NO_FATAL_FAILURE(HdcSessionBase::SendHeartbeatMsg(&t));
}

// LogMsg：格式化日志并经 ServerCommand（默认 true），不崩溃
HWTEST_F(HdcSessionBaseTest, LogMsg_NoCrash, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    EXPECT_NO_FATAL_FAILURE(s.LogMsg(0, 0, MSG_INFO, "ut msg %d", 42));
}

// QueryUSBDeviceRegister：空 mapSession → null（host 侧）
HWTEST_F(HdcSessionBaseTest, QueryUSBDeviceRegister_EmptyMap, TestSize.Level0)
{
#ifdef HDC_HOST
    HdcSessionBase s(false, 1);  // daemon 构造避免 libusb_init；空表早返回不依赖 libusb
    EXPECT_EQ(s.QueryUSBDeviceRegister(nullptr, 1, 2), nullptr);
#else
    GTEST_SUCCEED();
#endif
}

// EnumUSBDeviceRegister：null 回调 → 早返回
HWTEST_F(HdcSessionBaseTest, EnumUSBDeviceRegister_NullCallback, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    EXPECT_NO_FATAL_FAILURE(s.EnumUSBDeviceRegister(nullptr));
}

// EnumUSBDeviceRegister：空 mapSession + 回调 → 无调用
HWTEST_F(HdcSessionBaseTest, EnumUSBDeviceRegister_EmptyMap, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    EXPECT_NO_FATAL_FAILURE(s.EnumUSBDeviceRegister(DummyEnumCb));
}

// AllocCallback：零初始化 HSession，分配 ioBuf 不崩溃
HWTEST_F(HdcSessionBaseTest, AllocCallback_NoCrash, TestSize.Level0)
{
    HdcSession hs;
    uv_handle_t h;
    (void)memset_s(&h, sizeof(h), 0, sizeof(h));
    h.data = &hs;
    uv_buf_t buf = {};
    EXPECT_NO_FATAL_FAILURE(HdcSessionBase::AllocCallback(&h, 1024, &buf));
    EXPECT_NE(buf.base, nullptr);
    delete[] hs.ioBuf;
}

// PushAsyncMessage：无 data → 仅构造 AsyncParam，不崩溃
HWTEST_F(HdcSessionBaseTest, PushAsyncMessage_EmptyData, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    EXPECT_NO_FATAL_FAILURE(s.PushAsyncMessage(0, ASYNC_STOP_MAINLOOP, nullptr, 0));
}

// PushAsyncMessage：带 data → 拷贝，不崩溃
HWTEST_F(HdcSessionBaseTest, PushAsyncMessage_WithData, TestSize.Level0)
{
    HdcSessionBase s(false, 1);
    uint8_t d[] = {1, 2, 3};
    EXPECT_NO_FATAL_FAILURE(s.PushAsyncMessage(1, ASYNC_FREE_SESSION, d, 3));
}

}  // namespace Hdc
