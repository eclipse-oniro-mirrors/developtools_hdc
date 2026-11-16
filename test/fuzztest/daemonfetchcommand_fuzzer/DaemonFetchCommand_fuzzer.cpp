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

#include "DaemonFetchCommand_fuzzer.h"

#include <algorithm>
#include <list>
#include <map>
#include <new>
#include <string>
#include <vector>

#include <uv.h>

#include "serial_struct.h"

namespace Hdc {
namespace {
// Fuzz input layout. FetchCommand() is the daemon side entry point for every
// decoded packet, so the interesting dimensions are the command id, the channel
// and session identity, the handshake state and the payload bytes:
//   [0..1]  command     bit7 of [0] set -> raw uint16, otherwise CMD_TABLE index
//   [2..5]  channelId   uint32 LE
//   [6..9]  sessionId   uint32 LE, also used inside the structured handshake
//   [10]    flags       see FLAG_* below
//   [11]    hsAuthType  index into authTypes   (structured handshake)
//   [12]    hsVersion   index into BuildVersion (structured handshake)
//   [13]    hsBuf       index into BuildHsBuf   (structured handshake)
//   [14..15] reserved
//   [16..]  body        payload bytes
constexpr size_t CTRL_SIZE = 16;
constexpr size_t OFFSET_COMMAND = 0;
constexpr size_t OFFSET_CHANNEL_ID = 2;
constexpr size_t OFFSET_SESSION_ID = 6;
constexpr size_t OFFSET_FLAGS = 10;
constexpr size_t OFFSET_HS_AUTH_TYPE = 11;
constexpr size_t OFFSET_HS_VERSION = 12;
constexpr size_t OFFSET_HS_BUF = 13;
constexpr size_t MAX_PAYLOAD_SIZE = 64 * 1024;
constexpr uint8_t CMD_FLAG_RAW = 0x80;
constexpr uint8_t FLAG_AUTH_ENABLE = 0x01;
constexpr uint8_t FLAG_HANDSHAKE_OK = 0x02;
constexpr uint8_t FLAG_CONN_USB = 0x04;
constexpr uint8_t FLAG_STRUCTURED_HS = 0x08;
constexpr uint8_t FLAG_SUPPORT_CONN_VALIDATION = 0x10;
constexpr uint8_t FLAG_AUTH_STATE_OK = 0x20;
constexpr uint32_t SHIFT_BYTE = 8;
constexpr uint32_t SHIFT_WORD = 16;
constexpr uint32_t SHIFT_DWORD = 24;
constexpr uint32_t DEFAULT_SESSION_ID = 0x48444346;

using FuzzHandShake = HdcSessionBase::SessionHandShake;

// Every command FetchCommand() switches on or routes onward, plus values that
// must never arrive.
const uint16_t CMD_TABLE[] = {
    CMD_KERNEL_HANDSHAKE,      CMD_KERNEL_CHANNEL_CLOSE, CMD_HEARTBEAT_MSG,     CMD_SHELL_INIT,
    CMD_SHELL_DATA,            CMD_UNITY_EXECUTE,        CMD_UNITY_EXECUTE_EX,  CMD_UNITY_BUGREPORT_INIT,
    CMD_UNITY_BUGREPORT_DATA,  CMD_FILE_INIT,            CMD_FILE_DATA,         CMD_APP_CHECK,
    CMD_APP_UNINSTALL,         CMD_FORWARD_INIT,         CMD_FORWARD_DATA,      CMD_JDWP_LIST,
    CMD_SSL_HANDSHAKE,         0,                        0xFFFF,
};
constexpr size_t CMD_TABLE_COUNT = sizeof(CMD_TABLE) / sizeof(CMD_TABLE[0]);

const uint8_t AUTH_TYPES[] = {
    HdcSessionBase::AUTH_NONE,     HdcSessionBase::AUTH_TOKEN,   HdcSessionBase::AUTH_SIGNATURE,
    HdcSessionBase::AUTH_PUBLICKEY, HdcSessionBase::AUTH_OK,     HdcSessionBase::AUTH_FAIL,
    HdcSessionBase::AUTH_SSL_TLS_PSK, 0xFF,
};
constexpr size_t AUTH_TYPE_COUNT = sizeof(AUTH_TYPES) / sizeof(AUTH_TYPES[0]);

struct FuzzInput {
    uint16_t command;
    uint32_t channelId;
    uint32_t sessionId;
    uint8_t flags;
    uint8_t hsAuthType;
    uint8_t hsVersion;
    uint8_t hsBuf;
    const uint8_t *body;
    size_t bodySize;
};

// FetchCommand() is reached through HdcSessionBase::DecryptPayload(), so a real
// HdcDaemon is needed. Three overrides keep the harness off sockets, key files,
// RSA/HUKS and child processes.
class StubDaemon : public HdcDaemon {
public:
    StubDaemon() : HdcDaemon(false), stubSession(nullptr) {}
    ~StubDaemon() override = default;

    // Send() resolves the session with OP_QUERY_REF. Answering null makes every
    // outbound write stop at ERR_SESSION_NOFOUND before a stream is touched,
    // while OP_QUERY / OP_UPDATE keep working for the session bookkeeping.
    HSession AdminSession(const uint8_t op, const uint32_t sessionId, HSession hInput) override
    {
        if (op == OP_QUERY_REF) {
            return nullptr;
        }
        if (op == OP_QUERY && stubSession != nullptr && sessionId == stubSession->sessionId) {
            return stubSession;
        }
        return HdcDaemon::AdminSession(op, sessionId, hInput);
    }
    // The real RedirectToTask() constructs HdcShell / HdcFile / HdcDaemonForward
    // tasks, forks processes and opens files. Record the arguments instead; this
    // is also the oracle for a negative or out of range payload reaching a task.
    bool RedirectToTask(HTaskInfo hTaskInfo, HSession hSession, const uint32_t channelId, const uint16_t command,
                        uint8_t *payload, const int payloadSize) override
    {
        ++redirectCalls;
        lastCommand = command;
        lastPayloadSize = payloadSize;
        if (payloadSize < 0) {
            ++negativeSizeHits;
            return true;
        }
        if (payload != nullptr && payloadSize > 0) {
            if (payloadEnd != nullptr && payload + payloadSize > payloadEnd) {
                ++outOfRangeHits;
            }
            sink = payload[0];
            sink = payload[payloadSize - 1];
        }
        return true;
    }
    void FreeSession(const uint32_t sessionId) override {}

    HSession stubSession;
    const uint8_t *payloadEnd = nullptr;
    uint64_t redirectCalls = 0;
    uint64_t negativeSizeHits = 0;
    uint64_t outOfRangeHits = 0;
    uint16_t lastCommand = 0;
    int lastPayloadSize = 0;
    static volatile uint8_t sink;
};
volatile uint8_t StubDaemon::sink = 0;

struct FuzzEnv {
    StubDaemon *daemon;
    HSession session;
};

FuzzEnv *g_env = nullptr;

uint16_t ReadU16(const uint8_t *p)
{
    constexpr int zero = 0;
    constexpr int one = 1;
    return static_cast<uint16_t>(static_cast<uint16_t>(p[zero]) | (static_cast<uint16_t>(p[one]) << SHIFT_BYTE));
}

uint32_t ReadU32(const uint8_t *p)
{
    constexpr int zero = 0;
    constexpr int one = 1;
    constexpr int two = 2;
    constexpr int three = 3;
    return static_cast<uint32_t>(p[zero]) | (static_cast<uint32_t>(p[one]) << SHIFT_BYTE) |
           (static_cast<uint32_t>(p[two]) << SHIFT_WORD) | (static_cast<uint32_t>(p[three]) << SHIFT_DWORD);
}

void DecodeInput(const uint8_t *data, size_t size, FuzzInput &in)
{
    static const uint8_t emptyInput[1] = { 0 };
    if (data == nullptr) {
        data = emptyInput;
        size = 0;
    }
    uint8_t ctrl[CTRL_SIZE] = {};
    size_t ctrlLen = std::min(size, CTRL_SIZE);
    if (ctrlLen > 0) {
        (void)memcpy_s(ctrl, sizeof(ctrl), data, ctrlLen);
    }
    in.command = ((ctrl[OFFSET_COMMAND] & CMD_FLAG_RAW) != 0)
                     ? ReadU16(ctrl + OFFSET_COMMAND)
                     : CMD_TABLE[ctrl[OFFSET_COMMAND] % CMD_TABLE_COUNT];
    in.channelId = ReadU32(ctrl + OFFSET_CHANNEL_ID);
    in.sessionId = ReadU32(ctrl + OFFSET_SESSION_ID);
    in.flags = ctrl[OFFSET_FLAGS];
    in.hsAuthType = AUTH_TYPES[ctrl[OFFSET_HS_AUTH_TYPE] % AUTH_TYPE_COUNT];
    in.hsVersion = ctrl[OFFSET_HS_VERSION];
    in.hsBuf = ctrl[OFFSET_HS_BUF];
    in.body = data + ctrlLen;
    in.bodySize = std::min(size - ctrlLen, MAX_PAYLOAD_SIZE);
}

// HandDaemonAuth() compares handshake.version against "Ver: 3.0.0b" with plain
// operator< on std::string, so the ordering itself is part of the attack surface.
string BuildVersion(uint8_t sel)
{
    enum Item : uint8_t { ZERO = 0, ONE, TWO, THREE, FOUR };
    switch (sel) {
        case ZERO:
            return "";
        case ONE:
            return "Ver: 3.0.0b";
        case TWO:
            return "Ver: 3.0.0a";
        case THREE:
            // lexicographically smaller than "Ver: 3.0.0b" but a newer release
            return "Ver: 10.0.0a";
        case FOUR:
            // the value this build actually accepts at daemon.cpp:1066
            return Base::GetVersion() + HDC_MSG_HASH;
        default:
            return "Ver: 0.0.0z";
    }
}

string BuildHsBuf(uint8_t sel, const FuzzInput &in)
{
    enum Item : uint8_t { ZERO = 0, ONE, TWO };
    switch (sel) {
        case ZERO:
            return "";
        case ONE: {
            // well formed TLV, drives GetServerCapability() and ParsePeerSupportFeatures()
            string buf;
            Base::TlvAppend(buf, TAG_AUTH_TYPE, std::to_string(AuthVerifyType::RSA_3072_SHA512));
            return buf;
        }
        case TWO:
            // truncated TLV header, TlvToStringMap() must reject it
            return "ab";
        default:
            return string(reinterpret_cast<const char *>(in.body), in.bodySize);
    }
}

void BuildStructuredHandshake(const FuzzInput &in, std::vector<uint8_t> &out)
{
    FuzzHandShake handshake = {};
    handshake.banner = HANDSHAKE_MESSAGE;
    handshake.authType = in.hsAuthType;
    handshake.sessionId = in.sessionId;
    handshake.connectKey = "127.0.0.1:5555";
    handshake.version = BuildVersion(in.hsVersion);
    handshake.buf = BuildHsBuf(in.hsBuf, in);
    string enc = SerialStruct::SerializeToString(handshake);
    out.assign(enc.begin(), enc.end());
}

HSession BuildStubSession(StubDaemon *daemon)
{
    HSession session = new(std::nothrow) HdcSession();
    if (session == nullptr) {
        return nullptr;
    }
    session->classInstance = daemon;
    session->classModule = nullptr;
    session->connType = CONN_TCP;
    session->serverOrDaemon = false;
    session->sessionId = DEFAULT_SESSION_ID;
    session->isDead = false;
    session->childCleared = false;
    session->handshakeOK = false;
    session->stat.dataRecvBytes = 0;
    session->stat.dataSendBytes = 0;
    // ClearOwnTasks() and DispatchTaskData() -> AdminTask() need a real map.
    session->mapTask = new(std::nothrow) std::map<uint32_t, HTaskInfo>();
    session->listKey = new(std::nothrow) std::list<void *>();
    return session;
}

bool InitEnv()
{
    if (g_env != nullptr) {
        return true;
    }
    Base::SetLogLevel(LOG_OFF);
    StubDaemon *daemon = new(std::nothrow) StubDaemon();
    if (daemon == nullptr) {
        return false;
    }
    HSession session = BuildStubSession(daemon);
    if (session == nullptr || session->mapTask == nullptr) {
        delete daemon;
        return false;
    }
    daemon->stubSession = session;
    FuzzEnv *env = new(std::nothrow) FuzzEnv { daemon, session };
    if (env == nullptr) {
        delete session;
        delete daemon;
        return false;
    }
    // Deliberately leaked, the environment has to survive across iterations.
    g_env = env;
    return true;
}

void ApplyState(const FuzzInput &in)
{
    StubDaemon *daemon = g_env->daemon;
    HSession session = g_env->session;
    session->sessionId = (in.flags & FLAG_STRUCTURED_HS) != 0 ? in.sessionId : DEFAULT_SESSION_ID;
    session->handshakeOK = (in.flags & FLAG_HANDSHAKE_OK) != 0;
    session->connType = (in.flags & FLAG_CONN_USB) != 0 ? CONN_USB : CONN_TCP;
    session->supportConnValidation = (in.flags & FLAG_SUPPORT_CONN_VALIDATION) != 0;
    session->isDead = false;
    session->childCleared = false;
    daemon->authEnable = (in.flags & FLAG_AUTH_ENABLE) != 0;
    // Per iteration reset: without it a token issued by HandDaemonAuthInit()
    // would survive and let the next run reach HandDaemonAuthPubkey(), which
    // reads RSA key files.
    daemon->mapAuthStatus.clear();
    if ((in.flags & FLAG_AUTH_STATE_OK) != 0) {
        daemon->UpdateSessionAuthOk(session->sessionId);
    }
    std::map<uint32_t, HTaskInfo> *mapTask = session->mapTask;
    for (auto &item : *mapTask) {
        delete item.second;
    }
    mapTask->clear();
}

bool FuzzFetchCommand(const uint8_t *data, size_t size)
{
    if (!InitEnv()) {
        WRITE_LOG(LOG_FATAL, "FuzzFetchCommand init env failed");
        return false;
    }
    FuzzInput in = {};
    DecodeInput(data, size, in);
    ApplyState(in);

    std::vector<uint8_t> payload;
    if ((in.flags & FLAG_STRUCTURED_HS) != 0 && in.command == CMD_KERNEL_HANDSHAKE) {
        BuildStructuredHandshake(in, payload);
    } else {
        // Exactly bodySize bytes: FetchCommand() and everything below it derive
        // every length from payloadSize, so the allocation has to match it for an
        // overread to be reported instead of landing in a larger ioBuf.
        payload.assign(in.body, in.body + in.bodySize);
    }
    // payloadSize == 0 is a legitimate production value and is exactly what the
    // "payloadSize >= 1" and "payloadSize <= 0" guards are about, so keep it but
    // hand over a valid non null pointer.
    static uint8_t emptyPayloadByte = 0;
    uint8_t *payloadPtr = payload.empty() ? &emptyPayloadByte : payload.data();

    StubDaemon *daemon = g_env->daemon;
    daemon->payloadEnd = payloadPtr + payload.size();
    bool ret = daemon->FetchCommand(g_env->session, in.channelId, in.command, payloadPtr,
                                    static_cast<int>(payload.size()));
    if (!ret) {
        WRITE_LOG(LOG_FATAL, "FuzzFetchCommand ret false");
    }
    daemon->payloadEnd = nullptr;
    return true;
}
} // namespace

bool FuzzDaemonFetchCommand(const uint8_t *data, size_t size)
{
    return FuzzFetchCommand(data, size);
}
} // namespace Hdc

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    Hdc::FuzzDaemonFetchCommand(data, size);
    return 0;
}
