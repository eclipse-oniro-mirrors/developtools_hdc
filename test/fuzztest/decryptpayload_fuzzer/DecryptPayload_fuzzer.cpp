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

#include "DecryptPayload_fuzzer.h"

#include <algorithm>
#include <list>
#include <map>
#include <new>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <uv.h>

#include "serial_struct.h"

namespace Hdc {
namespace {
// Fuzz input layout:
//   [0]      mode        0 = OnRead (production framing), 1 = DecryptPayload called
//                        directly, 2 = FetchIOBuf (the real caller, multi packet loop)
//   [1]      flags       bit0 structured: build a syntactically valid packet instead
//                        of using the raw body, so the fuzzer gets past the vCode
//                        gate; bit1 session isDead; bit2 FetchCommand returns false
//   [2..3]   reserved
//   [4..7]   channelId   PayloadProtect.channelId   (structured mode)
//   [8..11]  commandFlag PayloadProtect.commandFlag (structured mode)
//   [12]     checkSum    PayloadProtect.checkSum    (structured mode)
//   [13..14] splitHint   headSize / dataSize split for mode 1
//   [15]     reserved
//   [16..]   body        raw packet bytes, or the payload in structured mode
constexpr size_t CTRL_SIZE = 16;
constexpr size_t OFFSET_MODE = 0;
constexpr size_t OFFSET_FLAGS = 1;
constexpr size_t OFFSET_CHANNEL_ID = 4;
constexpr size_t OFFSET_COMMAND_FLAG = 8;
constexpr size_t OFFSET_CHECKSUM = 12;
constexpr size_t OFFSET_SPLIT_HINT = 13;
constexpr size_t MAX_BUF_SIZE = 64 * 1024;
constexpr uint8_t FLAG_STRUCTURED = 0x01;
constexpr uint8_t FLAG_SESSION_DEAD = 0x02;
constexpr uint8_t FLAG_FETCH_FAILS = 0x04;
constexpr uint8_t MODE_ON_READ = 0;
constexpr uint8_t MODE_DECRYPT_DIRECT = 1;
constexpr uint8_t MODE_FETCH_IO_BUF = 2;
constexpr uint16_t SHIFT_BYTE = 8;
constexpr uint32_t SHIFT_WORD = 16;
constexpr uint32_t SHIFT_DWORD = 24;

using FuzzPayloadHead = HdcSessionBase::PayloadHead;
using FuzzPayloadProtect = HdcSessionBase::PayloadProtect;

struct FuzzInput {
    uint8_t mode;
    uint8_t flags;
    uint32_t channelId;
    uint32_t commandFlag;
    uint8_t checkSum;
    uint16_t splitHint;
    const uint8_t *body;
    size_t bodySize;
};

// FetchCommand() is the cut point: OnRead()'s framing checks, DecryptPayload(),
// SerialStruct::ParseFromString(), the vCode gate and the checksum all run for
// real, while the task machinery that would open files and spawn threads is
// replaced by an oracle.
class StubSessionBase : public HdcSessionBase {
public:
    StubSessionBase() : HdcSessionBase(false), payloadEnd(nullptr) {}
    ~StubSessionBase() override = default;

    bool FetchCommand(HSession hSession, const uint32_t channelId, const uint16_t command, uint8_t *payload,
                      int payloadSize) override
    {
        ++fetchCalls;
        lastChannelId = channelId;
        lastCommand = command;
        lastPayloadSize = payloadSize;
        if (payloadSize < 0) {
            ++negativeSizeHits;
            return fetchResult;
        }
        if (payload != nullptr && payloadSize > 0) {
            // DecryptPayload() computes data = encBuf + headSize and hands dataSize
            // straight over. Both come from the wire, so verify the declared range
            // really stays inside the buffer OnRead() was given, then touch both
            // ends so the sanitizer validates them.
            if (payloadEnd != nullptr && payload + payloadSize > payloadEnd) {
                ++outOfRangeHits;
                return fetchResult;
            }
            sink = payload[0];
            sink = payload[payloadSize - 1];
        }
        return fetchResult;
    }
    // FetchIOBuf() calls this on the heartbeat timeout path.
    void FreeSession(const uint32_t sessionId) override {}

    const uint8_t *payloadEnd;
    bool fetchResult = true;
    uint64_t fetchCalls = 0;
    uint64_t negativeSizeHits = 0;
    uint64_t outOfRangeHits = 0;
    uint32_t lastChannelId = 0;
    uint16_t lastCommand = 0;
    int lastPayloadSize = 0;
    static volatile uint8_t sink;
};
volatile uint8_t StubSessionBase::sink = 0;

struct FuzzEnv {
    StubSessionBase *stub;
    HSession session;
    uint8_t vcode;
    uint16_t splitHint;
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
    in.mode = ctrl[OFFSET_MODE];
    in.flags = ctrl[OFFSET_FLAGS];
    in.channelId = ReadU32(ctrl + OFFSET_CHANNEL_ID);
    in.commandFlag = ReadU32(ctrl + OFFSET_COMMAND_FLAG);
    in.checkSum = ctrl[OFFSET_CHECKSUM];
    in.splitHint = ReadU16(ctrl + OFFSET_SPLIT_HINT);
    in.body = data + ctrlLen;
    in.bodySize = std::min(size - ctrlLen, MAX_BUF_SIZE);
}

HSession BuildStubSession(StubSessionBase *stub)
{
    HSession session = new(std::nothrow) HdcSession();
    if (session == nullptr) {
        return nullptr;
    }
    session->classInstance = stub;
    session->connType = CONN_TCP;
    session->serverOrDaemon = true;
    session->sessionId = 0x48444346;
    session->isDead = false;
    session->childCleared = false;
    session->stat.dataRecvBytes = 0;
    session->stat.dataSendBytes = 0;
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
    StubSessionBase *stub = new(std::nothrow) StubSessionBase();
    if (stub == nullptr) {
        return false;
    }
    HSession session = BuildStubSession(stub);
    if (session == nullptr) {
        delete stub;
        return false;
    }
    FuzzEnv *env = new(std::nothrow) FuzzEnv { stub, session, stub->payloadProtectStaticVcode, 0 };
    if (env == nullptr) {
        delete session;
        delete stub;
        return false;
    }
    // Deliberately leaked, the environment has to survive across iterations.
    g_env = env;
    return true;
}

// Build a packet that passes OnRead()'s framing and DecryptPayload()'s vCode gate,
// so the fuzzer reaches FetchCommand() instead of dying on the first check.
void BuildStructuredPacket(const FuzzInput &in, std::vector<uint8_t> &out)
{
    FuzzPayloadProtect protect = {};
    protect.channelId = in.channelId;
    protect.commandFlag = in.commandFlag;
    protect.checkSum = in.checkSum;
    protect.vCode = g_env->vcode;
    string enc = SerialStruct::SerializeToString(protect);

    size_t payloadLen = std::min(in.bodySize, MAX_BUF_SIZE - sizeof(FuzzPayloadHead) - enc.size());
    FuzzPayloadHead head = {};
    head.flag[0] = static_cast<uint8_t>(PACKET_FLAG[0]);
    head.flag[1] = static_cast<uint8_t>(PACKET_FLAG[1]);
    head.protocolVer = VER_PROTOCOL;
    head.headSize = htons(static_cast<uint16_t>(enc.size()));
    head.dataSize = htonl(static_cast<uint32_t>(payloadLen));

    out.assign(sizeof(head) + enc.size() + payloadLen, 0);
    if (memcpy_s(out.data(), out.size(), &head, sizeof(head)) != EOK) {
        WRITE_LOG(LOG_FATAL, "build structured packet memcpy_s head failed");
        return;
    }
    if (memcpy_s(out.data() + sizeof(head), out.size() - sizeof(head), enc.data(), enc.size()) != EOK) {
        WRITE_LOG(LOG_FATAL, "build structured packet memcpy_s data failed");
        return;
    }
    if (payloadLen > 0) {
        (void)memcpy_s(out.data() + sizeof(head) + enc.size(), payloadLen, in.body, payloadLen);
    }
}

void BuildRawPacket(const FuzzInput &in, std::vector<uint8_t> &out)
{
    // Exactly bodySize bytes: the allocation matches the declared bufLen, so any
    // read past it is reported instead of silently landing in a larger ioBuf.
    out.assign(in.body, in.body + in.bodySize);
}

void RunDecryptDirect(std::vector<uint8_t> &buf)
{
    size_t bufLen = buf.size();
    if (bufLen < sizeof(FuzzPayloadHead)) {
        return;
    }
    auto *head = reinterpret_cast<FuzzPayloadHead *>(buf.data());
    size_t room = bufLen - sizeof(FuzzPayloadHead);
    // headSize + dataSize is kept exactly equal to the bytes available, the way
    // OnRead() guarantees it. Handing DecryptPayload() an inconsistent header
    // would be a harness bug rather than a finding.
    size_t maxHead = std::min(room, static_cast<size_t>(UINT16_MAX));
    size_t headSize = g_env->splitHint % (maxHead + 1);
    head->headSize = htons(static_cast<uint16_t>(headSize));
    head->dataSize = htonl(static_cast<uint32_t>(room - headSize));
    g_env->stub->DecryptPayload(g_env->session, head, buf.data() + sizeof(FuzzPayloadHead));
}

void RunFetchIoBuf(std::vector<uint8_t> &buf)
{
    HSession session = g_env->session;
    session->ioBuf = buf.data();
    session->bufSize = static_cast<int>(buf.size());
    session->availTailIndex = 0;
    (void)g_env->stub->FetchIOBuf(session, buf.data(), session->bufSize);
    session->ioBuf = nullptr;
    session->bufSize = 0;
    session->availTailIndex = 0;
}

bool FuzzDecryptPayload(const uint8_t *data, size_t size)
{
    if (!InitEnv()) {
        WRITE_LOG(LOG_FATAL, "FuzzDecryptPayload init env failed");
        return false;
    }
    FuzzInput in = {};
    DecodeInput(data, size, in);

    std::vector<uint8_t> buf;
    if ((in.flags & FLAG_STRUCTURED) != 0) {
        BuildStructuredPacket(in, buf);
    } else {
        BuildRawPacket(in, buf);
    }
    if (buf.empty()) {
        return true;
    }
    g_env->splitHint = in.splitHint;
    g_env->stub->payloadEnd = buf.data() + buf.size();
    g_env->stub->fetchResult = (in.flags & FLAG_FETCH_FAILS) == 0;
    g_env->session->isDead = (in.flags & FLAG_SESSION_DEAD) != 0;

    switch (in.mode) {
        case MODE_DECRYPT_DIRECT:
            RunDecryptDirect(buf);
            break;
        case MODE_FETCH_IO_BUF:
            RunFetchIoBuf(buf);
            break;
        case MODE_ON_READ:
        default:
            (void)g_env->stub->OnRead(g_env->session, buf.data(), static_cast<int>(buf.size()));
            break;
    }
    g_env->stub->payloadEnd = nullptr;
    return true;
}
} // namespace

bool FuzzSessionDecryptPayload(const uint8_t *data, size_t size)
{
    return FuzzDecryptPayload(data, size);
}
} // namespace Hdc

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    Hdc::FuzzSessionDecryptPayload(data, size);
    return 0;
}
