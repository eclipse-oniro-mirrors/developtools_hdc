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

#include "ForwardCommandDispatch_fuzzer.h"

#include <algorithm>
#include <new>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <uv.h>

namespace Hdc {
namespace {
// Fuzz input layout. The control prefix selects the dispatched command and the
// state of the forward context, everything behind it is the raw payload buffer
// as it would sit inside hSession->ioBuf:
//   [0..1]  command    bit7 of [0] set -> raw uint16, otherwise table index
//   [1]     ctxFlags   bit0 create a context, bit1 stamp its real id into the
//                      payload, bit2 masterSlave, bit3 ready, bit4 finish,
//                      bit5 checkPoint
//   [2]     ctxType    index into ctxTypes
//   [3]     tailFiller fill byte behind the copied payload, models the stale
//                      bytes of a previous packet still living in ioBuf
//   [4..7]  sizeRaw    encoded payloadSize
//   [8..]   body       payload bytes
constexpr size_t CTRL_SIZE = 8;
constexpr size_t CTRL_OFFSET_ZERO = 0;
constexpr size_t CTRL_OFFSET_ONE = 1;
constexpr size_t CTRL_OFFSET_TWO = 2;
constexpr size_t CTRL_OFFSET_THREE = 3;
constexpr size_t CTRL_OFFSET_FOUR = 4;
constexpr int PAYLOAD_CAPACITY = 64 * 1024;
constexpr int DRAIN_RUN_MAX = 8;
constexpr uint32_t SIZE_MODE_MASK = 0x3;
constexpr uint32_t SIZE_MODE_TINY = 0;
constexpr uint32_t SIZE_MODE_SMALL = 1;
constexpr uint32_t SIZE_MODE_MEDIUM = 2;
constexpr uint32_t TINY_MASK = 0xF;
constexpr uint32_t SMALL_MASK = 0xFF;
constexpr uint32_t MEDIUM_MASK = 0xFFF;
constexpr uint32_t SHIFT_BYTE = 8;
constexpr uint32_t SHIFT_WORD = 16;
constexpr uint32_t SHIFT_DWORD = 24;
constexpr uint32_t SHIFT_SIZE = 2;
constexpr uint8_t CMD_FLAG_RAW = 0x80;
constexpr uint8_t FLAG_WITH_CTX = 0x01;
constexpr uint8_t FLAG_STAMP_ID = 0x02;
constexpr uint8_t FLAG_MASTER = 0x04;
constexpr uint8_t FLAG_CTX_READY = 0x08;
constexpr uint8_t FLAG_CTX_CHECKPOINT = 0x20;
constexpr uint32_t FUZZ_SESSION_ID = 0x48444346;

// CMD_FORWARD_SUCCESS is not routed to the forward task in production, it is
// listed here to exercise the default: branch of ForwardCommandDispatch().
const uint16_t COMMANDS[] = {
    CMD_FORWARD_INIT,          CMD_FORWARD_CHECK,   CMD_FORWARD_CHECK_RESULT, CMD_FORWARD_ACTIVE_SLAVE,
    CMD_FORWARD_ACTIVE_MASTER, CMD_FORWARD_DATA,    CMD_FORWARD_FREE_CONTEXT, CMD_FORWARD_SUCCESS,
};
constexpr size_t COMMAND_COUNT = sizeof(COMMANDS) / sizeof(COMMANDS[0]);

// FORWARD_DEVICE is deliberately absent: SendForwardBuf() dereferences
// ctx->fdClass, which only SetupDevicePoint() creates. The string driven
// commands still reach the device path through the real code.
const HdcForwardBase::FORWARD_TYPE ctxTypes[] = {
    HdcForwardBase::FORWARD_TCP,     HdcForwardBase::FORWARD_JDWP,    HdcForwardBase::FORWARD_ARK,
    HdcForwardBase::FORWARD_ABSTRACT, HdcForwardBase::FORWARD_RESERVED, HdcForwardBase::FORWARD_FILESYSTEM,
};
constexpr size_t CTX_TYPE_COUNT = sizeof(ctxTypes) / sizeof(ctxTypes[0]);

struct FuzzInput {
    uint16_t command;
    uint8_t ctxFlags;
    uint8_t ctxType;
    uint8_t tailFiller;
    int payloadSize;
    const uint8_t *body;
    size_t bodySize;
};

struct FuzzEnv {
    uv_loop_t loop;
    LoopStatus *loopStatus;
    HdcSessionBase *session;
    HTaskInfo taskInfo;
    HdcForwardBase *forward;
    uint8_t *payload;
    int peerFd;
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

// payloadSize is an int that the session layer derives from a wire uint32, keep
// the generated values non negative and put most of the density around the two
// length guards (DWORD_SERIALIZE_SIZE and DWORD_SERIALIZE_SIZE + 8).
int DecodePayloadSize(uint32_t raw)
{
    switch (raw & SIZE_MODE_MASK) {
        case SIZE_MODE_TINY:
            return static_cast<int>((raw >> SHIFT_SIZE) & TINY_MASK);
        case SIZE_MODE_SMALL:
            return static_cast<int>((raw >> SHIFT_SIZE) & SMALL_MASK);
        case SIZE_MODE_MEDIUM:
            return static_cast<int>((raw >> SHIFT_SIZE) & MEDIUM_MASK);
        default:
            return static_cast<int>(raw % (static_cast<uint32_t>(PAYLOAD_CAPACITY) + 1));
    }
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
    in.command = ((ctrl[CTRL_OFFSET_ZERO] & CMD_FLAG_RAW) != 0)
                 ? ReadU16(ctrl) : COMMANDS[ctrl[CTRL_OFFSET_ZERO] % COMMAND_COUNT];
    in.ctxFlags = ctrl[CTRL_OFFSET_ONE];
    in.ctxType = ctrl[CTRL_OFFSET_TWO];
    in.tailFiller = ctrl[CTRL_OFFSET_THREE];
    in.payloadSize = DecodePayloadSize(ReadU32(ctrl + CTRL_OFFSET_FOUR));
    in.body = data + ctrlLen;
    in.bodySize = size - ctrlLen;
}

bool InitEnv()
{
    if (g_env != nullptr) {
        return true;
    }
    Base::SetLogLevel(LOG_OFF);
    FuzzEnv *env = new(std::nothrow) FuzzEnv();
    if (env == nullptr) {
        return false;
    }
    if (uv_loop_init(&env->loop) != 0) {
        delete env;
        return false;
    }
    env->loopStatus = new(std::nothrow) LoopStatus(&env->loop, "FuzzTaskLoop");
    env->session = new(std::nothrow) HdcSessionBase(false);
    env->taskInfo = new(std::nothrow) TaskInformation();
    env->payload = new(std::nothrow) uint8_t[PAYLOAD_CAPACITY]();
    if (env->loopStatus == nullptr || env->session == nullptr || env->taskInfo == nullptr ||
        env->payload == nullptr) {
        delete[] env->payload;
        delete env->taskInfo;
        delete env->session;
        delete env->loopStatus;
        delete env;
        return false;
    }
    env->taskInfo->runLoop = &env->loop;
    env->taskInfo->runLoopStatus = env->loopStatus;
    env->taskInfo->ownerSessionClass = env->session;
    env->taskInfo->channelTask = false;
    env->taskInfo->masterSlave = false;
    env->taskInfo->sessionId = FUZZ_SESSION_ID;
    env->taskInfo->channelId = 1;
    env->forward = new(std::nothrow) HdcForwardBase(env->taskInfo);
    if (env->forward == nullptr) {
        delete[] env->payload;
        delete env->taskInfo;
        delete env->session;
        delete env->loopStatus;
        delete env;
        return false;
    }
    env->peerFd = -1;
    // Deliberately leaked, the environment has to survive across iterations.
    g_env = env;
    return true;
}

// Give the context a real file descriptor so uv_read_start()/uv_write() never
// run against io_watcher.fd == -1, which libuv does not tolerate.
bool OpenCtxHandle(HdcForwardBase::HCtxForward ctx)
{
    switch (ctx->type) {
        case HdcForwardBase::FORWARD_TCP:
        case HdcForwardBase::FORWARD_JDWP:
        case HdcForwardBase::FORWARD_ARK:
            // uv_tcp_init() already owns a socket. It is neither bound nor
            // connected, so uv_is_writable() stays false and SendToStreamEx()
            // bails out before queueing a write.
            return uv_tcp_init(&g_env->loop, &ctx->tcp) == 0;
        default:
            break;
    }
    int sv[2] = { -1, -1 };
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        return false;
    }
    if (uv_pipe_init(&g_env->loop, &ctx->pipe, 0) != 0 || uv_pipe_open(&ctx->pipe, sv[0]) != 0) {
        close(sv[0]);
        close(sv[1]);
        return false;
    }
    // sv[0] belongs to libuv now, keep the peer end open so the stream reports
    // itself as writable and SendForwardBuf() reaches uv_write().
    g_env->peerFd = sv[1];
    return true;
}

HdcForwardBase::HCtxForward SetupCtx(uint8_t typeIndex, uint8_t ctxFlags)
{
    HdcForwardBase *forward = g_env->forward;
    auto ctx = reinterpret_cast<HdcForwardBase::HCtxForward>(forward->MallocContext(
        (ctxFlags & FLAG_MASTER) != 0));
    if (ctx == nullptr) {
        return nullptr;
    }
    ctx->type = ctxTypes[typeIndex % CTX_TYPE_COUNT];
    ctx->ready = (ctxFlags & FLAG_CTX_READY) != 0;
    ctx->finish = false;
    ctx->checkPoint = (ctxFlags & FLAG_CTX_CHECKPOINT) != 0;
    if (!OpenCtxHandle(ctx)) {
        forward->FreeContext(ctx, 0, false);
        return nullptr;
    }
    return ctx;
}

void FillPayload(const FuzzInput &in)
{
    size_t capacity = static_cast<size_t>(PAYLOAD_CAPACITY);
    size_t copyLen = std::min(in.bodySize, capacity);
    // [0, copyLen) is the packet content, the tail is what a previous, larger
    // packet left behind in ioBuf. A non zero tail is what turns the unbounded
    // strlen() inside CheckNodeInfo() into an out of bounds read.
    if (memset_s(g_env->payload, capacity, in.tailFiller, capacity) != EOK) {
        return;
    }
    if (copyLen > 0) {
        (void)memcpy_s(g_env->payload, capacity, in.body, copyLen);
    }
}

void Cleanup()
{
    // StopTask() walks mapCtxPoint and frees every context this iteration
    // produced, including the ones BeginForward()/SlaveConnect() allocated.
    g_env->forward->StopTask();
    if (g_env->peerFd >= 0) {
        close(g_env->peerFd);
        g_env->peerFd = -1;
    }
    // uv_close() callbacks and the DoNextLoop() timer that finally deletes a
    // context both need the loop to turn, run it without ever blocking.
    for (int i = 0; i < DRAIN_RUN_MAX && uv_loop_alive(&g_env->loop) != 0; ++i) {
        uv_run(&g_env->loop, UV_RUN_NOWAIT);
    }
}

bool FuzzCommandDispatch(const uint8_t *data, size_t size)
{
    if (!InitEnv()) {
        WRITE_LOG(LOG_FATAL, "FuzzCommandDispatch init env failed");
        return false;
    }
    FuzzInput in = {};
    DecodeInput(data, size, in);
    FillPayload(in);

    HdcForwardBase *forward = g_env->forward;
    if ((in.ctxFlags & FLAG_WITH_CTX) != 0) {
        auto ctx = SetupCtx(in.ctxType, in.ctxFlags);
        // A real peer learned the id from CMD_FORWARD_CHECK / ACTIVE_SLAVE,
        // reproduce that so AdminContext(OP_QUERY) actually hits.
        if (ctx != nullptr && (in.ctxFlags & FLAG_STAMP_ID) != 0 &&
            in.payloadSize >= static_cast<int>(DWORD_SERIALIZE_SIZE)) {
            uint32_t networkId = htonl(ctx->id);
            (void)memcpy_s(g_env->payload, PAYLOAD_CAPACITY, &networkId, sizeof(networkId));
        }
    }
    forward->CommandDispatch(in.command, g_env->payload, in.payloadSize);
    Cleanup();
    return true;
}
} // namespace

bool FuzzForwardCommandDispatch(const uint8_t *data, size_t size)
{
    return FuzzCommandDispatch(data, size);
}
} // namespace Hdc

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    Hdc::FuzzForwardCommandDispatch(data, size);
    return 0;
}
