/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "transfer.h"
#include <filesystem>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using namespace testing::ext;
using namespace testing;

namespace Hdc {

class HdcTransferTest : public Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    class MockHdcTransfer : public HdcTransferBase {
    public:
        explicit MockHdcTransfer(HTaskInfo hTaskInfo) : HdcTransferBase(hTaskInfo) {}
    };

private:
    HTaskInfo BuildPTask()
    {
        HTaskInfo hTaskInfo = new(std::nothrow) TaskInformation();
        if (hTaskInfo == nullptr) {
            return nullptr;
        }
        uv_loop_t looptest;
        uv_loop_init(&looptest);
        LoopStatus ls(&looptest, "not support");
        HdcSessionBase *unittest = new (std::nothrow) HdcSessionBase(false);
        if (unittest == nullptr) {
            delete hTaskInfo;
            return nullptr;
        }
        hTaskInfo->ownerSessionClass = unittest;
        hTaskInfo->channelId = 0;
        hTaskInfo->sessionId = 0;
        hTaskInfo->runLoop = &looptest;
        hTaskInfo->runLoopStatus = &ls;
        hTaskInfo->serverOrDaemon = false;
        hTaskInfo->masterSlave = false;
        hTaskInfo->closeRetryCount = 0;
        hTaskInfo->channelTask = false;
        hTaskInfo->isCleared = false;
        hTaskInfo->taskType = TASK_FILE;
        hTaskInfo->hasInitial = true;
        HdcTransferBase *ptrTask = nullptr;
        ptrTask = new (std::nothrow) HdcTransferBase(hTaskInfo);
        if (ptrTask == nullptr) {
            delete hTaskInfo;
            delete unittest;
            return nullptr;
        }
        hTaskInfo->taskClass = ptrTask;
        return hTaskInfo;
    }

    HTaskInfo hTaskInfo;
    MockHdcTransfer *mockHdcdTransfer;
};

void HdcTransferTest::SetUpTestCase()
{
#ifdef UT_DEBUG
    Hdc::Base::SetLogLevel(LOG_ALL);
#else
    Hdc::Base::SetLogLevel(LOG_OFF);
#endif
}
void HdcTransferTest::TearDownTestCase() {}
void HdcTransferTest::SetUp()
{
    hTaskInfo = BuildPTask();
    mockHdcdTransfer = new (std::nothrow) MockHdcTransfer(hTaskInfo);
    mockHdcdTransfer->commandBegin = CMD_FILE_BEGIN;
    mockHdcdTransfer->commandBegin = CMD_FILE_DATA;
    mockHdcdTransfer->isStableBuf = false;
}
void HdcTransferTest::TearDown()
{
    delete mockHdcdTransfer;
    mockHdcdTransfer = nullptr;
}

HWTEST_F(HdcTransferTest, TestCommandDispatch, TestSize.Level0)
{
    uint16_t command = CMD_FILE_DATA;
    uint8_t payload[10];
    int payloadSize = -1;
    ASSERT_EQ(mockHdcdTransfer->CommandDispatch(command, payload, payloadSize), false);
}

HWTEST_F(HdcTransferTest, TestExtractRelativePath, TestSize.Level0)
{
    // normal windows slash
    string cwd = "D:\\";
    string resolvedPath = "test\\path";
    string wantStr = "D:\\test\\path";
    mockHdcdTransfer->ExtractRelativePath(cwd, resolvedPath);
    ASSERT_EQ(resolvedPath, wantStr);

    // normal unix slash
    cwd = "/tmp/";
    resolvedPath = "test/path";
    wantStr = "/tmp/test/path";
    mockHdcdTransfer->ExtractRelativePath(cwd, resolvedPath);
    ASSERT_EQ(resolvedPath, wantStr);

    // test resolvedPath is absolute path
    cwd = "/tmp/";
    resolvedPath = "/test/path";
    wantStr = "/test/path";
    mockHdcdTransfer->ExtractRelativePath(cwd, resolvedPath);
    ASSERT_EQ(resolvedPath, wantStr);

    // test cwd is empty
    cwd = "";
    resolvedPath = "test/path";
    wantStr = "test/path";
    mockHdcdTransfer->ExtractRelativePath(cwd, resolvedPath);
    ASSERT_EQ(resolvedPath, wantStr);
}

HWTEST_F(HdcTransferTest, TestRemoveSandboxRootPath, TestSize.Level0)
{
    const string bundleName = "com.example.myapplication";
    const string testDir = "data/local/tmp/";
    std::filesystem::path testPath = mockHdcdTransfer->SANDBOX_ROOT_DIR + bundleName + Base::GetPathSep() + testDir;
    if (!std::filesystem::exists(testPath)) {
        std::filesystem::create_directories(testPath);
    }
    ASSERT_TRUE(std::filesystem::exists(testPath));

    // normal test, srcStr contains Sandbox Root Path
    string srcStr = testPath;
    string wantStr = testDir;
    mockHdcdTransfer->RemoveSandboxRootPath(srcStr, bundleName);
    ASSERT_EQ(srcStr, wantStr);

    // srcStr not contains full Sandbox Root Path, missing slash, srcStr.size() < fullPath.size()
    srcStr = mockHdcdTransfer->SANDBOX_ROOT_DIR + bundleName;
    wantStr = srcStr;
    mockHdcdTransfer->RemoveSandboxRootPath(srcStr, bundleName);
    ASSERT_EQ(srcStr, wantStr);

    // srcStr.size() > fullPath.size(), drop first slash
    srcStr = testPath;
    srcStr = srcStr.substr(1);
    wantStr = srcStr;
    mockHdcdTransfer->RemoveSandboxRootPath(srcStr, bundleName);
    ASSERT_EQ(srcStr, wantStr);

    // Invalid bundleName
    const string bundleNameTest = "test-" + bundleName + "-test";
    srcStr = testPath;
    wantStr = srcStr;
    mockHdcdTransfer->RemoveSandboxRootPath(srcStr, bundleNameTest);
    ASSERT_EQ(srcStr, wantStr);
}

HWTEST_F(HdcTransferTest, TestAddFeatures, TestSize.Level0)
{
    union HdcTransferBase::FeatureFlagsUnion f{};
    mockHdcdTransfer->AddFeatures(f);
    ASSERT_EQ(f.bits.reserveBits1, 1);
    ASSERT_EQ(f.bits.hugeBuf, true);
}

HWTEST_F(HdcTransferTest, TestCheckFeatures, TestSize.Level0)
{
    uint8_t payload[FEATURE_FLAG_MAX_SIZE] = {1};
    // case 1: payloadSize < 0;
    int payloadSize = 0;
    HdcTransferBase::CtxFile context;
    bool result = mockHdcdTransfer->CheckFeatures(&context, payload, payloadSize);
    EXPECT_TRUE(result);
    ASSERT_EQ(context.isStableBufSize, true);
    ASSERT_EQ(context.isOtherSideSandboxSupported, false);
    // case 1: payloadSize = FEATURE_FLAG_MAX_SIZE;
    payloadSize = FEATURE_FLAG_MAX_SIZE;
    result = mockHdcdTransfer->CheckFeatures(&context, payload, payloadSize);
    EXPECT_TRUE(result);
    ASSERT_EQ(context.isStableBufSize, false);
    ASSERT_EQ(context.isOtherSideSandboxSupported, false);
    // case 1: other payloadSize
    payloadSize = FEATURE_FLAG_MAX_SIZE + 1;
    result = mockHdcdTransfer->CheckFeatures(&context, payload, payloadSize);
    EXPECT_FALSE(result);
}

HWTEST_F(HdcTransferTest, TestCheckSandboxOptionCompatibility, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    bool result = mockHdcdTransfer->CheckSandboxOptionCompatibility(mockHdcdTransfer->cmdBundleName, &context);
    EXPECT_TRUE(result);

    context.isOtherSideSandboxSupported = false;
    ASSERT_EQ(mockHdcdTransfer->CheckSandboxOptionCompatibility(mockHdcdTransfer->cmdBundleName, &context), true);
}

HWTEST_F(HdcTransferTest, TestResetCtx, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    ASSERT_EQ(mockHdcdTransfer->ResetCtx(&context, true), true);
    ASSERT_EQ(context.openFd, -1);
}

HWTEST_F(HdcTransferTest, TestSimpleFileIO, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    int bufLen = MAX_SIZE_IOBUF_STABLE * mockHdcdTransfer->maxTransferBufFactor;
    context.indexIO = rand();
    context.isStableBufSize = true;
    int result = mockHdcdTransfer->SimpleFileIO(&context, context.indexIO, nullptr, bufLen + 1);
    ASSERT_EQ(result, -1);
    result = mockHdcdTransfer->SimpleFileIO(&context, context.indexIO, nullptr, -1);
    ASSERT_EQ(result, -1);

    context.ioFinish = true;
    result = mockHdcdTransfer->SimpleFileIO(&context, context.indexIO, nullptr, bufLen);
    ASSERT_EQ(result, -1);

    // case: memcpy error
    context.ioFinish = false;
    context.master = false;
    result = mockHdcdTransfer->SimpleFileIO(&context, context.indexIO, nullptr, bufLen);
    ASSERT_EQ(result, -1);
}

HWTEST_F(HdcTransferTest, TestInitTransferPayload, TestSize.Level0)
{
    HdcTransferBase::TransferPayload payloadHead;
    uint64_t index = rand();
    uint8_t compressType = HdcTransferBase::COMPRESS_LZ4;
    bool result = mockHdcdTransfer->InitTransferPayload(payloadHead, index,
                                                        compressType, MAX_SIZE_IOBUF_STABLE);

    ASSERT_EQ(result, true);
    ASSERT_EQ(payloadHead.compressType, compressType);
    ASSERT_EQ(payloadHead.uncompressSize, MAX_SIZE_IOBUF_STABLE);
    ASSERT_EQ(payloadHead.index, index);
}

HWTEST_F(HdcTransferTest, TestSendIOPayload, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    uint64_t index = rand();
    uint8_t *payload = new uint8_t[MAX_SIZE_IOBUF_STABLE];
    memset_s(payload, MAX_SIZE_IOBUF_STABLE, 1, MAX_SIZE_IOBUF_STABLE);

    bool result = mockHdcdTransfer->SendIOPayload(&context, index,
                                                    payload, -1);
    ASSERT_EQ(result, false);
}

HWTEST_F(HdcTransferTest, TestProcressFileIOWrite, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    context.thisClass = mockHdcdTransfer;
    uv_fs_t req;
    req.result = 0;
    context.indexIO = context.fileSize = rand();
    bool result = mockHdcdTransfer->ProcressFileIOWrite(&req, &context,
                                                        (HdcTransferBase *)context.thisClass);
    ASSERT_EQ(result, true);

    req.result = -1;
    context.indexIO = 1;
    context.fileSize = 2;
    result = mockHdcdTransfer->ProcressFileIOWrite(&req, &context,
                                                    (HdcTransferBase *)context.thisClass);
    ASSERT_EQ(result, false);
}

HWTEST_F(HdcTransferTest, TestProcressFileIO, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    context.thisClass = mockHdcdTransfer;
    uint64_t bytes = rand();
    uv_fs_t req;
    req.result = -1;

    context.ioFinish = true;
    bool result = mockHdcdTransfer->ProcressFileIO(&req, &context,
                                                    (HdcTransferBase *)context.thisClass, bytes);
    ASSERT_EQ(result, true);

    context.ioFinish = false;
    context.master = true;
    result = mockHdcdTransfer->ProcressFileIO(&req, &context,
                                                (HdcTransferBase *)context.thisClass, bytes);
    ASSERT_EQ(result, true);

    req.result = 0;
    req.fs_type = UV_FS_WRITE;
    result = mockHdcdTransfer->ProcressFileIO(&req, &context,
                                                (HdcTransferBase *)context.thisClass, bytes);
    ASSERT_EQ(result, true);
}

HWTEST_F(HdcTransferTest, TestIODelayed, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    uint64_t bytes = rand();
    HdcTransferBase::CtxFileIO *ioContext = new (std::nothrow) HdcTransferBase::CtxFileIO();
    uint8_t *buf = new uint8_t[bytes + HdcTransferBase::payloadPrefixReserve]();
    uv_fs_t *req = &ioContext->fs;
    ioContext->bytes = bytes;
    ioContext->bufIO = buf + HdcTransferBase::payloadPrefixReserve;
    ioContext->context = &context;
    req->data = ioContext;
    req->fs_type = UV_FS_WRITE;
    bool result = mockHdcdTransfer->IODelayed(req);
    ASSERT_EQ(result, false);
}

HWTEST_F(HdcTransferTest, TestIsValidBundlePath, TestSize.Level0)
{
    std::filesystem::path testPath = "/mnt/debug/100/debug_hap/com.example.myapplication/data/local/tmp/";
    if (!std::filesystem::exists(testPath))
    {
        std::filesystem::create_directories(testPath);
    }
    ASSERT_TRUE(std::filesystem::exists(testPath));
    const string bundleName = "com.example.myapplication";
    bool result = mockHdcdTransfer->IsValidBundlePath(bundleName);
    ASSERT_EQ(result, true);
}

HWTEST_F(HdcTransferTest, TestMatchPackageExtendName, TestSize.Level0)
{
    string resolvedPath = "D:\\test\\path\\libA_v10001.hsp";
    bool result = mockHdcdTransfer->MatchPackageExtendName(resolvedPath, ".hsp");
    ASSERT_EQ(result, true);

    string invalidPath = "D:\\test\\path\\libA_v10001.hp";
    result = mockHdcdTransfer->MatchPackageExtendName(invalidPath, ".hsp");
    ASSERT_EQ(result, false);
}

HWTEST_F(HdcTransferTest, TestRecvIOPayload, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    uint8_t *payload = new uint8_t[BUF_SIZE_TINY];
    memset_s(payload, BUF_SIZE_TINY, 1, BUF_SIZE_TINY);

    bool result = mockHdcdTransfer->RecvIOPayload(&context, payload, -1);
    ASSERT_EQ(result, false);
}

// RecvIOPayload：空 payload → false
HWTEST_F(HdcTransferTest, TestRecvIOPayload_NullPayload, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    bool result = mockHdcdTransfer->RecvIOPayload(&context, nullptr, 0);
    EXPECT_FALSE(result);
}

// RecvIOPayload：size=0 → false
HWTEST_F(HdcTransferTest, TestRecvIOPayload_ZeroSize, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    uint8_t b = 0;
    bool result = mockHdcdTransfer->RecvIOPayload(&context, &b, 0);
    EXPECT_FALSE(result);
}

// CheckFeatures：返回 bool 不崩溃
HWTEST_F(HdcTransferTest, TestCheckFeatures_NoCrash, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    EXPECT_NO_FATAL_FAILURE((void)mockHdcdTransfer->CheckFeatures(&context, nullptr, 0));
    EXPECT_TRUE(context.isStableBufSize);
}

// CommandDispatch：command==commandBegin，payloadSize==0（走 default feature 分支）
HWTEST_F(HdcTransferTest, CommandDispatch_BeginPayloadZero, TestSize.Level0)
{
    mockHdcdTransfer->commandBegin = CMD_FILE_BEGIN;
    mockHdcdTransfer->commandData = CMD_FILE_DATA;
    HdcTransferBase::CtxFile context;
    mockHdcdTransfer->ctxNow = context;
    mockHdcdTransfer->ctxNow.isStableBufSize = false;
    uint8_t payload[FEATURE_FLAG_MAX_SIZE] = {0};
    // SimpleFileIO will fail since openFd=-1, expect false
    EXPECT_FALSE(mockHdcdTransfer->CommandDispatch(CMD_FILE_BEGIN, payload, 0));
}

// CommandDispatch：command==commandBegin，payloadSize==FEATURE_FLAG_MAX_SIZE
HWTEST_F(HdcTransferTest, CommandDispatch_BeginPayloadMax, TestSize.Level0)
{
    mockHdcdTransfer->commandBegin = CMD_FILE_BEGIN;
    mockHdcdTransfer->commandData = CMD_FILE_DATA;
    uint8_t payload[FEATURE_FLAG_MAX_SIZE] = {1};
    EXPECT_FALSE(mockHdcdTransfer->CommandDispatch(CMD_FILE_BEGIN, payload, FEATURE_FLAG_MAX_SIZE));
}

// CommandDispatch：command==commandData，payloadSize > HDC_BUF_MAX_BYTES
HWTEST_F(HdcTransferTest, CommandDispatch_DataSizeTooLarge, TestSize.Level0)
{
    mockHdcdTransfer->commandBegin = CMD_FILE_BEGIN;
    mockHdcdTransfer->commandData = CMD_FILE_DATA;
    uint8_t payload[10] = {0};
    EXPECT_FALSE(mockHdcdTransfer->CommandDispatch(CMD_FILE_DATA, payload,
                                                    static_cast<int>(HDC_BUF_MAX_BYTES) + 1));
}

// CommandDispatch：command==commandData，payloadSize < 0
HWTEST_F(HdcTransferTest, CommandDispatch_DataSizeNegative, TestSize.Level0)
{
    mockHdcdTransfer->commandBegin = CMD_FILE_BEGIN;
    mockHdcdTransfer->commandData = CMD_FILE_DATA;
    uint8_t payload[10] = {0};
    EXPECT_FALSE(mockHdcdTransfer->CommandDispatch(CMD_FILE_DATA, payload, -1));
}

// CommandDispatch：command==commandData，RecvIOPayload 失败（payloadSize 小于 reserve）
HWTEST_F(HdcTransferTest, CommandDispatch_DataRecvFail, TestSize.Level0)
{
    mockHdcdTransfer->commandBegin = CMD_FILE_BEGIN;
    mockHdcdTransfer->commandData = CMD_FILE_DATA;
    uint8_t payload[10] = {0};
    EXPECT_FALSE(mockHdcdTransfer->CommandDispatch(CMD_FILE_DATA, payload, 10));
}

// CommandDispatch：未知 command → 走 else 分支返回 true
HWTEST_F(HdcTransferTest, CommandDispatch_UnknownCmd, TestSize.Level0)
{
    mockHdcdTransfer->commandBegin = CMD_FILE_BEGIN;
    mockHdcdTransfer->commandData = CMD_FILE_DATA;
    uint8_t payload[10] = {0};
    EXPECT_TRUE(mockHdcdTransfer->CommandDispatch(9999, payload, 10));
}

// CommandDispatch：null payload + payloadSize=0 → CheckFeatures payloadSize==0
HWTEST_F(HdcTransferTest, CommandDispatch_BeginNullPayload, TestSize.Level0)
{
    mockHdcdTransfer->commandBegin = CMD_FILE_BEGIN;
    mockHdcdTransfer->commandData = CMD_FILE_DATA;
    EXPECT_FALSE(mockHdcdTransfer->CommandDispatch(CMD_FILE_BEGIN, nullptr, 0));
}

// ExtractRelativePath：绝对路径不拼接
HWTEST_F(HdcTransferTest, ExtractRelativePath_AbsPath, TestSize.Level0)
{
    string cwd = "/data/local/tmp/";
    string path = "/abs/path";
    mockHdcdTransfer->ExtractRelativePath(cwd, path);
    EXPECT_EQ(path, "/abs/path");
}

// ExtractRelativePath：相对路径拼接 cwd
HWTEST_F(HdcTransferTest, ExtractRelativePath_RelPath, TestSize.Level0)
{
    string cwd = "/data/local/tmp/";
    string path = "rel/path";
    mockHdcdTransfer->ExtractRelativePath(cwd, path);
    EXPECT_EQ(path, "/data/local/tmp/rel/path");
}

// ExtractRelativePath：空 cwd + 相对路径
HWTEST_F(HdcTransferTest, ExtractRelativePath_EmptyCwd, TestSize.Level0)
{
    string cwd = "";
    string path = "rel/path";
    mockHdcdTransfer->ExtractRelativePath(cwd, path);
    EXPECT_EQ(path, "rel/path");
}

// ExtractRelativePath：空 path
HWTEST_F(HdcTransferTest, ExtractRelativePath_EmptyPath, TestSize.Level0)
{
    string cwd = "/data/local/tmp/";
    string path = "";
    mockHdcdTransfer->ExtractRelativePath(cwd, path);
    EXPECT_EQ(path, "/data/local/tmp/");
}

// RemoveSandboxRootPath：bundleName 非法 → 直接返回
HWTEST_F(HdcTransferTest, RemoveSandboxRootPath_InvalidBundle, TestSize.Level0)
{
    string srcStr = "/some/path/file.txt";
    string original = srcStr;
    mockHdcdTransfer->RemoveSandboxRootPath(srcStr, "invalid-bundle!");
    EXPECT_EQ(srcStr, original);
}

// RemoveSandboxRootPath：serverOrDaemon=true → 直接返回
HWTEST_F(HdcTransferTest, RemoveSandboxRootPath_ServerMode, TestSize.Level0)
{
    bool oldServer = mockHdcdTransfer->taskInfo->serverOrDaemon;
    mockHdcdTransfer->taskInfo->serverOrDaemon = true;
    string srcStr = "/some/path/file.txt";
    string original = srcStr;
    mockHdcdTransfer->RemoveSandboxRootPath(srcStr, "com.example.app");
    EXPECT_EQ(srcStr, original);
    mockHdcdTransfer->taskInfo->serverOrDaemon = oldServer;
}

// AddFeatures：isStableBuf=true → hugeBuf=false
HWTEST_F(HdcTransferTest, AddFeatures_StableBuf, TestSize.Level0)
{
    mockHdcdTransfer->isStableBuf = true;
    union HdcTransferBase::FeatureFlagsUnion f{};
    EXPECT_TRUE(mockHdcdTransfer->AddFeatures(f));
    EXPECT_EQ(f.bits.hugeBuf, false);
    EXPECT_EQ(f.bits.reserveBits1, 1);
}

// AddFeatures：isStableBuf=false → hugeBuf=true
HWTEST_F(HdcTransferTest, AddFeatures_NotStableBuf, TestSize.Level0)
{
    mockHdcdTransfer->isStableBuf = false;
    union HdcTransferBase::FeatureFlagsUnion f{};
    EXPECT_TRUE(mockHdcdTransfer->AddFeatures(f));
    EXPECT_EQ(f.bits.hugeBuf, true);
    EXPECT_EQ(f.bits.reserveBits1, 1);
}

// CheckFeatures：payloadSize == 0 → 默认 feature
HWTEST_F(HdcTransferTest, CheckFeatures_PayloadZero, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    uint8_t payload[1] = {0};
    bool result = mockHdcdTransfer->CheckFeatures(&context, payload, 0);
    EXPECT_TRUE(result);
    EXPECT_EQ(context.isStableBufSize, true);
    EXPECT_EQ(context.isOtherSideSandboxSupported, false);
}

// CheckFeatures：payloadSize == FEATURE_FLAG_MAX_SIZE
HWTEST_F(HdcTransferTest, CheckFeatures_PayloadMax, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    uint8_t payload[FEATURE_FLAG_MAX_SIZE] = {0};
    payload[0] = 0x01;  // hugeBuf=1, reserveBits1=0
    bool result = mockHdcdTransfer->CheckFeatures(&context, payload, FEATURE_FLAG_MAX_SIZE);
    EXPECT_TRUE(result);
}

// CheckFeatures：payloadSize 为其它值 → false
HWTEST_F(HdcTransferTest, CheckFeatures_PayloadOther, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    uint8_t payload[4] = {0};
    bool result = mockHdcdTransfer->CheckFeatures(&context, payload, 4);
    EXPECT_FALSE(result);
}

// CheckSandboxOptionCompatibility：非 sandboxMode → true
HWTEST_F(HdcTransferTest, CheckSandbox_NotSandboxMode, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    context.sandboxMode = false;
    context.isOtherSideSandboxSupported = false;
    EXPECT_TRUE(mockHdcdTransfer->CheckSandboxOptionCompatibility("-b", &context));
}

// CheckSandboxOptionCompatibility：sandboxMode 但 isOtherSideSandboxSupported=true → true
HWTEST_F(HdcTransferTest, CheckSandbox_SandboxSupported, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    context.sandboxMode = true;
    context.isOtherSideSandboxSupported = true;
    EXPECT_TRUE(mockHdcdTransfer->CheckSandboxOptionCompatibility("-b", &context));
}

// CheckSandboxOptionCompatibility：sandboxMode 且不支持 且 option==cmdBundleName → false
HWTEST_F(HdcTransferTest, CheckSandbox_NotSupported, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    context.sandboxMode = true;
    context.isOtherSideSandboxSupported = false;
    context.thisClass = mockHdcdTransfer;
    EXPECT_FALSE(mockHdcdTransfer->CheckSandboxOptionCompatibility(mockHdcdTransfer->cmdBundleName, &context));
}

// CheckSandboxOptionCompatibility：option != cmdBundleName → true
HWTEST_F(HdcTransferTest, CheckSandbox_DiffOption, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    context.sandboxMode = true;
    context.isOtherSideSandboxSupported = false;
    EXPECT_TRUE(mockHdcdTransfer->CheckSandboxOptionCompatibility("-other", &context));
}

// ResetCtx：full=false → 只重置部分字段
HWTEST_F(HdcTransferTest, ResetCtx_Partial, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    context.transferConfig.fileSize = 100;
    context.localPath = "/test/path";
    EXPECT_TRUE(mockHdcdTransfer->ResetCtx(&context, false));
    EXPECT_EQ(context.openFd, -1);
    EXPECT_EQ(context.ioFinish, false);
    // full=false 不清空所有字段
    EXPECT_EQ(context.localPath, "/test/path");
}

// ResetCtx：full=true → 清空所有字段
HWTEST_F(HdcTransferTest, ResetCtx_FullClear, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    context.transferConfig.fileSize = 100;
    context.localPath = "/test/path";
    EXPECT_TRUE(mockHdcdTransfer->ResetCtx(&context, true));
    EXPECT_EQ(context.openFd, -1);
    EXPECT_EQ(context.localPath, "");
    EXPECT_EQ(context.transferConfig.fileSize, 0ULL);
}

// SimpleFileIO：bytes<0 → -1
HWTEST_F(HdcTransferTest, SimpleFileIO_NegativeBytes, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    context.isStableBufSize = true;
    EXPECT_EQ(mockHdcdTransfer->SimpleFileIO(&context, 0, nullptr, -1), -1);
}

// SimpleFileIO：bytes 超过 bufMaxSize → -1
HWTEST_F(HdcTransferTest, SimpleFileIO_TooLarge, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    context.isStableBufSize = true;
    int tooLarge = Base::GetUsbffsBulkSizeStable() + 1024;
    EXPECT_EQ(mockHdcdTransfer->SimpleFileIO(&context, 0, nullptr, tooLarge), -1);
}

// SimpleFileIO：ioFinish=true → -1
HWTEST_F(HdcTransferTest, SimpleFileIO_IOFinish, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    context.isStableBufSize = true;
    context.ioFinish = true;
    int bufLen = MAX_SIZE_IOBUF_STABLE * mockHdcdTransfer->maxTransferBufFactor;
    EXPECT_EQ(mockHdcdTransfer->SimpleFileIO(&context, 0, nullptr, bufLen), -1);
}

// SimpleFileIO：master=true, openFd=-1 → uv_fs_read 失败
HWTEST_F(HdcTransferTest, SimpleFileIO_MasterReadFail, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    context.isStableBufSize = true;
    context.master = true;
    context.openFd = -1;
    int bufLen = MAX_SIZE_IOBUF_STABLE * mockHdcdTransfer->maxTransferBufFactor;
    EXPECT_EQ(mockHdcdTransfer->SimpleFileIO(&context, 0, nullptr, bufLen), -1);
}

// SimpleFileIO：master=false, memcpy 失败（sendBuf=nullptr, bytes>0）
HWTEST_F(HdcTransferTest, SimpleFileIO_SlaveMemcpyFail, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    context.isStableBufSize = true;
    context.master = false;
    context.openFd = -1;
    int bufLen = MAX_SIZE_IOBUF_STABLE * mockHdcdTransfer->maxTransferBufFactor;
    EXPECT_EQ(mockHdcdTransfer->SimpleFileIO(&context, 0, nullptr, bufLen), -1);
}

// SimpleFileIO：非 stable buf 也走类似分支
HWTEST_F(HdcTransferTest, SimpleFileIO_NotStableBuf, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    context.isStableBufSize = false;
    context.master = true;
    context.openFd = -1;
    int bufLen = MAX_SIZE_IOBUF * mockHdcdTransfer->maxTransferBufFactor;
    EXPECT_EQ(mockHdcdTransfer->SimpleFileIO(&context, 0, nullptr, bufLen), -1);
}

// InitTransferPayload：不同 compressType
HWTEST_F(HdcTransferTest, InitTransferPayload_None, TestSize.Level0)
{
    HdcTransferBase::TransferPayload payloadHead;
    EXPECT_TRUE(mockHdcdTransfer->InitTransferPayload(payloadHead, 42,
                                                       HdcTransferBase::COMPRESS_NONE, 1024));
    EXPECT_EQ(payloadHead.compressType, HdcTransferBase::COMPRESS_NONE);
    EXPECT_EQ(payloadHead.uncompressSize, 1024u);
    EXPECT_EQ(payloadHead.index, 42ULL);
}

// InitTransferPayload：compressType=LZ4
HWTEST_F(HdcTransferTest, InitTransferPayload_LZ4, TestSize.Level0)
{
    HdcTransferBase::TransferPayload payloadHead;
    EXPECT_TRUE(mockHdcdTransfer->InitTransferPayload(payloadHead, 99,
                                                       HdcTransferBase::COMPRESS_LZ4, 2048));
    EXPECT_EQ(payloadHead.compressType, HdcTransferBase::COMPRESS_LZ4);
}

// SendIOPayload：dataSize=0 → 跳过压缩分支
HWTEST_F(HdcTransferTest, SendIOPayload_ZeroSize, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    uint8_t data[10] = {0};
    EXPECT_FALSE(mockHdcdTransfer->SendIOPayload(&context, 0, data, 0));
}

// ProcressFileIOWrite：indexIO >= fileSize → finished
HWTEST_F(HdcTransferTest, ProcressFileIOWrite_IndexExceeds, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    context.thisClass = mockHdcdTransfer;
    uv_fs_t req;
    req.result = 100;
    context.indexIO = 200;
    context.fileSize = 100;
    bool result = mockHdcdTransfer->ProcressFileIOWrite(&req, &context,
                                                         (HdcTransferBase *)context.thisClass);
    EXPECT_TRUE(result);
    EXPECT_EQ(context.closeNotify, true);
}

// ProcressFileIOWrite：req->result == 0 → finished
HWTEST_F(HdcTransferTest, ProcressFileIOWrite_ResultZero, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    context.thisClass = mockHdcdTransfer;
    uv_fs_t req;
    req.result = 0;
    context.indexIO = 50;
    context.fileSize = 100;
    bool result = mockHdcdTransfer->ProcressFileIOWrite(&req, &context,
                                                         (HdcTransferBase *)context.thisClass);
    EXPECT_TRUE(result);
    EXPECT_EQ(context.closeNotify, true);
}

// ProcressFileIOWrite：正常进行中 → false
HWTEST_F(HdcTransferTest, ProcressFileIOWrite_InProgress, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    context.thisClass = mockHdcdTransfer;
    uv_fs_t req;
    req.result = 50;
    context.indexIO = 50;
    context.fileSize = 200;
    bool result = mockHdcdTransfer->ProcressFileIOWrite(&req, &context,
                                                         (HdcTransferBase *)context.thisClass);
    EXPECT_FALSE(result);
}

// ProcressFileIOIsSuccess：req->result < 0 → false
HWTEST_F(HdcTransferTest, ProcressFileIOIsSuccess_ResultNeg, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    uv_fs_t req;
    req.result = -1;
    EXPECT_FALSE(mockHdcdTransfer->ProcressFileIOIsSuccess(&req, &context, 100));
    EXPECT_NE(context.lastErrno, 0u);
}

// ProcressFileIOIsSuccess：master=true → true（即使 bytes 不匹配）
HWTEST_F(HdcTransferTest, ProcressFileIOIsSuccess_Master, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    context.master = true;
    uv_fs_t req;
    req.result = 50;
    EXPECT_TRUE(mockHdcdTransfer->ProcressFileIOIsSuccess(&req, &context, 100));
}

// ProcressFileIOIsSuccess：非 master，bytes == req->result → true
HWTEST_F(HdcTransferTest, ProcressFileIOIsSuccess_BytesMatch, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    context.master = false;
    uv_fs_t req;
    req.result = 100;
    EXPECT_TRUE(mockHdcdTransfer->ProcressFileIOIsSuccess(&req, &context, 100));
}

// ProcressFileIOIsSuccess：非 master，bytes != req->result → 查 statfs
HWTEST_F(HdcTransferTest, ProcressFileIOIsSuccess_BytesMismatch, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    context.master = false;
    context.localPath = "/tmp";
    uv_fs_t req;
    req.result = 50;
    // statfs 调用会执行，结果取决于 /tmp 的可用空间
    bool result = mockHdcdTransfer->ProcressFileIOIsSuccess(&req, &context, 100);
    EXPECT_FALSE(result);
}

// ProcressFileIO：ioFinish=true → 直接返回 true
HWTEST_F(HdcTransferTest, ProcressFileIO_AlreadyFinish, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    context.thisClass = mockHdcdTransfer;
    context.ioFinish = true;
    uv_fs_t req;
    req.result = 0;
    EXPECT_TRUE(mockHdcdTransfer->ProcressFileIO(&req, &context,
                                                   (HdcTransferBase *)context.thisClass, 0));
}

// ProcressFileIO：!IsSuccess，非 master → CommandDispatch(CMD_FILE_FINISH)
HWTEST_F(HdcTransferTest, ProcressFileIO_NotSuccessNotMaster, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    context.thisClass = mockHdcdTransfer;
    context.ioFinish = false;
    context.master = false;
    uv_fs_t req;
    req.result = -1;
    req.fs_type = UV_FS_READ;
    bool result = mockHdcdTransfer->ProcressFileIO(&req, &context,
                                                     (HdcTransferBase *)context.thisClass, 100);
    EXPECT_TRUE(result);
    EXPECT_EQ(context.closeNotify, true);
}

// ProcressFileIO：UV_FS_READ 类型，IsSuccess=true
HWTEST_F(HdcTransferTest, ProcressFileIO_ReadType, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    context.thisClass = mockHdcdTransfer;
    context.ioFinish = false;
    context.master = true;
    uv_fs_t req;
    req.result = 0;
    req.fs_type = UV_FS_READ;
    // ProcressFileIORead 会访问 req->data，需设置 CtxFileIO
    HdcTransferBase::CtxFileIO *ioCtx = new HdcTransferBase::CtxFileIO();
    uint8_t *buf = new uint8_t[HdcTransferBase::payloadPrefixReserve + 10]();
    ioCtx->bufIO = buf + HdcTransferBase::payloadPrefixReserve;
    ioCtx->context = &context;
    req.data = ioCtx;
    bool result = mockHdcdTransfer->ProcressFileIO(&req, &context,
                                                     (HdcTransferBase *)context.thisClass, 100);
    EXPECT_TRUE(result);
    delete[] buf;
    delete ioCtx;
}

// ProcressFileIO：UV_FS_WRITE 类型
HWTEST_F(HdcTransferTest, ProcressFileIO_WriteType, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    context.thisClass = mockHdcdTransfer;
    context.ioFinish = false;
    context.master = false;
    uv_fs_t req;
    req.result = 100;
    req.fs_type = UV_FS_WRITE;
    context.indexIO = 0;
    context.fileSize = 200;
    bool result = mockHdcdTransfer->ProcressFileIO(&req, &context,
                                                     (HdcTransferBase *)context.thisClass, 100);
    EXPECT_FALSE(result);
}

// ProcressFileIO：其它 fs_type → return true
HWTEST_F(HdcTransferTest, ProcressFileIO_OtherType, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    context.thisClass = mockHdcdTransfer;
    context.ioFinish = false;
    context.master = true;
    uv_fs_t req;
    req.result = 100;
    req.fs_type = UV_FS_RENAME;
    bool result = mockHdcdTransfer->ProcressFileIO(&req, &context,
                                                     (HdcTransferBase *)context.thisClass, 100);
    EXPECT_TRUE(result);
}

// MatchPackageExtendName：找不到 → false
HWTEST_F(HdcTransferTest, MatchPackage_NotFound, TestSize.Level0)
{
    EXPECT_FALSE(mockHdcdTransfer->MatchPackageExtendName("file.txt", ".hap"));
}

// MatchPackageExtendName：找到但不在末尾 → false
HWTEST_F(HdcTransferTest, MatchPackage_NotAtEnd, TestSize.Level0)
{
    EXPECT_FALSE(mockHdcdTransfer->MatchPackageExtendName("file.hap.txt", ".hap"));
}

// MatchPackageExtendName：找到且在末尾 → true
HWTEST_F(HdcTransferTest, MatchPackage_AtEnd, TestSize.Level0)
{
    EXPECT_TRUE(mockHdcdTransfer->MatchPackageExtendName("file.hap", ".hap"));
}

// IsValidBundlePath：非法 bundleName → false
HWTEST_F(HdcTransferTest, IsValidBundlePath_Invalid, TestSize.Level0)
{
    EXPECT_FALSE(mockHdcdTransfer->IsValidBundlePath("invalid!"));
}

// IsValidBundlePath：合法但路径不存在 → false
HWTEST_F(HdcTransferTest, IsValidBundlePath_NotExist, TestSize.Level0)
{
    EXPECT_FALSE(mockHdcdTransfer->IsValidBundlePath("com.nonexist.app"));
}

// SmartSlavePath：非 server 模式，路径不存在
HWTEST_F(HdcTransferTest, SmartSlavePath_NotServer, TestSize.Level0)
{
    bool oldServer = mockHdcdTransfer->taskInfo->serverOrDaemon;
    mockHdcdTransfer->taskInfo->serverOrDaemon = false;
    string cwd = "/data/local/tmp/";
    string localPath = "/nonexist_path_xyz/file.txt";
    bool result = mockHdcdTransfer->SmartSlavePath(cwd, localPath, "file.txt");
    EXPECT_FALSE(result);
    mockHdcdTransfer->taskInfo->serverOrDaemon = oldServer;
}

// SmartSlavePath：server 模式
HWTEST_F(HdcTransferTest, SmartSlavePath_ServerMode, TestSize.Level0)
{
    bool oldServer = mockHdcdTransfer->taskInfo->serverOrDaemon;
    mockHdcdTransfer->taskInfo->serverOrDaemon = true;
    string cwd = "/data/local/tmp/";
    string localPath = "rel/file.txt";
    mockHdcdTransfer->SmartSlavePath(cwd, localPath, "file.txt");
    // 路径会被拼接
    EXPECT_NE(localPath.find("rel"), string::npos);
    mockHdcdTransfer->taskInfo->serverOrDaemon = oldServer;
}

// CheckLocalPath：optName 无 '/' → true（非目录模式）
HWTEST_F(HdcTransferTest, CheckLocalPath_NoDir, TestSize.Level0)
{
    string localPath = "/data/local/tmp/file.txt";
    string optName = "file.txt";
    string errStr;
    EXPECT_TRUE(mockHdcdTransfer->CheckLocalPath(localPath, optName, errStr));
}

// CheckFilename：optName 无 '/' 或 '\\' → true
HWTEST_F(HdcTransferTest, CheckFilename_NoDir, TestSize.Level0)
{
    string localPath = "/data/local/tmp/";
    string optName = "file.txt";
    string errStr;
    EXPECT_TRUE(mockHdcdTransfer->CheckFilename(localPath, optName, errStr));
}

// SetFileTime：holdTimestamp=false → 直接返回
HWTEST_F(HdcTransferTest, SetFileTime_NoHold, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    context.transferConfig.holdTimestamp = false;
    EXPECT_NO_FATAL_FAILURE(mockHdcdTransfer->SetFileTime(&context));
}

// SetFileTime：holdTimestamp=true 但 mtime=0 → 直接返回
HWTEST_F(HdcTransferTest, SetFileTime_ZeroMtime, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    context.transferConfig.holdTimestamp = true;
    context.transferConfig.mtime = 0;
    EXPECT_NO_FATAL_FAILURE(mockHdcdTransfer->SetFileTime(&context));
}

// RecvIOPayload：dataSize < payloadPrefixReserve → false
HWTEST_F(HdcTransferTest, RecvIOPayload_SmallSize, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    uint8_t data[10] = {0};
    EXPECT_FALSE(mockHdcdTransfer->RecvIOPayload(&context, data, 10));
}

// RecvIOPayload：dataSize 正好等于 payloadPrefixReserve（边界）
HWTEST_F(HdcTransferTest, RecvIOPayload_EqualPrefix, TestSize.Level0)
{
    HdcTransferBase::CtxFile context;
    uint8_t data[HdcTransferBase::payloadPrefixReserve] = {0};
    // compressSize=0, uncompressSize=0 → SimpleFileIO with bytes=0
    // bytes=0 < 0 is false, bytes > bufMaxSize is false
    // ioFinish=false, master=false, memcpy(bytes=0) OK, uv_fs_write(openFd=-1) fail
    bool result = mockHdcdTransfer->RecvIOPayload(&context, data, HdcTransferBase::payloadPrefixReserve);
    EXPECT_FALSE(result);
}

}
