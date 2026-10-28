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

#include "file_ut.h"

using namespace testing::ext;
using namespace testing;

namespace Hdc {

class HdcFileTest : public Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    class MockHdcFile : public HdcFile {
    public:
        explicit MockHdcFile(HTaskInfo hTaskInfo) : HdcFile(hTaskInfo) {}
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
        HdcFile *ptrTask = nullptr;
        ptrTask = new (std::nothrow) HdcFile(hTaskInfo);
        if (ptrTask == nullptr) {
            delete hTaskInfo;
            delete unittest;
            return nullptr;
        }
        hTaskInfo->taskClass = ptrTask;
        return hTaskInfo;
    }

    HTaskInfo hTaskInfo;
    MockHdcFile *mockHdcdFile;
};

void HdcFileTest::SetUpTestCase()
{
#ifdef UT_DEBUG
    Hdc::Base::SetLogLevel(LOG_ALL);
#else
    Hdc::Base::SetLogLevel(LOG_OFF);
#endif
}
void HdcFileTest::TearDownTestCase() {}
void HdcFileTest::SetUp()
{
    hTaskInfo = BuildPTask();
    mockHdcdFile = new (std::nothrow) MockHdcFile(hTaskInfo);
}
void HdcFileTest::TearDown()
{
    delete mockHdcdFile;
    mockHdcdFile = nullptr;
}

HWTEST_F(HdcFileTest, TestStopTask, TestSize.Level0)
{
    mockHdcdFile->StopTask();
    ASSERT_EQ(mockHdcdFile->singalStop, true);
}

HWTEST_F(HdcFileTest, TestBegintarnsfer, TestSize.Level0)
{
    HdcFile::CtxFile context;
    // case 1: argc < CMD_ARG1_COUNT
    std::string command = "-cwd";
    bool result = mockHdcdFile->BeginTransfer(&context, command);
    EXPECT_FALSE(result);
    // case 2: argv == nullptr
    command = "";
    result = mockHdcdFile->BeginTransfer(&context, command);
    EXPECT_FALSE(result);
}

HWTEST_F(HdcFileTest, TestCheckBlacklistPath, TestSize.Level0)
{
    HdcFile::CtxFile context;
    // case 1: path not in blacklist
    context.localPath = "/data/service/el1/public/validpath";
    ASSERT_EQ(mockHdcdFile->CheckBlacklistPath(&context), true);

    // case 2: path in blacklist
    context.localPath = "/data/service/el1/public/hdc";
    ASSERT_EQ(mockHdcdFile->CheckBlacklistPath(&context), false);

    // case 3: path in blacklist
    context.localPath = "/data/service/el1/public/../public/hdc";
    ASSERT_EQ(mockHdcdFile->CheckBlacklistPath(&context), false);

    // case 4: path in blacklist
    context.localPath = "/data/service/../service/el1/public/hdc";
    ASSERT_EQ(mockHdcdFile->CheckBlacklistPath(&context), false);

    // case 5: path in blacklist
    context.localPath = "/data/service/el1/public/../../../service/el1/public/hdc";
    ASSERT_EQ(mockHdcdFile->CheckBlacklistPath(&context), false);
}

HWTEST_F(HdcFileTest, TestParseMasterParameters, TestSize.Level0)
{
    HdcFile::CtxFile context;
    int argc = 0, srcArgvIndex = 0;
    char arg0[] = "-b";
    char arg1[] = "-z";
    char arg2[] = "-sync";
    char arg3[] = "-a";
    char arg4[] = "-m";
    char *argBase[] = {arg0, arg1, arg2, arg3, arg4};
    char argFirst[] = "-cwd";
    char argRemotePath[] = "D:\\";
    char argBundleName[] = "com.example.myapplication";
    char argLocalPath[] = "data/local/tmp/test.txt";
    // case 1: -b Parameter ok
    argc = 5;
    char *argvB[] = {argFirst, argRemotePath, argBase[0], argBundleName, argLocalPath};
    bool result = mockHdcdFile->ParseMasterParameters(&context, argc, argvB, srcArgvIndex);
    EXPECT_TRUE(result);
    EXPECT_EQ(context.bundleName, "com.example.myapplication");
    EXPECT_EQ(srcArgvIndex, argc - 1);
    // case 2: -b MissingParameter
    argc = 4;
    srcArgvIndex = 0;
    char *argvBInvalid[] = {argFirst, argRemotePath, argBase[0], argLocalPath};
    result = mockHdcdFile->ParseMasterParameters(&context, argc, argvBInvalid, srcArgvIndex);
    EXPECT_FALSE(result);
    EXPECT_EQ(srcArgvIndex, argc);
    int i = 1;
    int numArgs = sizeof(argBase) / sizeof(argBase[0]);
    for (i = 1; i < numArgs; i++)
    {
        argc = 4;
        srcArgvIndex = 0;
        // case: argBase Parameter ok
        char *argv[] = {argFirst, argRemotePath, argBase[i], argLocalPath};
        result = mockHdcdFile->ParseMasterParameters(&context, argc, argv, srcArgvIndex);
        EXPECT_TRUE(result);
        EXPECT_EQ(srcArgvIndex, argc - 1);

        argc = 3;
        srcArgvIndex = 0;
        // case: argBase MissingParameter
        char *argvInvalid[] = {argFirst, argRemotePath, argBase[i]};
        result = mockHdcdFile->ParseMasterParameters(&context, argc, argvInvalid, srcArgvIndex);
        EXPECT_FALSE(result);
        EXPECT_EQ(srcArgvIndex, argc);
    }
}

HWTEST_F(HdcFileTest, TestCheckSandboxSubPath, TestSize.Level0)
{
    HdcFile::CtxFile context;
    // case 1: application path
    string resolvedPath;
    context.bundleName = "com.example.myapplication";
    context.inputLocalPath = "data/storage/el2/base/";
    ASSERT_EQ(mockHdcdFile->CheckSandboxSubPath(&context, resolvedPath), true);
    std::stringstream ss;
    ss << "/mnt/debug/100/debug_hap/com.example.myapplication/data/storage/el2/";
    ASSERT_EQ(resolvedPath, ss.str());
}

HWTEST_F(HdcFileTest, TestSetMasterParameters, TestSize.Level0)
{
    HdcFile::CtxFile context;
    char arg0[] = "-b";
    char arg1[] = "-z";
    char arg2[] = "-sync";
    char arg3[] = "-a";
    char arg4[] = "-m";
    char *argBase[] = {arg0, arg1, arg2, arg3, arg4};
    char argFirst[] = "-cwd";
    char argRemotePath[] = "D:\\";
    char argBundleName[] = "com.example.myapplication";
    char argLocalPath[] = "data/local/tmp/test.txt";
    char argInvalidBundlePath[] = "../../../../test.txt";
    std::filesystem::path testPath = "/mnt/debug/100/debug_hap/com.example.myapplication/data/local/tmp/";
    if (!std::filesystem::exists(testPath))
    {
        std::filesystem::create_directories(testPath);
    }
    ASSERT_TRUE(std::filesystem::exists(testPath));
    // case 1: -b Parameter ok
    int argc = 5;
    context.transferConfig.clientCwd = argRemotePath;
    char *argvB[] = {argFirst, argRemotePath, argBase[0], argBundleName, argLocalPath};
    std::stringstream ss;
    ss << "/mnt/debug/100/debug_hap/com.example.myapplication/data/local/tmp//test.txt";
    EXPECT_EQ(mockHdcdFile->SetMasterParameters(&context, argc, argvB), true);
    EXPECT_EQ(context.bundleName, "com.example.myapplication");
    EXPECT_EQ(context.localPath, ss.str());
    EXPECT_EQ(context.localName, "test.txt");
    // case 2: -b serverOrDaemon == true
    hTaskInfo->serverOrDaemon = true;
    EXPECT_EQ(mockHdcdFile->SetMasterParameters(&context, argc, argvB), false);
    // case 3: -b InvalidBundlePath
    hTaskInfo->serverOrDaemon = false;
    char *argvBInvalidBundlePath[] = {argFirst, argRemotePath, argBase[0], argBundleName, argInvalidBundlePath};
    EXPECT_EQ(mockHdcdFile->SetMasterParameters(&context, argc, argvBInvalidBundlePath), false);
    // case 4: -b MissingParameter
    argc = 4;
    char *argvBInvalid[] = {argFirst, argRemotePath, argBase[0], argLocalPath};
    EXPECT_EQ(mockHdcdFile->SetMasterParameters(&context, argc, argvBInvalid), false);
    context.bundleName = "";
    context.transferConfig.reserve1 = "";

    int i = 1;
    int numArgs = sizeof(argBase) / sizeof(argBase[0]);
    for (i = 1; i < numArgs; i++)
    {
        argc = 4;
        // case: argBase Parameter ok
        char *argv[] = {argFirst, argRemotePath, argBase[i], argLocalPath};
        EXPECT_EQ(mockHdcdFile->SetMasterParameters(&context, argc, argv), true);
        argc = 3;
        // case: argBase MissingParameter
        char *argvInvalid[] = {argFirst, argRemotePath, argBase[i]};
        EXPECT_EQ(mockHdcdFile->SetMasterParameters(&context, argc, argvInvalid), false);
    }
}

HWTEST_F(HdcFileTest, TestIsPathInsideSandbox, TestSize.Level0)
{
    {
        // case 1: 在沙箱路径
        const string path = "data/storage/el2/base/com.example.myapplication/data/file.txt";
        const string appDir = "data/storage/el2/base/com.example.myapplication";
        ASSERT_TRUE(mockHdcdFile->IsPathInsideSandbox(path, appDir));
    }

    {
        // case 2: 不在沙箱路径
        const string path = "data/storage/el2/base/com.example.yourapplication/file.txt";
        const string appDir = "data/storage/el2/base/com.example.myapplication";
        ASSERT_FALSE(mockHdcdFile->IsPathInsideSandbox(path, appDir));
    }

    {
        // case 3: 路径长度小于沙箱路径
        const string path = "data/local/tmp/file.txt";
        const string appDir = "data/storage/el2/base/com.example.myapplication";
        ASSERT_FALSE(mockHdcdFile->IsPathInsideSandbox(path, appDir));
    }
}


HWTEST_F(HdcFileTest, TestSetMasterParametersOnDaemon, TestSize.Level0)
{
    HdcFile::CtxFile context;
    char arg0[] = "-b";
    char argFirst[] = "-cwd";
    char argRemotePath[] = "D:\\";
    char argBundleName[] = "com.example.myapplication";
    char argLocalPath[] = "data/local/tmp/test.txt";
    char argInvalidBundlePath[] = "../../../../test.txt";
    std::filesystem::path testPath = "/mnt/debug/100/debug_hap/com.example.myapplication/data/local/tmp/";
    if (!std::filesystem::exists(testPath))
    {
        std::filesystem::create_directories(testPath);
    }
    ASSERT_TRUE(std::filesystem::exists(testPath));

    {
        // case 1: normal
        int argc = 5;
        context.sandboxMode = true;
        context.transferConfig.reserve1 = "com.example.myapplication";
        char *argvB[] = {argFirst, argRemotePath, arg0, argBundleName, argLocalPath};
        EXPECT_EQ(mockHdcdFile->SetMasterParametersOnDaemon(&context, argc, argvB, argc), true);
    }

    {
        // case 1: Invalid bundle name
        int argc = 5;
        context.sandboxMode = true;
        context.transferConfig.reserve1 = "com.example.test";
        char *argvB[] = {argFirst, argRemotePath, arg0, argBundleName, argInvalidBundlePath};
        EXPECT_EQ(mockHdcdFile->SetMasterParametersOnDaemon(&context, argc, argvB, argc), false);
    }
}

HWTEST_F(HdcFileTest, TestParseAndValidateOptions, TestSize.Level0)
{
    HdcFile::CtxFile ctxNow;
    ctxNow.transferConfig.fileSize = 102400;
    ctxNow.transferConfig.path = "data/local/tmp/file.txt";
    ctxNow.transferConfig.reserve1 = "com.example.myapplication";

    // case 1: application path
    string s = SerialStruct::SerializeToString(ctxNow.transferConfig);
    bool result = mockHdcdFile->ParseAndValidateOptions(reinterpret_cast<uint8_t*>(s.data()), s.size());
    ASSERT_TRUE(result);
}

HWTEST_F(HdcFileTest, TestCheckBundleAndPath, TestSize.Level0)
{
    HdcFile::CtxFile ctxNow;
    hTaskInfo->serverOrDaemon = true;
    bool result = mockHdcdFile->CheckBundleAndPath();
    ASSERT_TRUE(result);
}

// CheckBundleAndPath：daemon 模式（serverOrDaemon=false）不崩溃
HWTEST_F(HdcFileTest, TestCheckBundleAndPath_DaemonMode, TestSize.Level0)
{
    HdcFile::CtxFile ctxNow;
    hTaskInfo->serverOrDaemon = false;
    EXPECT_NO_FATAL_FAILURE((void)mockHdcdFile->CheckBundleAndPath());
}

// CheckBundleAndPath：连续两次调用不崩溃（覆盖重复进入分支）
HWTEST_F(HdcFileTest, TestCheckBundleAndPath_Twice, TestSize.Level0)
{
    hTaskInfo->serverOrDaemon = true;
    EXPECT_NO_FATAL_FAILURE((void)mockHdcdFile->CheckBundleAndPath());
    EXPECT_NO_FATAL_FAILURE((void)mockHdcdFile->CheckBundleAndPath());
}

// ====== Incremental UT cases (2026) ======

// BeginTransfer：argc < CMD_ARG1_COUNT → false
HWTEST_F(HdcFileTest, BeginTransfer_TooFewArgs, TestSize.Level0)
{
    HdcFile::CtxFile context;
    EXPECT_FALSE(mockHdcdFile->BeginTransfer(&context, "single"));
}

// BeginTransfer：未知选项 → SetMasterParameters 失败 → false
HWTEST_F(HdcFileTest, BeginTransfer_UnknownOption, TestSize.Level0)
{
    HdcFile::CtxFile context;
    EXPECT_FALSE(mockHdcdFile->BeginTransfer(&context, "-x local remote"));
}

// BeginTransfer：黑名单路径 → false
HWTEST_F(HdcFileTest, BeginTransfer_BlacklistPath, TestSize.Level0)
{
    HdcFile::CtxFile context;
    EXPECT_FALSE(mockHdcdFile->BeginTransfer(&context, "/data/service/el1/public/hdc test.txt"));
}

// CheckBlacklistPath：第二条黑名单
HWTEST_F(HdcFileTest, CheckBlacklistPath_SecondBlacklist, TestSize.Level0)
{
    HdcFile::CtxFile context;
    context.localPath = "/data/service/el2/public/hdc_service";
    ASSERT_FALSE(mockHdcdFile->CheckBlacklistPath(&context));
}

// CheckBlacklistPath：空路径 → true
HWTEST_F(HdcFileTest, CheckBlacklistPath_EmptyPath, TestSize.Level0)
{
    HdcFile::CtxFile context;
    context.localPath = "";
    ASSERT_TRUE(mockHdcdFile->CheckBlacklistPath(&context));
}

// CheckBlacklistPath：合法长路径 → true
HWTEST_F(HdcFileTest, CheckBlacklistPath_ValidLongPath, TestSize.Level0)
{
    HdcFile::CtxFile context;
    context.localPath = "/data/local/tmp/sub/dir/file.txt";
    ASSERT_TRUE(mockHdcdFile->CheckBlacklistPath(&context));
}

// containsBlacklistedSubstring：命中
HWTEST_F(HdcFileTest, ContainsBlacklistedSubstring_Match, TestSize.Level0)
{
    std::unordered_set<std::string> blacklist = {"/bad/path"};
    EXPECT_TRUE(mockHdcdFile->containsBlacklistedSubstring("/bad/path/file", blacklist));
}

// containsBlacklistedSubstring：未命中
HWTEST_F(HdcFileTest, ContainsBlacklistedSubstring_NoMatch, TestSize.Level0)
{
    std::unordered_set<std::string> blacklist = {"/bad/path"};
    EXPECT_FALSE(mockHdcdFile->containsBlacklistedSubstring("/good/path/file", blacklist));
}

// ParseMasterParameters：-z 压缩选项
HWTEST_F(HdcFileTest, ParseMasterParameters_ZipOption, TestSize.Level0)
{
    HdcFile::CtxFile context;
    char argFirst[] = "-cwd";
    char argRemote[] = "D:\\";
    char argZip[] = "-z";
    char argLocal[] = "data/local/tmp/test.txt";
    char *argv[] = {argFirst, argRemote, argZip, argLocal};
    int srcArgvIndex = 0;
    EXPECT_TRUE(mockHdcdFile->ParseMasterParameters(&context, 4, argv, srcArgvIndex));
    EXPECT_EQ(context.transferConfig.compressType, HdcFile::COMPRESS_LZ4);
}

// ParseMasterParameters：-sync 选项
HWTEST_F(HdcFileTest, ParseMasterParameters_SyncOption, TestSize.Level0)
{
    HdcFile::CtxFile context;
    char argFirst[] = "-cwd";
    char argRemote[] = "D:\\";
    char argSync[] = "-sync";
    char argLocal[] = "data/local/tmp/test.txt";
    char *argv[] = {argFirst, argRemote, argSync, argLocal};
    int srcArgvIndex = 0;
    EXPECT_TRUE(mockHdcdFile->ParseMasterParameters(&context, 4, argv, srcArgvIndex));
    EXPECT_TRUE(context.transferConfig.updateIfNew);
}

// ParseMasterParameters：-m 模式同步选项
HWTEST_F(HdcFileTest, ParseMasterParameters_ModeSyncOption, TestSize.Level0)
{
    HdcFile::CtxFile context;
    char argFirst[] = "-cwd";
    char argRemote[] = "D:\\";
    char argM[] = "-m";
    char argLocal[] = "data/local/tmp/test.txt";
    char *argv[] = {argFirst, argRemote, argM, argLocal};
    int srcArgvIndex = 0;
    EXPECT_TRUE(mockHdcdFile->ParseMasterParameters(&context, 4, argv, srcArgvIndex));
    EXPECT_TRUE(context.fileModeSync);
}

// ParseMasterParameters：-a 时间戳选项
HWTEST_F(HdcFileTest, ParseMasterParameters_TstmpOption, TestSize.Level0)
{
    HdcFile::CtxFile context;
    char argFirst[] = "-cwd";
    char argRemote[] = "D:\\";
    char argA[] = "-a";
    char argLocal[] = "data/local/tmp/test.txt";
    char *argv[] = {argFirst, argRemote, argA, argLocal};
    int srcArgvIndex = 0;
    EXPECT_TRUE(mockHdcdFile->ParseMasterParameters(&context, 4, argv, srcArgvIndex));
    EXPECT_TRUE(context.transferConfig.holdTimestamp);
}

// ParseMasterParameters：remote 参数
HWTEST_F(HdcFileTest, ParseMasterParameters_RemoteParameter, TestSize.Level0)
{
    HdcFile::CtxFile context;
    char argRemote[] = "remote";
    char argPath1[] = "data/local/tmp/test.txt";
    char argPath2[] = "/data/test";
    char *argv[] = {argRemote, argPath1, argPath2};
    int srcArgvIndex = 0;
    EXPECT_TRUE(mockHdcdFile->ParseMasterParameters(&context, 3, argv, srcArgvIndex));
    EXPECT_EQ(srcArgvIndex, 1);
}

// ParseMasterParameters：未知选项 → false
HWTEST_F(HdcFileTest, ParseMasterParameters_UnknownOption, TestSize.Level0)
{
    HdcFile::CtxFile context;
    char argUnknown[] = "-x";
    char argPath1[] = "local";
    char argPath2[] = "remote";
    char *argv[] = {argUnknown, argPath1, argPath2};
    int srcArgvIndex = 0;
    EXPECT_FALSE(mockHdcdFile->ParseMasterParameters(&context, 3, argv, srcArgvIndex));
}

// ParseMasterParameters：argc == srcArgvIndex → 无路径 → false
HWTEST_F(HdcFileTest, ParseMasterParameters_NoLocalRemote, TestSize.Level0)
{
    HdcFile::CtxFile context;
    char argZip[] = "-z";
    char *argv[] = {argZip};
    int srcArgvIndex = 0;
    EXPECT_FALSE(mockHdcdFile->ParseMasterParameters(&context, 1, argv, srcArgvIndex));
}

// SetMasterParameters：server 模式无 remote → false
HWTEST_F(HdcFileTest, SetMasterParameters_ServerNoRemote, TestSize.Level0)
{
    HdcFile::CtxFile context;
    hTaskInfo->serverOrDaemon = true;
    char argZip[] = "-z";
    char argLocal[] = "data/local/tmp/test.txt";
    char *argv[] = {argZip, argLocal};
    EXPECT_FALSE(mockHdcdFile->SetMasterParameters(&context, 2, argv));
}

// IsPathInsideSandbox：path.size() == appDir.size()
HWTEST_F(HdcFileTest, IsPathInsideSandbox_EqualLength, TestSize.Level0)
{
    const string path = "/mnt/debug/100/debug_hap/com.example.app";
    const string appDir = "/mnt/debug/100/debug_hap/com.example.app";
    EXPECT_TRUE(mockHdcdFile->IsPathInsideSandbox(path, appDir));
}

// IsPathInsideSandbox：两个空字符串
HWTEST_F(HdcFileTest, IsPathInsideSandbox_EmptyStrings, TestSize.Level0)
{
    EXPECT_TRUE(mockHdcdFile->IsPathInsideSandbox("", ""));
}

// PathSimplify：正常路径
HWTEST_F(HdcFileTest, PathSimplify_NormalPath, TestSize.Level0)
{
    EXPECT_EQ(mockHdcdFile->PathSimplify("/a/b/c"), "/a/b/c");
}

// PathSimplify：../ 穿越
HWTEST_F(HdcFileTest, PathSimplify_DotDotTraversal, TestSize.Level0)
{
    EXPECT_EQ(mockHdcdFile->PathSimplify("/a/b/../c"), "/a/c");
}

// PathSimplify：空路径 → "/"
HWTEST_F(HdcFileTest, PathSimplify_EmptyPath, TestSize.Level0)
{
    EXPECT_EQ(mockHdcdFile->PathSimplify(""), "/");
}

// PathSimplify：. 路径被忽略
HWTEST_F(HdcFileTest, PathSimplify_DotPath, TestSize.Level0)
{
    EXPECT_EQ(mockHdcdFile->PathSimplify("/a/./b"), "/a/b");
}

// PathSimplify：连续 ../ 越界不崩溃
HWTEST_F(HdcFileTest, PathSimplify_ExcessiveDotDot, TestSize.Level0)
{
    EXPECT_EQ(mockHdcdFile->PathSimplify("/a/../../../b"), "/b");
}

// CheckSandboxSubPath：路径穿越 → false
HWTEST_F(HdcFileTest, CheckSandboxSubPath_TraversalFail, TestSize.Level0)
{
    HdcFile::CtxFile context;
    context.bundleName = "com.example.test";
    context.inputLocalPath = "../../etc/passwd";
    string resolvedPath;
    EXPECT_FALSE(mockHdcdFile->CheckSandboxSubPath(&context, resolvedPath));
}

// ValidateAndSetPaths：非沙箱模式正常
HWTEST_F(HdcFileTest, ValidateAndSetPaths_NoSandbox, TestSize.Level0)
{
    HdcFile::CtxFile context;
    char argLocal[] = "data/local/tmp/test.txt";
    char argRemote[] = "/data/test";
    char *argv[] = {argLocal, argRemote};
    int srcArgvIndex = 0;
    EXPECT_TRUE(mockHdcdFile->ValidateAndSetPaths(&context, 2, argv, srcArgvIndex));
    EXPECT_EQ(context.localPath, "data/local/tmp/test.txt");
    EXPECT_EQ(context.remotePath, "/data/test");
}

// ValidateAndSetPaths：argc == srcArgvIndex → false
HWTEST_F(HdcFileTest, ValidateAndSetPaths_NoPaths, TestSize.Level0)
{
    HdcFile::CtxFile context;
    char argZip[] = "-z";
    char *argv[] = {argZip};
    int srcArgvIndex = 1;
    EXPECT_FALSE(mockHdcdFile->ValidateAndSetPaths(&context, 1, argv, srcArgvIndex));
}

// CheckBundleAndPath：daemon 模式非法 bundle → false
HWTEST_F(HdcFileTest, CheckBundleAndPath_DaemonInvalidBundle, TestSize.Level0)
{
    hTaskInfo->serverOrDaemon = false;
    mockHdcdFile->ctxNow.bundleName = "xx";
    EXPECT_FALSE(mockHdcdFile->CheckBundleAndPath());
}

// CheckBundleAndPath：daemon 模式空 bundle → true
HWTEST_F(HdcFileTest, CheckBundleAndPath_DaemonEmptyBundle, TestSize.Level0)
{
    hTaskInfo->serverOrDaemon = false;
    mockHdcdFile->ctxNow.bundleName = "";
    EXPECT_TRUE(mockHdcdFile->CheckBundleAndPath());
}

// CheckBundleAndPath：server 模式 → true
HWTEST_F(HdcFileTest, CheckBundleAndPath_ServerMode, TestSize.Level0)
{
    hTaskInfo->serverOrDaemon = true;
    mockHdcdFile->ctxNow.bundleName = "com.example.test";
    EXPECT_TRUE(mockHdcdFile->CheckBundleAndPath());
}

// CommandDispatch：未知命令 → default → true
HWTEST_F(HdcFileTest, CommandDispatch_UnknownCommand, TestSize.Level0)
{
    uint8_t payload = 0;
    EXPECT_TRUE(mockHdcdFile->CommandDispatch(static_cast<uint16_t>(99999), &payload, 1));
}

// CommandDispatch：CMD_FILE_INIT 短命令 → false
HWTEST_F(HdcFileTest, CommandDispatch_FileInitShort, TestSize.Level0)
{
    uint8_t payload[] = "x";
    EXPECT_FALSE(mockHdcdFile->CommandDispatch(CMD_FILE_INIT, payload, 1));
}

// StopTask：验证 singalStop 被设置
HWTEST_F(HdcFileTest, StopTask_SetsSignalStop, TestSize.Level0)
{
    mockHdcdFile->singalStop = false;
    mockHdcdFile->StopTask();
    EXPECT_TRUE(mockHdcdFile->singalStop);
}

// SetMasterParametersOnDaemon：非沙箱 + 单路径 (srcArgvIndex+1==argc 分支，localPath 取 argv[srcArgvIndex])
HWTEST_F(HdcFileTest, SetMasterParametersOnDaemon_NonSandboxSinglePath, TestSize.Level0)
{
    HdcFile::CtxFile context;
    context.sandboxMode = false;
    char argLocal[] = "data/local/tmp/test.txt";
    char argRemote[] = "/remote";
    char *argv[] = {argLocal, argRemote};
    EXPECT_TRUE(mockHdcdFile->SetMasterParametersOnDaemon(&context, 2, argv, 1));
    EXPECT_EQ(context.localPath, "/remote");
}

// SetMasterParametersOnDaemon：沙箱模式非法 bundle → false
HWTEST_F(HdcFileTest, SetMasterParametersOnDaemon_SandboxInvalidBundle, TestSize.Level0)
{
    HdcFile::CtxFile context;
    context.sandboxMode = true;
    context.transferConfig.reserve1 = "invalid_bundle";
    char argLocal[] = "data/local/tmp/test.txt";
    char argRemote[] = "/remote";
    char *argv[] = {argLocal, argRemote};
    EXPECT_FALSE(mockHdcdFile->SetMasterParametersOnDaemon(&context, 2, argv, 0));
}

}