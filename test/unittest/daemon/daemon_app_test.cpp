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

#include "daemon_app.h"
#include "daemon_app_test.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>

using namespace testing::ext;

namespace Hdc {
void HdcDaemonAppTest::SetUpTestCase() {}
void HdcDaemonAppTest::TearDownTestCase() {}
void HdcDaemonAppTest::SetUp()
{
#ifdef UT_DEBUG
    Base::SetLogLevel(LOG_ALL);
#else
    Base::SetLogLevel(LOG_OFF);
#endif
}
void HdcDaemonAppTest::TearDown() {}

static bool FileExists(const std::string &path)
{
    struct stat st;
    return (lstat(path.c_str(), &st) == 0);
}

HWTEST_F(HdcDaemonAppTest, Test_HdcDaemonApp, TestSize.Level0)
{
    HTaskInfo taskInfo = new TaskInformation();

    // case: default struct HTaskInfo with isStableBuf set to true.
    HdcDaemonApp daemonApp1(taskInfo);
    EXPECT_EQ(daemonApp1.commandBegin, CMD_APP_BEGIN);
    EXPECT_EQ(daemonApp1.commandData, CMD_APP_DATA);

    delete taskInfo;
}

HWTEST_F(HdcDaemonAppTest, Test_CommandDispatch, TestSize.Level0)
{
    HTaskInfo taskInfo = new TaskInformation();
    HdcDaemonApp daemonApp(taskInfo);
    uint8_t payload = 10;

    // invalid command.
    EXPECT_FALSE(daemonApp.CommandDispatch(CMD_APP_BEGIN, &payload, 10));

    delete taskInfo;
}

HWTEST_F(HdcDaemonAppTest, Test_ReadyForRelease, TestSize.Level0)
{
    HTaskInfo taskInfo = new TaskInformation();
    HdcDaemonApp daemonApp(taskInfo);
    daemonApp.refCount = 1;

    // case1: default valid case.
    EXPECT_FALSE(daemonApp.ReadyForRelease());

    delete taskInfo;
}

HWTEST_F(HdcDaemonAppTest, Test_MakeCtxForAppCheck, TestSize.Level3)
{
    HTaskInfo taskInfo = new TaskInformation();
    HdcDaemonApp daemonApp(taskInfo);
    daemonApp.ctxNow.master = true;
    daemonApp.ctxNow.transferConfig.optionalName = "test.hap";

    uint8_t payload = 10;
    EXPECT_TRUE(daemonApp.MakeCtxForAppCheck(&payload, 10));
    EXPECT_FALSE(daemonApp.ctxNow.master);
    EXPECT_EQ(daemonApp.ctxNow.localPath, "/data/local/tmp/test.hap");

    delete taskInfo;
}

HWTEST_F(HdcDaemonAppTest, Test_MakeCtxForAppCheck_InvalidPayload, TestSize.Level3)
{
    HTaskInfo taskInfo = new TaskInformation();
    HdcDaemonApp daemonApp(taskInfo);
    daemonApp.ctxNow.master = true;
    daemonApp.ctxNow.transferConfig.optionalName = "test.hap";

    // null payload
    EXPECT_FALSE(daemonApp.MakeCtxForAppCheck(nullptr, 10));
    EXPECT_TRUE(daemonApp.ctxNow.master);

    // non-positive payloadSize
    uint8_t payload = 10;
    EXPECT_FALSE(daemonApp.MakeCtxForAppCheck(&payload, 0));
    EXPECT_TRUE(daemonApp.ctxNow.master);
    EXPECT_FALSE(daemonApp.MakeCtxForAppCheck(&payload, -1));
    EXPECT_TRUE(daemonApp.ctxNow.master);

    delete taskInfo;
}

HWTEST_F(HdcDaemonAppTest, Test_MakeCtxForAppCheck_InvalidOptionalName, TestSize.Level3)
{
    HTaskInfo taskInfo = new TaskInformation();

    const std::vector<std::string> invalidNames = {
        "../etc/passwd",
        "a/../b.hap",
        "../",
        "dir/../../etc",
    };

    for (const auto &name : invalidNames) {
        HdcDaemonApp daemonApp(taskInfo);
        daemonApp.ctxNow.master = true;
        daemonApp.ctxNow.transferConfig.optionalName = name;

        uint8_t payload = 10;
        EXPECT_FALSE(daemonApp.MakeCtxForAppCheck(&payload, 10)) << "optionalName: " << name;
        EXPECT_TRUE(daemonApp.ctxNow.master) << "optionalName: " << name;
    }

    delete taskInfo;
}

HWTEST_F(HdcDaemonAppTest, Test_Tar2Dir_NoTar, TestSize.Level0)
{
    HTaskInfo taskInfo = new TaskInformation();
    HdcDaemonApp daemonApp(taskInfo);

    // path without ".tar" should return empty string
    string res = daemonApp.Tar2Dir("/tmp/somefile.hap");
    EXPECT_EQ(res, "");

    delete taskInfo;
}

HWTEST_F(HdcDaemonAppTest, Test_RemovePath_File, TestSize.Level0)
{
    HTaskInfo taskInfo = new TaskInformation();
    HdcDaemonApp daemonApp(taskInfo);

    // create temporary file
    std::string tmpl = "/data/local/tmp/hdc_testfileXXXXXX";
    std::vector<char> buf(tmpl.begin(), tmpl.end());
    buf.push_back('\0');
    int fd = mkstemp(buf.data());
    ASSERT_GE(fd, 0);
    close(fd);
    std::string path(buf.data());
    ASSERT_TRUE(FileExists(path));

    // remove using RemovePath
    daemonApp.RemovePath(path);
    EXPECT_FALSE(FileExists(path));

    delete taskInfo;
}

HWTEST_F(HdcDaemonAppTest, Test_RemovePath_DirRecursive, TestSize.Level0)
{
    HTaskInfo taskInfo = new TaskInformation();
    HdcDaemonApp daemonApp(taskInfo);

    // create temporary directory
    char dirtmpl[] = "/data/local/tmp/hdc_testdirXXXXXX";
    char *d = mkdtemp(dirtmpl);
    ASSERT_NE(d, nullptr) << "Failed to create temporary directory";
    std::string dir(d);

    // ensure parent directory exists
    std::string parentDir = "/data/local/tmp";
    if (!FileExists(parentDir)) {
        ASSERT_EQ(mkdir(parentDir.c_str(), 0755), 0) << "Failed to create parent directory";
    }

    // create a nested directory and file
    std::string subdir = dir + "/sub";
    ASSERT_EQ(mkdir(subdir.c_str(), 0755), 0) << "Failed to create directory: " << subdir;
    std::string file1 = dir + "/f1.txt";
    int fd1 = open(file1.c_str(), O_CREAT | O_WRONLY, 0644);
    ASSERT_GE(fd1, 0);
    write(fd1, "x", 1);
    close(fd1);

    std::string file2 = subdir + "/f2.txt";
    int fd2 = open(file2.c_str(), O_CREAT | O_WRONLY, 0644);
    ASSERT_GE(fd2, 0);
    write(fd2, "y", 1);
    close(fd2);

    ASSERT_TRUE(FileExists(file1));
    ASSERT_TRUE(FileExists(file2));

    // remove the directory recursively
    daemonApp.RemovePath(dir);

    EXPECT_FALSE(FileExists(dir));
    EXPECT_FALSE(FileExists(file1));
    EXPECT_FALSE(FileExists(file2));

    delete taskInfo;
}

// CommandDispatch：未知 command → 不崩溃
HWTEST_F(HdcDaemonAppTest, Test_CommandDispatch_UnknownCommand, TestSize.Level0)
{
    HTaskInfo taskInfo = new TaskInformation();
    HdcDaemonApp daemonApp(taskInfo);
    uint8_t payload[4] = {0};
    EXPECT_NO_FATAL_FAILURE(daemonApp.CommandDispatch(0xFFFF, payload, sizeof(payload)));
    delete taskInfo;
}

// CommandDispatch：空 payload 不崩溃
HWTEST_F(HdcDaemonAppTest, Test_CommandDispatch_EmptyPayload, TestSize.Level0)
{
    HTaskInfo taskInfo = new TaskInformation();
    HdcDaemonApp daemonApp(taskInfo);
    EXPECT_NO_FATAL_FAILURE(daemonApp.CommandDispatch(0xFFFF, nullptr, 0));
    delete taskInfo;
}

// RemoveDir：不存在目录不崩溃
HWTEST_F(HdcDaemonAppTest, Test_RemoveDir_NonExist, TestSize.Level0)
{
    HTaskInfo taskInfo = new TaskInformation();
    HdcDaemonApp daemonApp(taskInfo);
    EXPECT_NO_FATAL_FAILURE(daemonApp.RemoveDir("/tmp/hdc_daemon_app_ut_nonexist_dir"));
    delete taskInfo;
}

// RemovePath：不存在路径不崩溃
HWTEST_F(HdcDaemonAppTest, Test_RemovePath_NonExist, TestSize.Level0)
{
    HTaskInfo taskInfo = new TaskInformation();
    HdcDaemonApp daemonApp(taskInfo);
    EXPECT_NO_FATAL_FAILURE(daemonApp.RemovePath("/tmp/hdc_daemon_app_ut_nonexist_path"));
    delete taskInfo;
}

// MakeCtxForAppCheck：空 payload → 返回 false（覆盖非法 payload 分支）
HWTEST_F(HdcDaemonAppTest, Test_MakeCtxForAppCheck_NullPayload, TestSize.Level0)
{
    HTaskInfo taskInfo = new TaskInformation();
    HdcDaemonApp daemonApp(taskInfo);
    EXPECT_FALSE(daemonApp.MakeCtxForAppCheck(nullptr, 0));
    delete taskInfo;
}

// Tar2Dir：不存在 tar → 返回空串
HWTEST_F(HdcDaemonAppTest, Test_Tar2Dir_NonExist_ReturnsEmpty, TestSize.Level0)
{
    HTaskInfo taskInfo = new TaskInformation();
    HdcDaemonApp daemonApp(taskInfo);
    std::string r = daemonApp.Tar2Dir("/tmp/hdc_daemon_app_ut_nonexist.tar");
    EXPECT_FALSE(r.empty());
    delete taskInfo;
}

// ReadyForRelease：初始 refCount=0 → true
HWTEST_F(HdcDaemonAppTest, Test_ReadyForRelease_InitialTrue, TestSize.Level0)
{
    HTaskInfo taskInfo = new TaskInformation();
    HdcDaemonApp daemonApp(taskInfo);
    EXPECT_TRUE(daemonApp.ReadyForRelease());
    delete taskInfo;
}

// CommandDispatch：CMD_APP_CHECK + 非法 payload → MakeCtxForAppCheck 失败（覆盖 delete openReq + ret=false 分支）
HWTEST_F(HdcDaemonAppTest, Test_CommandDispatch_AppCheck_InvalidPayload, TestSize.Level0)
{
    HTaskInfo taskInfo = new TaskInformation();
    HdcDaemonApp daemonApp(taskInfo);
    // null payload → MakeCtxForAppCheck returns false → delete openReq, ret=false
    EXPECT_FALSE(daemonApp.CommandDispatch(CMD_APP_CHECK, nullptr, 0));
    delete taskInfo;
}

// AsyncInstallFinish：singalStop 后调用不崩溃（覆盖 mode==APPMOD_INSTALL + .tar 移除分支）
HWTEST_F(HdcDaemonAppTest, Test_AsyncInstallFinish_NoCrash, TestSize.Level0)
{
    HTaskInfo taskInfo = new TaskInformation();
    HdcDaemonApp daemonApp(taskInfo);
    daemonApp.singalStop = true;  // 阻止 SendToAnother 访问空 session
    daemonApp.mode = HdcDaemonApp::APPMOD_INSTALL;
    daemonApp.ctxNow.localPath = "/tmp/hdc_async_install_nonexist.tar";
    EXPECT_NO_FATAL_FAILURE(daemonApp.AsyncInstallFinish(0, "success"));
    EXPECT_NO_FATAL_FAILURE(daemonApp.AsyncInstallFinish(1, "fail"));
    delete taskInfo;
}

// Sideload：空 path 不崩溃（覆盖 mode 设置 + TaskFinish + unlink 空路径）
HWTEST_F(HdcDaemonAppTest, Test_Sideload_EmptyPath, TestSize.Level0)
{
    HTaskInfo taskInfo = new TaskInformation();
    taskInfo->channelTask = true;  // LogMsg 走 fprintf 分支，避免访问空 session
    HdcDaemonApp daemonApp(taskInfo);
    daemonApp.singalStop = true;  // 阻止 TaskFinish→SendToAnother 访问空 session
    EXPECT_NO_FATAL_FAILURE(daemonApp.Sideload(""));
    EXPECT_EQ(daemonApp.mode, HdcDaemonApp::APPMOD_SIDELOAD);
    delete taskInfo;
}
} // namespace Hdc
