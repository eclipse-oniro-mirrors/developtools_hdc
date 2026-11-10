/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless by or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "base.h"
#include "daemon_unity.h"
#include "task.h"
#include "tlv.h"

using namespace testing::ext;
using namespace testing;

namespace Hdc {
class HdcDaemonUnityTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    HTaskInfo NewInfo();
};

void HdcDaemonUnityTest::SetUpTestCase() {}
void HdcDaemonUnityTest::TearDownTestCase() {}
void HdcDaemonUnityTest::SetUp() {}
void HdcDaemonUnityTest::TearDown() {}

HTaskInfo HdcDaemonUnityTest::NewInfo()
{
    HTaskInfo info = new TaskInformation();
    return info;
}

// 构造：默认 TaskInformation 不崩溃
HWTEST_F(HdcDaemonUnityTest, Constructor_NoCrash, TestSize.Level0)
{
    HTaskInfo info = NewInfo();
    ASSERT_NO_FATAL_FAILURE(HdcDaemonUnity u(info));
    delete info;
}

// ReadyForRelease：初始 refCount=0 → true
HWTEST_F(HdcDaemonUnityTest, ReadyForRelease_Initial_True, TestSize.Level0)
{
    HTaskInfo info = NewInfo();
    HdcDaemonUnity u(info);
    EXPECT_TRUE(u.ReadyForRelease());
    delete info;
}

// CommandDispatch：未知 command → switch 未命中分支，ret 保持 true，不崩溃
HWTEST_F(HdcDaemonUnityTest, CommandDispatch_UnknownCommand_NoCrash, TestSize.Level0)
{
    HTaskInfo info = NewInfo();
    HdcDaemonUnity u(info);
    uint8_t payload[4] = {0};
    EXPECT_NO_FATAL_FAILURE(u.CommandDispatch(0xFFFF, payload, sizeof(payload)));
    delete info;
}

// RebootDevice：cmd 过长 → SystemDepend::RebootDevice 返回 false（覆盖失败分支，不触发真实重启）
HWTEST_F(HdcDaemonUnityTest, RebootDevice_CmdTooLong_ReturnsFalse, TestSize.Level0)
{
    HTaskInfo info = NewInfo();
    HdcDaemonUnity u(info);
    EXPECT_FALSE(u.RebootDevice("abcdefghijklm"));  // 13 > 12
    delete info;
}

// RebootDevice：非法目标 → false
HWTEST_F(HdcDaemonUnityTest, RebootDevice_Unauthorized_ReturnsFalse, TestSize.Level0)
{
    HTaskInfo info = NewInfo();
    HdcDaemonUnity u(info);
    EXPECT_FALSE(u.RebootDevice("foobar"));
    delete info;
}

// AsyncCmdOut：finish=true（singalStop=true 避免 SendToAnother 崩溃）→ true
HWTEST_F(HdcDaemonUnityTest, AsyncCmdOut_FinishTrue_Stopped_ReturnsTrue, TestSize.Level0)
{
    HTaskInfo info = NewInfo();
    HdcDaemonUnity u(info);
    u.singalStop = true;
    EXPECT_TRUE(u.AsyncCmdOut(true, "done"));
    delete info;
}

// AsyncCmdOut：finish=false + singalStop=true → SendToAnother 失败 → false
HWTEST_F(HdcDaemonUnityTest, AsyncCmdOut_FinishFalse_Stopped_ReturnsFalse, TestSize.Level0)
{
    HTaskInfo info = NewInfo();
    HdcDaemonUnity u(info);
    u.singalStop = true;
    EXPECT_FALSE(u.AsyncCmdOut(false, "partial"));
    delete info;
}

// AsyncCmdOut：finish=false + 空结果 + singalStop=true → false
HWTEST_F(HdcDaemonUnityTest, AsyncCmdOut_EmptyResult_Stopped_ReturnsFalse, TestSize.Level0)
{
    HTaskInfo info = NewInfo();
    HdcDaemonUnity u(info);
    u.singalStop = true;
    EXPECT_FALSE(u.AsyncCmdOut(false, ""));
    delete info;
}

// CheckbundlePath：非法 bundle 名 → false（仅在 UPDATER_MODE 下编译）
HWTEST_F(HdcDaemonUnityTest, CheckbundlePath_InvalidBundle_ReturnsFalse, TestSize.Level0)
{
#ifdef UPDATER_MODE
    HTaskInfo info = NewInfo();
    info->channelTask = true;
    HdcDaemonUnity u(info);
    std::string mountPath;
    EXPECT_FALSE(u.CheckbundlePath("a;b", mountPath));
    delete info;
#else
    // 非 UPDATER_MODE 下 CheckbundlePath 不存在，用 ExecuteOptionShell 间接覆盖同分支
    HTaskInfo info = NewInfo();
    info->channelTask = true;
    HdcDaemonUnity u(info);
    EXPECT_EQ(u.ExecuteOptionShell("ls", "a;b"), -1);
    delete info;
#endif
}

// ExecuteOptionShell：非法 bundle 名 → -1
HWTEST_F(HdcDaemonUnityTest, ExecuteOptionShell_InvalidBundle_ReturnsNegOne, TestSize.Level0)
{
    HTaskInfo info = NewInfo();
    info->channelTask = true;
    HdcDaemonUnity u(info);
    EXPECT_EQ(u.ExecuteOptionShell("ls", "a;b"), -1);
    delete info;
}

// ExecuteShellExtend：空 payload → 无 TAG_SHELL_BUNDLE → -1
HWTEST_F(HdcDaemonUnityTest, ExecuteShellExtend_EmptyPayload_ReturnsNegOne, TestSize.Level0)
{
    HTaskInfo info = NewInfo();
    info->channelTask = true;
    HdcDaemonUnity u(info);
    uint8_t payload[4] = {0};
    EXPECT_EQ(u.ExecuteShellExtend(payload, 0), -1);
    delete info;
}

// ExecuteShellExtend：仅含 TAG_SHELL_CMD 但无 TAG_SHELL_BUNDLE → -1
HWTEST_F(HdcDaemonUnityTest, ExecuteShellExtend_NoBundleTag_ReturnsNegOne, TestSize.Level0)
{
    HTaskInfo info = NewInfo();
    info->channelTask = true;
    HdcDaemonUnity u(info);
    TlvBuf tlvBuf(Base::REGISTERD_TAG_SET);
    ASSERT_TRUE(tlvBuf.Append(TAG_SHELL_CMD, "ls"));
    uint32_t bufSize = tlvBuf.GetBufSize();
    std::vector<uint8_t> tlv(bufSize, 0);
    ASSERT_TRUE(tlvBuf.CopyToBuf(tlv.data(), bufSize));
    EXPECT_EQ(u.ExecuteShellExtend(tlv.data(), static_cast<int>(tlv.size())), -1);
    delete info;
}

// FindMountDeviceByPath：不存在的挂载点 → false
HWTEST_F(HdcDaemonUnityTest, FindMountDeviceByPath_NotFound_ReturnsFalse, TestSize.Level0)
{
    HTaskInfo info = NewInfo();
    HdcDaemonUnity u(info);
    char dev[256] = {0};
    EXPECT_FALSE(u.FindMountDeviceByPath("/no/such/path", dev));
    delete info;
}

// RemountPartition：FindMountDeviceByPath 失败 → false
HWTEST_F(HdcDaemonUnityTest, RemountPartition_NotFound_ReturnsFalse, TestSize.Level0)
{
    HTaskInfo info = NewInfo();
    HdcDaemonUnity u(info);
    EXPECT_FALSE(u.RemountPartition("/no/such/path"));
    delete info;
}

// SetDeviceRunMode：tmode usb → true（不真实切换，仅记录失败消息）
HWTEST_F(HdcDaemonUnityTest, SetDeviceRunMode_TmodeUsb_ReturnsTrue, TestSize.Level0)
{
    HTaskInfo info = NewInfo();
    info->channelTask = true;
    HdcDaemonUnity u(info);
    EXPECT_TRUE(u.SetDeviceRunMode("usb"));
    delete info;
}

// SetDeviceRunMode：未知命令（非 usb/非 port 前缀）→ false
HWTEST_F(HdcDaemonUnityTest, SetDeviceRunMode_UnknownCommand_ReturnsFalse, TestSize.Level0)
{
    HTaskInfo info = NewInfo();
    info->channelTask = true;
    HdcDaemonUnity u(info);
    EXPECT_FALSE(u.SetDeviceRunMode("foobar"));
    delete info;
}

// SetDeviceRunMode：port abc（非数字端口）→ false
HWTEST_F(HdcDaemonUnityTest, SetDeviceRunMode_InvalidPort_ReturnsFalse, TestSize.Level0)
{
    HTaskInfo info = NewInfo();
    info->channelTask = true;
    HdcDaemonUnity u(info);
    EXPECT_FALSE(u.SetDeviceRunMode("port abc"));
    delete info;
}
}  // namespace Hdc
