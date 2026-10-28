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
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>
#include "shell.h"
#include "task.h"
#include "daemon_base.h"
#include "base.h"
#include "define_plus.h"
#include "tlv.h"
#include "os_account_manager.h"
#include "shell_test.h"

using namespace testing;
using namespace testing::ext;

namespace {
static const int32_t DEFAULT_USER_ID = 100;
}

namespace Hdc {
void ShellTest::SetUpTestCase()
{
#ifdef UT_DEBUG
    Base::SetLogLevel(LOG_ALL);
#else
    Base::SetLogLevel(LOG_OFF);
#endif
}

void ShellTest::TearDownTestCase() {}

void ShellTest::SetUp()
{
    taskInfo = new TaskInformation();
    taskInfo->channelId = 1;
    taskInfo->sessionId = 1;
    shell = new HdcShell(taskInfo);
}

void ShellTest::TearDown()
{
    if (shell != nullptr) {
        delete shell;
        shell = nullptr;
    }
    if (taskInfo != nullptr) {
        delete taskInfo;
        taskInfo = nullptr;
    }
}

HWTEST_F(ShellTest, TestShellConstruction, TestSize.Level0)
{
    ASSERT_NE(shell, nullptr);
    EXPECT_EQ(shell->taskInfo->channelId, 1);
}

HWTEST_F(ShellTest, TestShellDestruction, TestSize.Level0)
{
    HdcShell *testShell = new HdcShell(taskInfo);
    ASSERT_NE(testShell, nullptr);
    delete testShell;
    testShell = nullptr;
}

HWTEST_F(ShellTest, TestReadyForRelease_Initial, TestSize.Level0)
{
    bool result = shell->ReadyForRelease();
    EXPECT_TRUE(result);
}

HWTEST_F(ShellTest, TestStopTask_Initial, TestSize.Level0)
{
    shell->StopTask();
}

HWTEST_F(ShellTest, TestInitShell_WithValidBundle, TestSize.Level0)
{
    std::string bundleName = "com.example.testapp";
    std::string basePath = DEBUG_BUNDLE_PATH;
    std::vector<int32_t> ids;
    OHOS::ErrCode err = OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
    int id = -1;
    if (err != 0 || ids.empty()) {
        id = DEFAULT_USER_ID;
    } else {
        id = ids[0];
    }
    basePath += std::to_string(id) + "/debug_hap/";
    
    mkdir(basePath.c_str(), 0755);
    std::string bundlePath = basePath + bundleName;
    mkdir(bundlePath.c_str(), 0755);

    TlvBuf tlvBuf(Base::REGISTERD_TAG_SET);
    tlvBuf.Append(TAG_SHELL_BUNDLE, bundleName);
    uint32_t size = tlvBuf.GetBufSize();
    uint8_t *buf = new (std::nothrow) uint8_t[size];
    tlvBuf.CopyToBuf(buf, size);
    
    bool result = shell->InitShell(buf, size);
    
    EXPECT_TRUE(result);
    
    delete[] buf;
    rmdir(bundlePath.c_str());
    rmdir(basePath.c_str());
}

HWTEST_F(ShellTest, TestInitShell_WithoutBundle, TestSize.Level0)
{
    TlvBuf tlvBuf(Base::REGISTERD_TAG_SET);
    uint32_t size = tlvBuf.GetBufSize();
    uint8_t *buf = new (std::nothrow) uint8_t[size];
    tlvBuf.CopyToBuf(buf, size);
    
    bool result = shell->InitShell(buf, size);
    
    EXPECT_TRUE(result);
    
    delete[] buf;
}

HWTEST_F(ShellTest, TestInitShell_WithEmptyPayload, TestSize.Level0)
{
    bool result = shell->InitShell(nullptr, 0);
    EXPECT_TRUE(result);
}

// InitShell：短 payload（1 字节）不崩溃
HWTEST_F(ShellTest, TestInitShell_ShortPayload, TestSize.Level0)
{
    uint8_t p = 'x';
    EXPECT_NO_FATAL_FAILURE((void)shell->InitShell(&p, 1));
}

// ReadyForRelease：初始 refCount=0 → true
HWTEST_F(ShellTest, TestReadyForRelease_InitialDup, TestSize.Level0)
{
    EXPECT_TRUE(shell->ReadyForRelease());
}

// CommandDispatch：未知命令 → default → true
HWTEST_F(ShellTest, CommandDispatch_UnknownCommand, TestSize.Level0)
{
    uint8_t payload = 0;
    EXPECT_TRUE(shell->CommandDispatch(static_cast<uint16_t>(99999), &payload, 1));
}

// CommandDispatch：CMD_SHELL_INIT 已初始化 → false
HWTEST_F(ShellTest, CommandDispatch_InitAlreadyReady, TestSize.Level0)
{
    shell->childReady = true;
    uint8_t payload = 0;
    EXPECT_FALSE(shell->CommandDispatch(CMD_SHELL_INIT, &payload, 1));
}

// CommandDispatch：CMD_SHELL_DATA 未就绪 → false
HWTEST_F(ShellTest, CommandDispatch_DataNotReady, TestSize.Level0)
{
    shell->childReady = false;
    uint8_t payload = 'x';
    EXPECT_FALSE(shell->CommandDispatch(CMD_SHELL_DATA, &payload, 1));
}

// CommandDispatch：CMD_SHELL_DATA null payload → false
HWTEST_F(ShellTest, CommandDispatch_DataNullPayload, TestSize.Level0)
{
    shell->childReady = true;
    EXPECT_FALSE(shell->CommandDispatch(CMD_SHELL_DATA, nullptr, 1));
}

// CommandDispatch：CMD_SHELL_DATA size=0 → false
HWTEST_F(ShellTest, CommandDispatch_DataZeroSize, TestSize.Level0)
{
    shell->childReady = true;
    uint8_t payload = 'x';
    EXPECT_FALSE(shell->CommandDispatch(CMD_SHELL_DATA, &payload, 0));
}

// CommandDispatch：CMD_SHELL_DATA 负 size → false
HWTEST_F(ShellTest, CommandDispatch_DataNegativeSize, TestSize.Level0)
{
    shell->childReady = true;
    uint8_t payload = 'x';
    EXPECT_FALSE(shell->CommandDispatch(CMD_SHELL_DATA, &payload, -1));
}

// CommandDispatch：CMD_SHELL_DATA 特殊信号 ETX → true
HWTEST_F(ShellTest, CommandDispatch_DataSpecialSignalETX, TestSize.Level0)
{
    shell->childReady = true;
    uint8_t signal = 0x3; // ETX = Ctrl+C
    EXPECT_TRUE(shell->CommandDispatch(CMD_SHELL_DATA, &signal, 1));
}

// SpecialSignal：ETX 无 fdPTY → true
HWTEST_F(ShellTest, SpecialSignal_ETX_NoFdPTY, TestSize.Level0)
{
    shell->fdPTY = 0;
    EXPECT_TRUE(shell->SpecialSignal(0x3));
}

// SpecialSignal：ETX 有 fdPTY → true（tcgetpgrp 失败不崩溃）
HWTEST_F(ShellTest, SpecialSignal_ETX_WithFdPTY, TestSize.Level0)
{
    shell->fdPTY = 999;
    EXPECT_TRUE(shell->SpecialSignal(0x3));
    shell->fdPTY = 0;
}

// SpecialSignal：非 ETX → false
HWTEST_F(ShellTest, SpecialSignal_Other, TestSize.Level0)
{
    EXPECT_FALSE(shell->SpecialSignal(0x41)); // 'A'
    EXPECT_FALSE(shell->SpecialSignal(0x0));
    EXPECT_FALSE(shell->SpecialSignal(0xFF));
}

// ReadyForRelease：refCount > 0 → false
HWTEST_F(ShellTest, ReadyForRelease_WithRefCount, TestSize.Level0)
{
    shell->refCount = 1;
    EXPECT_FALSE(shell->ReadyForRelease());
    shell->refCount = 0;
}

// StopTask：childReady=true, childShell=nullptr → 不崩溃
HWTEST_F(ShellTest, StopTask_ChildReadyNoShell, TestSize.Level0)
{
    shell->childReady = true;
    shell->childShell = nullptr;
    shell->pidShell = 0;
    EXPECT_NO_FATAL_FAILURE(shell->StopTask());
    EXPECT_TRUE(shell->singalStop);
}

// StopTask：fake pidShell → kill/waitpid 失败不崩溃
HWTEST_F(ShellTest, StopTask_WithFakePid, TestSize.Level0)
{
    shell->childReady = true;
    shell->childShell = nullptr;
    shell->pidShell = 99999;
    EXPECT_NO_FATAL_FAILURE(shell->StopTask());
    EXPECT_TRUE(shell->singalStop);
}

// StopTask：验证 singalStop 被设置
HWTEST_F(ShellTest, StopTask_SetsSignalStop, TestSize.Level0)
{
    shell->singalStop = false;
    shell->StopTask();
    EXPECT_TRUE(shell->singalStop);
}

// Constructor：验证初始字段值
HWTEST_F(ShellTest, Constructor_VerifyFields, TestSize.Level0)
{
    EXPECT_EQ(shell->childShell, nullptr);
    EXPECT_EQ(shell->pidShell, 0);
    EXPECT_EQ(shell->fdPTY, 0);
    EXPECT_EQ(shell->ptm, 0);
    EXPECT_FALSE(shell->childReady);
    EXPECT_FALSE(shell->singalStop);
}

// InitShell：null payload + 正 size → true（清空 optionPath）
HWTEST_F(ShellTest, InitShell_NullPayloadPositiveSize, TestSize.Level0)
{
    EXPECT_TRUE(shell->InitShell(nullptr, 100));
    EXPECT_TRUE(shell->optionPath.empty());
}

}
