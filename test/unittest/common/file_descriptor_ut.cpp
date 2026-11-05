/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file in compliance with the License.
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

#include <cstdint>
#include <unistd.h>
#include <uv.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "file_descriptor.h"

using namespace testing::ext;
using namespace testing;

namespace Hdc {
class HdcFileDescriptorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    uv_loop_t loop{};
    int fds[2] = {-1, -1};
};

void HdcFileDescriptorTest::SetUpTestCase() {}
void HdcFileDescriptorTest::TearDownTestCase() {}
void HdcFileDescriptorTest::SetUp()
{
    ASSERT_EQ(uv_loop_init(&loop), 0);
    ASSERT_EQ(pipe(fds), 0);
}
void HdcFileDescriptorTest::TearDown()
{
    if (fds[0] >= 0) close(fds[0]);
    if (fds[1] >= 0) close(fds[1]);
    uv_loop_close(&loop);
}

static bool DummyReadCb(const void *, uint8_t *, const int) { return true; }
static bool DummyFinishCb(const void *, const bool, const string) { return true; }

// 构造/析构：以 pipe 读端为 fd，不崩溃
HWTEST_F(HdcFileDescriptorTest, ConstructorDestructor_NoCrash, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(HdcFileDescriptor fd(&loop, fds[0], this, DummyReadCb, DummyFinishCb, false));
}

// ReadyForRelease：初始 refCount=0 → true（覆盖初始状态分支）
HWTEST_F(HdcFileDescriptorTest, ReadyForRelease_Initial_True, TestSize.Level0)
{
    HdcFileDescriptor fd(&loop, fds[0], this, DummyReadCb, DummyFinishCb, false);
    EXPECT_TRUE(fd.ReadyForRelease());
}

// Write：向 fd 写入小数据，返回写入字节数 >=0（覆盖正常写分支）
HWTEST_F(HdcFileDescriptorTest, Write_SmallData, TestSize.Level0)
{
    HdcFileDescriptor fd(&loop, fds[0], this, DummyReadCb, DummyFinishCb, false);
    uint8_t data[4] = {1, 2, 3, 4};
    int rc = fd.Write(data, sizeof(data));
    EXPECT_GE(rc, 0);
}

// Write：size=0 → 走 0 长度分支
HWTEST_F(HdcFileDescriptorTest, Write_ZeroSize, TestSize.Level0)
{
    HdcFileDescriptor fd(&loop, fds[0], this, DummyReadCb, DummyFinishCb, false);
    uint8_t data[4] = {0};
    int rc = fd.Write(data, 0);
    EXPECT_EQ(rc, -1);
}

// WriteWithMem：写入小数据，不崩溃
HWTEST_F(HdcFileDescriptorTest, WriteWithMem_SmallData, TestSize.Level0)
{
    HdcFileDescriptor fd(&loop, fds[0], this, DummyReadCb, DummyFinishCb, false);
    uint8_t data[4] = {5, 6, 7, 8};
    EXPECT_NO_FATAL_FAILURE(fd.WriteWithMem(data, sizeof(data)));
}

// 无效 fd（-1）构造：不崩溃
HWTEST_F(HdcFileDescriptorTest, Constructor_InvalidFd_NoCrash, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(HdcFileDescriptor fd(&loop, -1, this, DummyReadCb, DummyFinishCb, false));
}

// Write：data 为 nullptr → 返回 -1（覆盖 null data 校验分支）
HWTEST_F(HdcFileDescriptorTest, Write_NullData_ReturnsNegative, TestSize.Level0)
{
    HdcFileDescriptor fd(&loop, fds[0], this, DummyReadCb, DummyFinishCb, false);
    EXPECT_EQ(fd.Write(nullptr, 16), -1);
}

// Write：size 为负 → 返回 -1（覆盖 size<=0 分支）
HWTEST_F(HdcFileDescriptorTest, Write_NegativeSize_ReturnsNegative, TestSize.Level0)
{
    HdcFileDescriptor fd(&loop, fds[0], this, DummyReadCb, DummyFinishCb, false);
    uint8_t d = 0;
    EXPECT_EQ(fd.Write(&d, -1), -1);
}

// Write：size 较大但合法 → 正常写入（覆盖大 size 分支，不触发 clamp）
HWTEST_F(HdcFileDescriptorTest, Write_LargeData_NoCrash, TestSize.Level0)
{
    HdcFileDescriptor fd(&loop, fds[0], this, DummyReadCb, DummyFinishCb, false);
    constexpr int largeSize = 4096;
    auto data = new uint8_t[largeSize];
    for (int i = 0; i < largeSize; ++i) { data[i] = 0xAA; }
    int rc = fd.Write(data, largeSize);
    EXPECT_GE(rc, 0);
    delete[] data;
}

// WriteWithMem：size = 0 → 返回 0（覆盖零长度分支）
HWTEST_F(HdcFileDescriptorTest, WriteWithMem_ZeroSize_ReturnsZero, TestSize.Level0)
{
    HdcFileDescriptor fd(&loop, fds[0], this, DummyReadCb, DummyFinishCb, false);
    auto buf = new uint8_t[1];
    EXPECT_EQ(fd.WriteWithMem(buf, 0), 0);
}

// WriteWithMem：size 为负 → 返回 size（负值，覆盖负长度分支）
HWTEST_F(HdcFileDescriptorTest, WriteWithMem_NegativeSize_ReturnsSize, TestSize.Level0)
{
    HdcFileDescriptor fd(&loop, fds[0], this, DummyReadCb, DummyFinishCb, false);
    auto buf = new uint8_t[1];
    EXPECT_EQ(fd.WriteWithMem(buf, -1), -1);
    delete[] buf;
}

// WriteWithMem：data 为 nullptr，size = 0 → 不崩溃
HWTEST_F(HdcFileDescriptorTest, WriteWithMem_NullDataZeroSize_NoCrash, TestSize.Level0)
{
    HdcFileDescriptor fd(&loop, fds[0], this, DummyReadCb, DummyFinishCb, false);
    EXPECT_NO_FATAL_FAILURE(fd.WriteWithMem(nullptr, 0));
}

// Write：交互模式（isInteractive=true）写入小数据 → 不崩溃（ioWriteThread 后台处理）
HWTEST_F(HdcFileDescriptorTest, Write_InteractiveMode_NoCrash, TestSize.Level0)
{
    HdcFileDescriptor fd(&loop, fds[1], this, DummyReadCb, DummyFinishCb, true);
    uint8_t data[4] = {9, 8, 7, 6};
    EXPECT_NO_FATAL_FAILURE(fd.Write(data, sizeof(data)));
}

// Write：交互模式 size=0 → 走零长度分支
HWTEST_F(HdcFileDescriptorTest, Write_InteractiveZeroSize_NoCrash, TestSize.Level0)
{
    HdcFileDescriptor fd(&loop, fds[1], this, DummyReadCb, DummyFinishCb, true);
    uint8_t data[4] = {0};
    EXPECT_NO_FATAL_FAILURE(fd.Write(data, 0));
}

// ReadyForRelease：非交互模式初始 refIO=0 → true
HWTEST_F(HdcFileDescriptorTest, ReadyForRelease_NonInteractive_True, TestSize.Level0)
{
    HdcFileDescriptor fd(&loop, fds[0], this, DummyReadCb, DummyFinishCb, false);
    EXPECT_TRUE(fd.ReadyForRelease());
}

// StopWorkOnThread：tryCloseFdIo=false → 不调用 callback
HWTEST_F(HdcFileDescriptorTest, StopWorkOnThread_TryCloseFalse_NoCrash, TestSize.Level0)
{
    HdcFileDescriptor fd(&loop, fds[0], this, DummyReadCb, DummyFinishCb, false);
    bool called = false;
    EXPECT_NO_FATAL_FAILURE(fd.StopWorkOnThread(false, [&called]() { called = true; }));
    EXPECT_FALSE(called);
}

// StopWorkOnThread：tryCloseFdIo=true 但 refIO=0 → 不调用 callback
HWTEST_F(HdcFileDescriptorTest, StopWorkOnThread_TryCloseTrueZeroRef_NoCallback, TestSize.Level0)
{
    HdcFileDescriptor fd(&loop, fds[0], this, DummyReadCb, DummyFinishCb, false);
    bool called = false;
    EXPECT_NO_FATAL_FAILURE(fd.StopWorkOnThread(true, [&called]() { called = true; }));
    EXPECT_FALSE(called);
}

// StopWorkOnThread：无 callback → 不崩溃
HWTEST_F(HdcFileDescriptorTest, StopWorkOnThread_NullCallback_NoCrash, TestSize.Level0)
{
    HdcFileDescriptor fd(&loop, fds[0], this, DummyReadCb, DummyFinishCb, false);
    EXPECT_NO_FATAL_FAILURE(fd.StopWorkOnThread(true, nullptr));
}

// StartWorkOnThread：返回 true（后台线程读 pipe，测试后立即 StopWorkOnThread）
HWTEST_F(HdcFileDescriptorTest, StartWorkOnThread_ReturnsTrue, TestSize.Level0)
{
    HdcFileDescriptor fd(&loop, fds[0], this, DummyReadCb, DummyFinishCb, false);
    EXPECT_TRUE(fd.StartWorkOnThread());
    // 关闭写端使读端收到 EOF，后台线程退出
    fd.StopWorkOnThread(true, [this]() { close(fds[1]); fds[1] = -1; });
    // 给后台线程一点退出时间
    usleep(200 * 1000);
}
}  // namespace Hdc
