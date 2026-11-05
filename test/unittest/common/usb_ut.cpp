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

#include <cstring>
#include <uv.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "usb.h"

using namespace testing::ext;
using namespace testing;

namespace Hdc {
// 派生类暴露 protected 纯逻辑 helper 以便单测
class TestableUSB : public HdcUSBBase {
public:
    explicit TestableUSB(bool serverOrDaemonIn, void *ptrMainBase)
        : HdcUSBBase(serverOrDaemonIn, ptrMainBase) {}
    bool PubIsUsbPacketHeader(uint8_t *b, int n) { return IsUsbPacketHeader(b, n); }
    USBHead *PubBuildPacketHeader(uint32_t sid, uint8_t opt, uint32_t sz)
    {
        return BuildPacketHeader(sid, opt, sz);
    }
};

class HdcUSBBaseTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HdcUSBBaseTest::SetUpTestCase() {}
void HdcUSBBaseTest::TearDownTestCase() {}
void HdcUSBBaseTest::SetUp() {}
void HdcUSBBaseTest::TearDown() {}

// 构造：server/daemon 两模式不崩溃
HWTEST_F(HdcUSBBaseTest, Constructor_BothModes, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(TestableUSB u(true, nullptr));
    ASSERT_NO_FATAL_FAILURE(TestableUSB u(false, nullptr));
}

// IsUsbPacketHeader：长度不足 → false
HWTEST_F(HdcUSBBaseTest, IsUsbPacketHeader_TooShort, TestSize.Level0)
{
    TestableUSB u(true, nullptr);
    uint8_t b[1] = {0};
    EXPECT_FALSE(u.PubIsUsbPacketHeader(b, sizeof(b)));
}

// IsUsbPacketHeader：magic 不匹配 "UB" → false
HWTEST_F(HdcUSBBaseTest, IsUsbPacketHeader_BadMagic, TestSize.Level0)
{
    TestableUSB u(true, nullptr);
    uint8_t b[8] = {0};
    EXPECT_FALSE(u.PubIsUsbPacketHeader(b, sizeof(b)));
}

// IsUsbPacketHeader：magic 匹配 "UB" → true
HWTEST_F(HdcUSBBaseTest, IsUsbPacketHeader_GoodMagic, TestSize.Level0)
{
    TestableUSB u(true, nullptr);
    uint8_t b[sizeof(USBHead)] = {0};
    b[0] = 'U';
    b[1] = 'B';
    EXPECT_TRUE(u.PubIsUsbPacketHeader(b, sizeof(b)));
}

// BuildPacketHeader：返回非空且 magic 为 "UB"
HWTEST_F(HdcUSBBaseTest, BuildPacketHeader_ReturnsValidHeader, TestSize.Level0)
{
    TestableUSB u(true, nullptr);
    USBHead *h = u.PubBuildPacketHeader(1234, 1, 100);
    ASSERT_NE(h, nullptr);
    EXPECT_EQ(memcmp(&h->flag, "UB", 2), 0);
    delete h;
}

// BuildPacketHeader：dataSize 0 也能构造
HWTEST_F(HdcUSBBaseTest, BuildPacketHeader_ZeroDataSize, TestSize.Level0)
{
    TestableUSB u(true, nullptr);
    USBHead *h = u.PubBuildPacketHeader(1, 0, 0);
    ASSERT_NE(h, nullptr);
    delete h;
}

// IsUsbPacketHeader：magic 匹配 + dataSize>0 + option 含 USB_OPTION_HEADER → true（覆盖 option 校验分支）
HWTEST_F(HdcUSBBaseTest, IsUsbPacketHeader_GoodMagic_OptionHeader_ReturnsTrue, TestSize.Level0)
{
    TestableUSB u(true, nullptr);
    USBHead *h = u.PubBuildPacketHeader(1234, USB_OPTION_HEADER, 100);
    ASSERT_NE(h, nullptr);
    EXPECT_TRUE(u.PubIsUsbPacketHeader(reinterpret_cast<uint8_t *>(h), sizeof(USBHead)));
    delete h;
}

// IsUsbPacketHeader：magic 匹配 + dataSize>0 + option 不含 USB_OPTION_HEADER → false（覆盖 maybeSize!=0 且无 option 分支）
HWTEST_F(HdcUSBBaseTest, IsUsbPacketHeader_GoodMagic_NoOption_NonZeroSize_ReturnsFalse, TestSize.Level0)
{
    TestableUSB u(true, nullptr);
    USBHead *h = u.PubBuildPacketHeader(1234, 0, 100);
    ASSERT_NE(h, nullptr);
    EXPECT_FALSE(u.PubIsUsbPacketHeader(reinterpret_cast<uint8_t *>(h), sizeof(USBHead)));
    delete h;
}

// BuildPacketHeader：sessionId/dataSize 使用网络字节序（htonl）
HWTEST_F(HdcUSBBaseTest, BuildPacketHeader_NetworkByteOrder, TestSize.Level0)
{
    TestableUSB u(true, nullptr);
    USBHead *h = u.PubBuildPacketHeader(0x12345678, USB_OPTION_HEADER, 0xABCDEF01);
    ASSERT_NE(h, nullptr);
    // 验证 sessionId 被 htonl 转换
    EXPECT_EQ(h->sessionId, htonl(0x12345678u));
    EXPECT_EQ(h->dataSize, htonl(0xABCDEF01u));
    EXPECT_EQ(h->option, USB_OPTION_HEADER);
    delete h;
}
}  // namespace Hdc
