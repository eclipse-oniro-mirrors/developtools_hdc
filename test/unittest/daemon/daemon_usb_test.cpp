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

#include "daemon_usb_test.h"
#include "daemon_usb.h"

#include <string>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace testing::ext;

namespace Hdc {
void HdcDaemonUSBTest::SetUpTestCase() {}
void HdcDaemonUSBTest::TearDownTestCase() {}
void HdcDaemonUSBTest::SetUp()
{
#ifdef UT_DEBUG
    Hdc::Base::SetLogLevel(LOG_ALL);
#else
    Hdc::Base::SetLogLevel(LOG_OFF);
#endif
}
void HdcDaemonUSBTest::TearDown() {}

HWTEST_F(HdcDaemonUSBTest, ConstructorDestructor_DefaultValues, TestSize.Level0)
{
    HdcDaemonUSB usb(false, nullptr);
    EXPECT_EQ(usb.usbHandle.bulkOut, -1);
    EXPECT_EQ(usb.usbHandle.bulkIn, -1);
    EXPECT_FALSE(usb.usbHandle.isBulkOutClosing);
    EXPECT_FALSE(usb.usbHandle.isBulkInClosing);
}

HWTEST_F(HdcDaemonUSBTest, GetDevPath_ReturnsEmptyOnInvalidPath, TestSize.Level0)
{
    HdcDaemonUSB usb(false, nullptr);
    std::string invalidPath = "/data/local/tmp/nonexistent_usb_dir";
    if (std::filesystem::exists(invalidPath))
    {
        std::filesystem::remove(invalidPath);
    }
    ASSERT_FALSE(std::filesystem::exists(invalidPath));
    std::string result = usb.GetDevPath(invalidPath);
    EXPECT_EQ(result, "");
}

HWTEST_F(HdcDaemonUSBTest, GetMaxPacketSize_ReturnsConstant, TestSize.Level0)
{
    HdcDaemonUSB usb(false, nullptr);
    EXPECT_EQ(usb.GetMaxPacketSize(), MAX_PACKET_SIZE_HISPEED);
}

HWTEST_F(HdcDaemonUSBTest, JumpAntiquePacket_DetectsAntique, TestSize.Level0)
{
    HdcDaemonUSB usb(false, nullptr);
    uint8_t antique[24] = {0x43, 0x4e, 0x58, 0x4e}; // CNXN
    EXPECT_TRUE(usb.JumpAntiquePacket(antique[0], 24));
    uint8_t notAntique[24] = {0};
    EXPECT_FALSE(usb.JumpAntiquePacket(notAntique[0], 24));
    EXPECT_FALSE(usb.JumpAntiquePacket(antique[0], 10));
}

HWTEST_F(HdcDaemonUSBTest, IsUSBBulkClosing_NullPtr, TestSize.Level0)
{
    HdcDaemonUSB usb(false, nullptr);
    EXPECT_FALSE(usb.IsUSBBulkClosing(nullptr));
}

HWTEST_F(HdcDaemonUSBTest, IsUSBBulkClosing_TrueIfClosing, TestSize.Level0)
{
    HdcDaemonUSB usb(false, nullptr);
    usb.usbHandle.isBulkInClosing = true;
    EXPECT_TRUE(usb.IsUSBBulkClosing(&usb.usbHandle));
    usb.usbHandle.isBulkInClosing = false;
    usb.usbHandle.isBulkOutClosing = true;
    EXPECT_TRUE(usb.IsUSBBulkClosing(&usb.usbHandle));
    usb.usbHandle.isBulkOutClosing = false;
    EXPECT_FALSE(usb.IsUSBBulkClosing(&usb.usbHandle));
}

HWTEST_F(HdcDaemonUSBTest, OnNewHandshakeOK_SetsCurrentSessionId, TestSize.Level0)
{
    HdcDaemonUSB usb(false, nullptr);
    uint32_t sessionId = 12345;
    usb.OnNewHandshakeOK(sessionId);
    EXPECT_EQ(usb.currentSessionId, sessionId);
    // No getter, but we can check by calling again and expecting no crash
    usb.OnNewHandshakeOK(sessionId + 1);
    EXPECT_EQ(usb.currentSessionId, sessionId + 1);
}

static vector<uint8_t> BuildPacketHeaderOld(uint32_t sessionId, uint8_t option, uint32_t dataSize)
{
    const string USB_PACKET_FLAG = "UB";  // must 2bytes
    vector<uint8_t> testVecData;
    USBHead tHead;
    tHead.sessionId = htonl(sessionId);
    for (size_t i = 0; i < sizeof(tHead.flag); i++) {
        tHead.flag[i] = USB_PACKET_FLAG.data()[i];
    }
    tHead.option = option;
    tHead.dataSize = htonl(dataSize);
    testVecData.insert(testVecData.end(), (uint8_t *)&tHead, (uint8_t *)&tHead + sizeof(USBHead));
    return testVecData;
}

HWTEST_F(HdcDaemonUSBTest, BuildPacketHeaderTest, TestSize.Level0)
{
    static constexpr uint32_t sessionId = 13245;
    static constexpr uint8_t option = 7;
    static constexpr uint32_t dataSize = 15;
    vector<uint8_t> vec = BuildPacketHeaderOld(sessionId, option, dataSize);
    HdcDaemonUSB usb(false, nullptr);
    USBHead* head = usb.BuildPacketHeader(sessionId, option, dataSize);

    EXPECT_EQ(vec.size(), sizeof(USBHead));
    uint8_t* p1 = vec.data();
    uint8_t* p2 = reinterpret_cast<uint8_t*>(head);
    for (int i = 0; i < vec.size(); i++) {
        EXPECT_EQ(*(p1 + i), *(p2 + i));
    }
    delete head;
}

// GetMaxPacketSize：返回常量 > 0
HWTEST_F(HdcDaemonUSBTest, GetMaxPacketSize_Positive, TestSize.Level0)
{
    HdcDaemonUSB usb(false, nullptr);
    EXPECT_GT(usb.GetMaxPacketSize(), 0);
}

// BuildPacketHeader：dataSize 为大值仍可构造
HWTEST_F(HdcDaemonUSBTest, BuildPacketHeader_LargeDataSize, TestSize.Level0)
{
    HdcDaemonUSB usb(false, nullptr);
    USBHead *head = usb.BuildPacketHeader(4143, 1, 65535);
    ASSERT_NE(head, nullptr);
    delete head;
}

// GetDevPath：空字符串路径 → 空结果
HWTEST_F(HdcDaemonUSBTest, GetDevPath_EmptyPath, TestSize.Level0)
{
    HdcDaemonUSB usb(false, nullptr);
    EXPECT_EQ(usb.GetDevPath(""), "");
}

// GetDevPath：单条目目录 → 返回 USB_FFS_BASE + 条目名
HWTEST_F(HdcDaemonUSBTest, GetDevPath_SingleEntry, TestSize.Level0)
{
    HdcDaemonUSB usb(false, nullptr);
    std::string tmpDir = "/data/local/tmp/hdc_ut_usb_single";
    std::filesystem::remove_all(tmpDir);
    std::filesystem::create_directories(tmpDir);
    std::filesystem::create_directories(tmpDir + "/ep1");
    std::string result = usb.GetDevPath(tmpDir);
    EXPECT_EQ(result, std::string("/dev/usb-ffs/") + "ep1");
    std::filesystem::remove_all(tmpDir);
}

// GetDevPath：多条目目录 → 返回 USB_FFS_BASE + "hdc"
HWTEST_F(HdcDaemonUSBTest, GetDevPath_MultipleEntries, TestSize.Level0)
{
    HdcDaemonUSB usb(false, nullptr);
    std::string tmpDir = "/data/local/tmp/hdc_ut_usb_multi";
    std::filesystem::remove_all(tmpDir);
    std::filesystem::create_directories(tmpDir);
    std::filesystem::create_directories(tmpDir + "/ep1");
    std::filesystem::create_directories(tmpDir + "/ep2");
    std::string result = usb.GetDevPath(tmpDir);
    EXPECT_EQ(result, std::string("/dev/usb-ffs/") + "hdc");
    std::filesystem::remove_all(tmpDir);
}

// JumpAntiquePacket：0 字节 → false
HWTEST_F(HdcDaemonUSBTest, JumpAntiquePacket_ZeroBytes, TestSize.Level0)
{
    HdcDaemonUSB usb(false, nullptr);
    uint8_t buf[1] = {0};
    EXPECT_FALSE(usb.JumpAntiquePacket(buf[0], 0));
}

// JumpAntiquePacket：小于 24 字节 → false
HWTEST_F(HdcDaemonUSBTest, JumpAntiquePacket_LessThan24, TestSize.Level0)
{
    HdcDaemonUSB usb(false, nullptr);
    uint8_t buf[24] = {0x43, 0x4e, 0x58, 0x4e};
    EXPECT_FALSE(usb.JumpAntiquePacket(buf[0], 23));
}

// JumpAntiquePacket：24 字节但 flag 部分匹配 → false
HWTEST_F(HdcDaemonUSBTest, JumpAntiquePacket_PartialFlag, TestSize.Level0)
{
    HdcDaemonUSB usb(false, nullptr);
    uint8_t buf[24] = {0x43, 0x4e, 0x58, 0x4d}; // last byte differs
    EXPECT_FALSE(usb.JumpAntiquePacket(buf[0], 24));
}

// JumpAntiquePacket：全零 24 字节 → false
HWTEST_F(HdcDaemonUSBTest, JumpAntiquePacket_AllZero, TestSize.Level0)
{
    HdcDaemonUSB usb(false, nullptr);
    uint8_t buf[24] = {0};
    EXPECT_FALSE(usb.JumpAntiquePacket(buf[0], 24));
}

// OnNewHandshakeOK：sessionId=0
HWTEST_F(HdcDaemonUSBTest, OnNewHandshakeOK_ZeroSessionId, TestSize.Level0)
{
    HdcDaemonUSB usb(false, nullptr);
    usb.OnNewHandshakeOK(0);
    EXPECT_EQ(usb.currentSessionId, 0u);
}

// OnNewHandshakeOK：最大值 sessionId
HWTEST_F(HdcDaemonUSBTest, OnNewHandshakeOK_MaxSessionId, TestSize.Level0)
{
    HdcDaemonUSB usb(false, nullptr);
    usb.OnNewHandshakeOK(UINT32_MAX);
    EXPECT_EQ(usb.currentSessionId, UINT32_MAX);
}

// OnNewHandshakeOK：覆盖已有 sessionId
HWTEST_F(HdcDaemonUSBTest, OnNewHandshakeOK_Overwrite, TestSize.Level0)
{
    HdcDaemonUSB usb(false, nullptr);
    usb.OnNewHandshakeOK(100);
    EXPECT_EQ(usb.currentSessionId, 100u);
    usb.OnNewHandshakeOK(200);
    EXPECT_EQ(usb.currentSessionId, 200u);
}

// BuildPacketHeader：零值 → 结构合法
HWTEST_F(HdcDaemonUSBTest, BuildPacketHeader_ZeroValues, TestSize.Level0)
{
    HdcDaemonUSB usb(false, nullptr);
    USBHead *head = usb.BuildPacketHeader(0, 0, 0);
    ASSERT_NE(head, nullptr);
    EXPECT_EQ(ntohl(head->sessionId), 0u);
    delete head;
}

// BuildPacketHeader：验证 sessionId 网络字节序
HWTEST_F(HdcDaemonUSBTest, BuildPacketHeader_VerifySessionId, TestSize.Level0)
{
    HdcDaemonUSB usb(false, nullptr);
    uint32_t sid = 0x12345678;
    USBHead *head = usb.BuildPacketHeader(sid, 0, 0);
    ASSERT_NE(head, nullptr);
    EXPECT_EQ(ntohl(head->sessionId), sid);
    delete head;
}

// BuildPacketHeader：验证 flag 字段
HWTEST_F(HdcDaemonUSBTest, BuildPacketHeader_VerifyFlag, TestSize.Level0)
{
    HdcDaemonUSB usb(false, nullptr);
    USBHead *head = usb.BuildPacketHeader(0, 0, 0);
    ASSERT_NE(head, nullptr);
    EXPECT_EQ(head->flag[0], 'U');
    EXPECT_EQ(head->flag[1], 'B');
    delete head;
}

// Constructor：验证所有初始值
HWTEST_F(HdcDaemonUSBTest, Constructor_AllInitialValues, TestSize.Level0)
{
    HdcDaemonUSB usb(false, nullptr);
    EXPECT_EQ(usb.usbHandle.bulkOut, -1);
    EXPECT_EQ(usb.usbHandle.bulkIn, -1);
    EXPECT_FALSE(usb.usbHandle.isBulkOutClosing);
    EXPECT_FALSE(usb.usbHandle.isBulkInClosing);
    EXPECT_FALSE(usb.isAlive);
    EXPECT_EQ(usb.controlEp, 0);
    EXPECT_EQ(usb.currentSessionId, 0u);
}

// Destructor：不崩溃
HWTEST_F(HdcDaemonUSBTest, Destructor_NoCrash, TestSize.Level0)
{
    HdcDaemonUSB *usb = new HdcDaemonUSB(false, nullptr);
    EXPECT_NO_FATAL_FAILURE(delete usb);
}

// OnSessionFreeFinally：isSoftReset=true → isAlive 不变
HWTEST_F(HdcDaemonUSBTest, OnSessionFreeFinally_SoftReset, TestSize.Level0)
{
    HdcDaemonUSB usb(false, nullptr);
    HdcSession session;
    session.sessionId = 12345;
    session.isSoftReset = true;
    usb.currentSessionId = 12345;
    usb.isAlive = true;
    usb.OnSessionFreeFinally(&session);
    EXPECT_TRUE(usb.isAlive);
}

// OnSessionFreeFinally：相同 sessionId → isAlive=false
HWTEST_F(HdcDaemonUSBTest, OnSessionFreeFinally_SameSession, TestSize.Level0)
{
    HdcDaemonUSB usb(false, nullptr);
    HdcSession session;
    session.sessionId = 12345;
    session.isSoftReset = false;
    usb.currentSessionId = 12345;
    usb.isAlive = true;
    usb.OnSessionFreeFinally(&session);
    EXPECT_FALSE(usb.isAlive);
}

// OnSessionFreeFinally：不同 sessionId → isAlive 不变
HWTEST_F(HdcDaemonUSBTest, OnSessionFreeFinally_DiffSession, TestSize.Level0)
{
    HdcDaemonUSB usb(false, nullptr);
    HdcSession session;
    session.sessionId = 99999;
    session.isSoftReset = false;
    usb.currentSessionId = 12345;
    usb.isAlive = true;
    usb.OnSessionFreeFinally(&session);
    EXPECT_TRUE(usb.isAlive);
}

// CloseEndpoint：默认 handle → 不崩溃
HWTEST_F(HdcDaemonUSBTest, CloseEndpoint_DefaultHandle, TestSize.Level0)
{
    HdcDaemonUSB usb(false, nullptr);
    HUSB hUSB = &usb.usbHandle;
    EXPECT_NO_FATAL_FAILURE(usb.CloseEndpoint(hUSB, false));
    EXPECT_FALSE(usb.isAlive);
}

// AvailablePacket：非 header 数据 → RET_SUCCESS
HWTEST_F(HdcDaemonUSBTest, AvailablePacket_NoHeader, TestSize.Level0)
{
    HdcDaemonUSB usb(false, nullptr);
    uint8_t buf[8] = {0};
    uint32_t sessionId = 0;
    EXPECT_EQ(usb.AvailablePacket(buf, sizeof(buf), &sessionId), RET_SUCCESS);
}

// AvailablePacket：合法 header 无 RESET → 设置 sessionId
HWTEST_F(HdcDaemonUSBTest, AvailablePacket_ValidHeader, TestSize.Level0)
{
    HdcDaemonUSB usb(false, nullptr);
    uint8_t buf[sizeof(USBHead)] = {0};
    USBHead *head = reinterpret_cast<USBHead *>(buf);
    head->flag[0] = 'U';
    head->flag[1] = 'B';
    head->sessionId = htonl(54321);
    head->option = USB_OPTION_HEADER;
    head->dataSize = htonl(0);
    uint32_t sessionId = 0;
    EXPECT_EQ(usb.AvailablePacket(buf, sizeof(USBHead), &sessionId), RET_SUCCESS);
    EXPECT_EQ(sessionId, 54321u);
}

// ConnectEPPoint：basePath 为空 → open 失败 → ERR_GENERIC
HWTEST_F(HdcDaemonUSBTest, ConnectEPPoint_EmptyBasePath, TestSize.Level0)
{
    HdcDaemonUSB usb(false, nullptr);
    HUSB hUSB = &usb.usbHandle;
    EXPECT_EQ(usb.ConnectEPPoint(hUSB), ERR_GENERIC);
}

} // namespace
