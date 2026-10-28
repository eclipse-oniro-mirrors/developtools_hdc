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

#include "define_ut.h"
using namespace testing::ext;
using namespace std;
namespace Hdc {
void HdcDefineTest::SetUpTestCase() {}

void HdcDefineTest::TearDownTestCase() {}

void HdcDefineTest::SetUp() {}

void HdcDefineTest::TearDown() {}

HSession HdcDefineTest::InstanceHSession()
{
    return new(std::nothrow) HdcSession();
}

HChannel HdcDefineTest::InstanceHChannel()
{
    return new(std::nothrow) HdcChannel();
}

/*
 * @tc.name: TestToDisplayConnectionStr
 * @tc.desc: Check the return of ToDisplayConnectionStr method.
 * @tc.type: FUNC
 */
HWTEST_F(HdcDefineTest, TestToDisplayConnectionStr, TestSize.Level1)
{
    HSession session = HdcDefineTest::InstanceHSession();
    session->connectKey = "7001005458323933328a259b97233900";
    session->sessionId = 2867909239;
    session->connType = 0;
    session->isRunningOk = true;
    session->faultInfo = "";
    session->commandCount = 1;
    std::string result = "HdcServer [ sessionId:286******239(L:10) connectKey:700******900(L:32) "
    "connType:0 connect state:1 faultInfo: commandCount:1 ]";
    ASSERT_EQ(session->ToDisplayConnectionStr(), result);
    
    delete session;
}

/*
 * @tc.name: TestToDisplayChannelStr1
 * @tc.desc: Check the return of ToDisplayChannelStr method.
 * @tc.type: FUNC
 */
HWTEST_F(HdcDefineTest, TestToDisplayChannelStr1, TestSize.Level1)
{
    HChannel channel = HdcDefineTest::InstanceHChannel();
    channel->connectKey = "7001005458323933328a259b97233900";
    channel->channelId = 2867909239;
    channel->commandFlag = 3000;
    channel->commandParameters = "send remote -cwd \"D:\\test\\script0408\\scripts\\\" main.py /data/";
    channel->startTime = 22121121212;
    channel->endTime = 22121121312;
    channel->isSuccess = true;
    channel->faultInfo = "";
    std::string result = "HdcServerForClient [ channelId:2867909239 connectKey:700******900(L:32) "
        "command flag:3000 command result:1 command take time:100ms faultInfo: ]";
    ASSERT_EQ(channel->ToDisplayChannelStr(), result);
    
    delete channel;
}

/*
 * @tc.name: TestToDisplayChannelStr2
 * @tc.desc: Check the return of ToDisplayChannelStr method.
 * @tc.type: FUNC
 */
HWTEST_F(HdcDefineTest, TestToDisplayChannelStr2, TestSize.Level1)
{
    HChannel channel = HdcDefineTest::InstanceHChannel();
    channel->connectKey = "192.168.43.176:8989";
    channel->channelId = 2867909239;
    channel->commandFlag = 3000;
    channel->startTime = 22121121212;
    channel->endTime = 22121121312;
    channel->isSuccess = true;
    channel->faultInfo = "";
    std::string result = "HdcServerForClient [ channelId:2867909239 connectKey:192******989(L:19) "
        "command flag:3000 command result:1 command take time:100ms faultInfo: ]";
    ASSERT_EQ(channel->ToDisplayChannelStr(), result);
    
    delete channel;
}

HWTEST_F(HdcDefineTest, TestMaskStringEmpty, TestSize.Level0)
{
    EXPECT_EQ(MaskString(""), "");
}

HWTEST_F(HdcDefineTest, TestMaskStringShortLen, TestSize.Level0)
{
    EXPECT_EQ(MaskString("abc"), "a***c");
    EXPECT_EQ(MaskString("abcdef"), "a******f");
}

HWTEST_F(HdcDefineTest, TestMaskStringLongLen, TestSize.Level0)
{
    EXPECT_EQ(MaskString("abcdefg"), "abc******efg(L:7)");
}

HWTEST_F(HdcDefineTest, TestMaskSessionIdToStringLong, TestSize.Level0)
{
    EXPECT_EQ(MaskSessionIdToString(2867909239), "286******239(L:10)");
}

HWTEST_F(HdcDefineTest, TestMaskSessionIdToStringShort, TestSize.Level0)
{
    EXPECT_EQ(MaskSessionIdToString(123), "1***3");
}

HWTEST_F(HdcDefineTest, TestGetConnectionErrorInfoUsb, TestSize.Level0)
{
    EXPECT_STREQ(GetConnectionErrorInfo(CONN_USB),
        "[E001003] USB communication abnormal, please check the USB communication link.");
}

HWTEST_F(HdcDefineTest, TestGetConnectionErrorInfoUart, TestSize.Level0)
{
    EXPECT_STREQ(GetConnectionErrorInfo(CONN_SERIAL),
        "[E001408] UART communication abnormal, please check the UART communication link.");
}

HWTEST_F(HdcDefineTest, TestGetConnectionErrorInfoUnknown, TestSize.Level0)
{
    EXPECT_EQ(GetConnectionErrorInfo(CONN_BT), nullptr);
    EXPECT_EQ(GetConnectionErrorInfo(CONN_UNKNOWN), nullptr);
}
}