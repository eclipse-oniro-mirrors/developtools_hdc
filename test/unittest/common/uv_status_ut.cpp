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

#include "log.h"
#include "uv_status.h"
#include "define.h"
#include "hdc_statistic_reporter.h"
#include <random>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using namespace testing::ext;
using namespace testing;

namespace Hdc {
class HandleTest : public testing::Test {
public:
    HandleTest() {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
public:
    uv_loop_t mLoop;
    uv_idle_t mIdle;
    LoopStatus *mLoopStatus;
    unsigned int mCallDuration;
    int mCycles;
};

static void IdleCallBack(uv_idle_t* handle)
{
    HandleTest *ht = (HandleTest *)handle->data;
    static int cycles = 0;
    CALLSTAT_GUARD(*(ht->mLoopStatus), &(ht->mLoop), "IdleCallBack");

    uv_sleep(ht->mCallDuration);
    if (cycles++ > ht->mCycles) {
        uv_stop(&(ht->mLoop));
    }
}

void HandleTest::SetUpTestCase() { }

void HandleTest::TearDownTestCase() {}

void HandleTest::SetUp()
{
    mCallDuration = 1 * MS_PER_SEC;
    uv_loop_init(&mLoop);
    mIdle.data = this;
    uv_idle_init(&mLoop, &mIdle);
    uv_idle_start(&mIdle, IdleCallBack);
    StartLoopMonitor();
    mLoopStatus = new LoopStatus(&mLoop, "HandleTestLoop");
}

void HandleTest::TearDown()
{
    delete mLoopStatus;
    mLoopStatus = nullptr;
}

HWTEST_F(HandleTest, Handle_NoHungTest_001, TestSize.Level0)
{
    mCycles = 5;
    mCallDuration = MS_PER_SEC / 2;
    ASSERT_NO_FATAL_FAILURE(uv_run(&mLoop, UV_RUN_DEFAULT));
}
HWTEST_F(HandleTest, Handle_HungTest_001, TestSize.Level0)
{
    mCycles = 1;
    mCallDuration = 6 * MS_PER_SEC;
    ASSERT_NO_FATAL_FAILURE(uv_run(&mLoop, UV_RUN_DEFAULT));
}
HWTEST_F(HandleTest, HandleStart_Normal_001, TestSize.Level0)
{
    mLoopStatus->HandleStart(&mLoop, "HandleStartTest");
    ASSERT_TRUE(mLoopStatus->Busy());
    ASSERT_EQ(mLoopStatus->mHandleName, "HandleStartTest");
    ASSERT_EQ(mLoopStatus->mCallBackTime, uv_now(&mLoop));
    mLoopStatus->HandleEnd(&mLoop);
    ASSERT_FALSE(mLoopStatus->Busy());
}

HWTEST_F(HandleTest, HandleStart_NullLoop_001, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(mLoopStatus->HandleStart(nullptr, "NullLoop"));
    ASSERT_FALSE(mLoopStatus->Busy());
    ASSERT_EQ(mLoopStatus->mCallBackTime, 0);
}

HWTEST_F(HandleTest, HandleStart_NotMatchLoop_001, TestSize.Level0)
{
    uv_loop_t loop2;
    ASSERT_EQ(uv_loop_init(&loop2), 0);
    ASSERT_NO_FATAL_FAILURE(mLoopStatus->HandleStart(&loop2, "NotMatch"));
    ASSERT_FALSE(mLoopStatus->Busy());
    ASSERT_NO_FATAL_FAILURE(uv_loop_close(&loop2));
}

HWTEST_F(HandleTest, HandleStart_BusyState_001, TestSize.Level0)
{
    mLoopStatus->mBusyNow = true;
    ASSERT_NO_FATAL_FAILURE(mLoopStatus->HandleStart(&mLoop, "BusyState"));
    ASSERT_TRUE(mLoopStatus->Busy());
    ASSERT_EQ(mLoopStatus->mHandleName, "");
}

HWTEST_F(HandleTest, HandleEnd_Normal_001, TestSize.Level0)
{
    mLoopStatus->HandleStart(&mLoop, "HandleEndTest");
    ASSERT_TRUE(mLoopStatus->Busy());
    mLoopStatus->HandleEnd(&mLoop);
    ASSERT_FALSE(mLoopStatus->Busy());
    ASSERT_FALSE(mLoopStatus->mBusyNow);
}

HWTEST_F(HandleTest, HandleEnd_NotMatchLoop_001, TestSize.Level0)
{
    uv_loop_t loop2;
    ASSERT_EQ(uv_loop_init(&loop2), 0);
    mLoopStatus->HandleStart(&mLoop, "HandleEndTest");
    ASSERT_NO_FATAL_FAILURE(mLoopStatus->HandleEnd(&loop2));
    ASSERT_TRUE(mLoopStatus->Busy());
    ASSERT_NO_FATAL_FAILURE(uv_loop_close(&loop2));
}

HWTEST_F(HandleTest, HandleEnd_IdleState_001, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(mLoopStatus->HandleEnd(&mLoop));
    ASSERT_FALSE(mLoopStatus->Busy());
}

HWTEST_F(HandleTest, Busy_DefaultState_001, TestSize.Level0)
{
    ASSERT_FALSE(mLoopStatus->Busy());
    mLoopStatus->mBusyNow = true;
    ASSERT_TRUE(mLoopStatus->Busy());
}

HWTEST_F(HandleTest, Display_IdleAll_001, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(mLoopStatus->Display("displayTest", true));
}

HWTEST_F(HandleTest, Display_BusyState_001, TestSize.Level0)
{
    mLoopStatus->HandleStart(&mLoop, "DisplayBusy");
    ASSERT_NO_FATAL_FAILURE(mLoopStatus->Display("displayTest", true));
}

HWTEST_F(HandleTest, Display_FreezeCount_001, TestSize.Level0)
{
    uint64_t now = uv_hrtime() / NS_PER_MS;
    mLoopStatus->mCallBackTime = now - (MAX_FREEZE_TIME + 1500);
    int before = HdcStatisticReporter::GetInstance().eventCnt_[static_cast<int>(STATISTIC_ITEM::FREEZE_COUNT)];
    ASSERT_NO_FATAL_FAILURE(mLoopStatus->Display("displayTest", false));
    int after = HdcStatisticReporter::GetInstance().eventCnt_[static_cast<int>(STATISTIC_ITEM::FREEZE_COUNT)];
    ASSERT_GE(after, before + 1);
}

HWTEST_F(HandleTest, Display_NoFreeze_001, TestSize.Level0)
{
    mLoopStatus->mCallBackTime = uv_hrtime() / NS_PER_MS;
    int before = HdcStatisticReporter::GetInstance().eventCnt_[static_cast<int>(STATISTIC_ITEM::FREEZE_COUNT)];
    ASSERT_NO_FATAL_FAILURE(mLoopStatus->Display("displayNoFreeze", false));
    int after = HdcStatisticReporter::GetInstance().eventCnt_[static_cast<int>(STATISTIC_ITEM::FREEZE_COUNT)];
    ASSERT_EQ(after, before);
}

HWTEST_F(HandleTest, HungCheck_Timeout_001, TestSize.Level0)
{
    uint64_t now = uv_hrtime() / NS_PER_MS;
    mLoopStatus->mCallBackTime = now - 60000;
    ASSERT_NO_FATAL_FAILURE(mLoopStatus->HungCheck(LOOP_HUNG_TIMEOUT));
}

HWTEST_F(HandleTest, HungCheck_NoTimeout_001, TestSize.Level0)
{
    mLoopStatus->mCallBackTime = uv_hrtime() / NS_PER_MS;
    ASSERT_NO_FATAL_FAILURE(mLoopStatus->HungCheck(LOOP_HUNG_TIMEOUT));
}

HWTEST_F(HandleTest, DispAllLoopStatus_Registered_001, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(DispAllLoopStatus("dispAllTest"));
}

HWTEST_F(HandleTest, Constructor_SecondSameLoop_001, TestSize.Level0)
{
    LoopStatus *second = new LoopStatus(&mLoop, "SecondLoop");
    ASSERT_FALSE(second->Busy());
    delete second;
    second = nullptr;
    ASSERT_NO_FATAL_FAILURE(DispAllLoopStatus("afterDelete"));
    ASSERT_FALSE(mLoopStatus->Busy());
}

HWTEST_F(HandleTest, ReportTimerProc_001, TestSize.Level0)
{
    uv_timer_t timer;
    ASSERT_EQ(uv_timer_init(&mLoop, &timer), 0);
    timer.data = mLoopStatus;
    ASSERT_NO_FATAL_FAILURE(LoopStatus::ReportTimerProc(&timer));
    ASSERT_FALSE(mLoopStatus->Busy());
    uv_close(reinterpret_cast<uv_handle_t*>(&timer), nullptr);
    mCycles = 100;
    mCallDuration = 1;
    ASSERT_NO_FATAL_FAILURE(uv_run(&mLoop, UV_RUN_NOWAIT));
}

HWTEST_F(HandleTest, StartReportTimer_001, TestSize.Level0)
{
    mLoopStatus->StartReportTimer();
    uv_close(reinterpret_cast<uv_handle_t*>(&mLoopStatus->mReportTimer), nullptr);
    mCycles = 100;
    mCallDuration = 1;
    ASSERT_NO_FATAL_FAILURE(uv_run(&mLoop, UV_RUN_NOWAIT));
    ASSERT_NO_FATAL_FAILURE(uv_run(&mLoop, UV_RUN_NOWAIT));
}

HWTEST_F(HandleTest, CallStatGuard_Commit_001, TestSize.Level0)
{
    CallStatGuard guard(*mLoopStatus, &mLoop, "GuardCommit");
    ASSERT_TRUE(mLoopStatus->Busy());
    guard.Commit();
    ASSERT_FALSE(mLoopStatus->Busy());
}

HWTEST_F(HandleTest, CallStatGuard_Destructor_001, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE([this]() { CallStatGuard guard(*mLoopStatus, &mLoop, "GuardDtor"); }());
    ASSERT_FALSE(mLoopStatus->Busy());
}

HWTEST_F(HandleTest, CallStatGuard_NullLoop_001, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE([this]() { CallStatGuard guard(*mLoopStatus, nullptr, "GuardNull"); }());
    ASSERT_FALSE(mLoopStatus->Busy());
}

HWTEST_F(HandleTest, CallStatGuard_CommitTwice_001, TestSize.Level0)
{
    CallStatGuard guard(*mLoopStatus, &mLoop, "GuardCommitTwice");
    ASSERT_TRUE(mLoopStatus->Busy());
    guard.Commit();
    ASSERT_FALSE(mLoopStatus->Busy());
    guard.Commit();
    ASSERT_FALSE(mLoopStatus->Busy());
}

} // namespace Hdc
