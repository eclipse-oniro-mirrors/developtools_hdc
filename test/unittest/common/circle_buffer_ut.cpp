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

#include "base.h"
#include "circle_buffer.h"

using namespace testing::ext;
using namespace testing;

namespace Hdc {
class CircleBufferTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void CircleBufferTest::SetUpTestCase() {}
void CircleBufferTest::TearDownTestCase() {}
void CircleBufferTest::SetUp() {}
void CircleBufferTest::TearDown() {}

// 构造/析构不启动后台线程（host 模式 TimerStart 为空实现），验证可重复构造
HWTEST_F(CircleBufferTest, Constructor_NoCrash, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(CircleBuffer buf);
}

// Malloc 首次申请：返回非空且长度为 Base::GetUsbffsBulkSize，内容被清零
HWTEST_F(CircleBufferTest, Malloc_FirstAllocate_ReturnsZeroedBuffer, TestSize.Level0)
{
    CircleBuffer buf;
    uint8_t *p = buf.Malloc();
    ASSERT_NE(p, nullptr);
    const size_t expectSize = static_cast<size_t>(Base::GetUsbffsBulkSize());
    for (size_t i = 0; i < expectSize; ++i) {
        EXPECT_EQ(p[i], 0);
    }
    buf.Free(p);
}

// Malloc 连续多次：每次返回不同指针（不同 key），均可独立使用
HWTEST_F(CircleBufferTest, Malloc_MultipleAllocate_ReturnsDistinctBuffers, TestSize.Level0)
{
    CircleBuffer buf;
    uint8_t *a = buf.Malloc();
    uint8_t *b = buf.Malloc();
    uint8_t *c = buf.Malloc();
    ASSERT_NE(a, nullptr);
    ASSERT_NE(b, nullptr);
    ASSERT_NE(c, nullptr);
    EXPECT_NE(a, b);
    EXPECT_NE(a, c);
    EXPECT_NE(b, c);
    buf.Free(a);
    buf.Free(b);
    buf.Free(c);
}

// Free 后再次 Malloc：命中已释放槽位（used=false 分支），复用同一缓冲
HWTEST_F(CircleBufferTest, Malloc_AfterFree_ReusesSlot, TestSize.Level0)
{
    CircleBuffer buf;
    uint8_t *first = buf.Malloc();
    ASSERT_NE(first, nullptr);
    buf.Free(first);
    uint8_t *second = buf.Malloc();
    ASSERT_NE(second, nullptr);
    EXPECT_EQ(second, first);
    buf.Free(second);
}

// Free 传入未登记指针：走 find 失败分支，不应崩溃
HWTEST_F(CircleBufferTest, Free_UnknownPointer_NoCrash, TestSize.Level0)
{
    CircleBuffer buf;
    uint8_t stackByte = 0;
    EXPECT_NO_FATAL_FAILURE(buf.Free(&stackByte));
}

// Free 传入 nullptr：reinterpret_cast 得到 key=0，未命中，不应崩溃
HWTEST_F(CircleBufferTest, Free_NullPointer_NoCrash, TestSize.Level0)
{
    CircleBuffer buf;
    EXPECT_NO_FATAL_FAILURE(buf.Free(nullptr));
}

// Free 后内容标记 used=false，可再次被 Malloc 复用且被重新清零
HWTEST_F(CircleBufferTest, Malloc_ReuseSlot_IsZeroedAgain, TestSize.Level0)
{
    CircleBuffer buf;
    uint8_t *p = buf.Malloc();
    ASSERT_NE(p, nullptr);
    p[0] = 0xAB;
    p[10] = 0xCD;
    buf.Free(p);
    uint8_t *q = buf.Malloc();
    ASSERT_EQ(q, p);
    EXPECT_EQ(q[0], 0);
    EXPECT_EQ(q[10], 0);
    buf.Free(q);
}

// 大量 Malloc/Free 循环：覆盖循环遍历与多次新增分支，不泄漏不崩溃
HWTEST_F(CircleBufferTest, MallocFree_StressManyRounds, TestSize.Level0)
{
    CircleBuffer buf;
    constexpr int rounds = 64;
    std::vector<uint8_t *> ptrs;
    for (int i = 0; i < rounds; ++i) {
        uint8_t *p = buf.Malloc();
        ASSERT_NE(p, nullptr);
        ptrs.push_back(p);
    }
    for (auto *p : ptrs) {
        buf.Free(p);
    }
    // 全部释放后再申请一次，应复用已存在槽位
    uint8_t *again = buf.Malloc();
    ASSERT_NE(again, nullptr);
    buf.Free(again);
}
}  // namespace Hdc
