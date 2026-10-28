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

#include <cstdint>
#include <cstring>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "memory_pool.h"

using namespace testing::ext;
using namespace testing;

namespace Hdc {
class MemoryPoolTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void MemoryPoolTest::SetUpTestCase() {}
void MemoryPoolTest::TearDownTestCase() {}
void MemoryPoolTest::SetUp() {}
void MemoryPoolTest::TearDown() {}

// Allocate 非零大小：返回可用指针，可写入可释放
HWTEST_F(MemoryPoolTest, Allocate_NormalSize_ReturnsUsablePointer, TestSize.Level0)
{
    auto &pool = MemoryPool::Instance();
    void *p = pool.Allocate(128);
    ASSERT_NE(p, nullptr);
    memset(p, 0x5A, 128);
    pool.Deallocate(p);
}

// Allocate 不同大小：各自独立有效
HWTEST_F(MemoryPoolTest, Allocate_DifferentSizes, TestSize.Level0)
{
    auto &pool = MemoryPool::Instance();
    void *small = pool.Allocate(16);
    void *mid = pool.Allocate(1024);
    void *big = pool.Allocate(64 * 1024);
    ASSERT_NE(small, nullptr);
    ASSERT_NE(mid, nullptr);
    ASSERT_NE(big, nullptr);
    EXPECT_NE(small, mid);
    EXPECT_NE(small, big);
    pool.Deallocate(small);
    pool.Deallocate(mid);
    pool.Deallocate(big);
}

// Deallocate(nullptr)：空操作分支，不应崩溃
HWTEST_F(MemoryPoolTest, Deallocate_Nullptr_Noop, TestSize.Level0)
{
    auto &pool = MemoryPool::Instance();
    EXPECT_NO_FATAL_FAILURE(pool.Deallocate(nullptr));
}

// Allocate/Deallocate 循环复用：连续多轮不泄漏不崩溃
HWTEST_F(MemoryPoolTest, AllocateDeallocate_ReuseCycle, TestSize.Level0)
{
    auto &pool = MemoryPool::Instance();
    for (int i = 0; i < 32; ++i) {
        void *p = pool.Allocate(256);
        ASSERT_NE(p, nullptr);
        memset(p, i & 0xFF, 256);
        pool.Deallocate(p);
    }
}

// 同尺寸释放后再申请：池化模式下应复用，直通模式下返回有效指针
HWTEST_F(MemoryPoolTest, Allocate_AfterDeallocateSameSize_Valid, TestSize.Level0)
{
    auto &pool = MemoryPool::Instance();
    void *first = pool.Allocate(512);
    ASSERT_NE(first, nullptr);
    pool.Deallocate(first);
    void *second = pool.Allocate(512);
    ASSERT_NE(second, nullptr);
    pool.Deallocate(second);
}

// Allocate 后写入再读出：数据完整性校验
HWTEST_F(MemoryPoolTest, Allocate_WriteReadIntegrity, TestSize.Level0)
{
    auto &pool = MemoryPool::Instance();
    constexpr size_t sz = 1024;
    uint8_t *p = static_cast<uint8_t *>(pool.Allocate(sz));
    ASSERT_NE(p, nullptr);
    for (size_t i = 0; i < sz; ++i) {
        p[i] = static_cast<uint8_t>(i & 0xFF);
    }
    for (size_t i = 0; i < sz; ++i) {
        EXPECT_EQ(p[i], static_cast<uint8_t>(i & 0xFF));
    }
    pool.Deallocate(p);
}
}  // namespace Hdc
