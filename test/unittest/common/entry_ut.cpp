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

#include <cstdio>
#include <fstream>
#include <optional>
#include <string>
#include <unistd.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "base.h"
#include "entry.h"
#include "header.h"

using namespace testing::ext;
using namespace testing;

namespace Hdc {
// entry.cpp 内部函数前向申明（未在entry.h导出）
std::optional<std::string> StripPrefix(const std::string& str, const std::string& prefix);
class EntryTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static std::string TempFile(const std::string &suffix, const std::string &content);
    static std::string TempDir(const std::string &suffix);
    static std::string workDir;
};

std::string EntryTest::workDir;

void EntryTest::SetUpTestCase()
{
    char tmpl[] = "/data/local/tmp/hdc_entry_ut_XXXXXX";
    workDir = mkdtemp(tmpl) ? std::string(tmpl) : "/tmp";
}

void EntryTest::TearDownTestCase()
{
    if (!workDir.empty() && workDir != "/tmp") {
        std::string cmd = "rm -rf " + workDir;
        (void)system(cmd.c_str());
    }
}

void EntryTest::SetUp() {}
void EntryTest::TearDown() {}

std::string EntryTest::TempFile(const std::string &suffix, const std::string &content)
{
    std::string p = workDir + "/" + suffix;
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f << content;
    f.close();
    return p;
}

std::string EntryTest::TempDir(const std::string &suffix)
{
    std::string p = workDir + "/" + suffix;
    (void)mkdir(p.c_str(), 0755);
    return p;
}

// StripPrefix：前缀匹配，返回去除前缀的子串
HWTEST_F(EntryTest, StripPrefix_Match, TestSize.Level0)
{
    auto r = StripPrefix("/a/b/c", "/a/b");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r.value(), "/c");
}

// StripPrefix：前缀不匹配，返回 nullopt
HWTEST_F(EntryTest, StripPrefix_NoMatch, TestSize.Level0)
{
    auto r = StripPrefix("/x/y", "/a/b");
    EXPECT_FALSE(r.has_value());
}

// StripPrefix：空串入参
HWTEST_F(EntryTest, StripPrefix_EmptyStr, TestSize.Level0)
{
    auto r = StripPrefix("", "/a");
    EXPECT_FALSE(r.has_value());
    auto r2 = StripPrefix("/a", "");
    ASSERT_TRUE(r2.has_value());
    EXPECT_EQ(r2.value(), "/a");
}

// Entry 普通文件构造：Size 等于文件大小，类型为 ORDINARYFILE，IsFinish 初始为 false
HWTEST_F(EntryTest, Entry_RegularFile, TestSize.Level0)
{
    std::string content = "hello hdc entry";
    std::string p = TempFile("regular.txt", content);
    Entry e("", p);
    EXPECT_FALSE(e.IsInvalid());
    EXPECT_FALSE(e.IsFinish());
    EXPECT_EQ(e.Size(), content.size());
    (void)unlink(p.c_str());
}

// Entry 目录构造：类型为 DIRECTORY，Size 为 0
HWTEST_F(EntryTest, Entry_Directory, TestSize.Level0)
{
    std::string d = TempDir("entrydir");
    Entry e("", d);
    EXPECT_FALSE(e.IsInvalid());
    EXPECT_EQ(e.Size(), 0u);
    (void)rmdir(d.c_str());
}

// Entry 不存在路径：lstat 失败，header 未填充，IsInvalid 为 true
HWTEST_F(EntryTest, Entry_NonexistentPath, TestSize.Level0)
{
    Entry e("", workDir + "/not_exist_file");
    EXPECT_TRUE(e.IsInvalid());
}

// Entry 带 prefix：GetName 返回带 prefix 前缀的名字
HWTEST_F(EntryTest, Entry_GetName_WithPrefix, TestSize.Level0)
{
    std::string content = "abc";
    std::string p = TempFile("pf.txt", content);
    Entry e("myprefix", p);
    std::string name = e.GetName();
    EXPECT_NE(name.find("myprefix"), std::string::npos);
    (void)unlink(p.c_str());
}

// AddData：len < needSize 时追加 len 字节，needSize 递减
HWTEST_F(EntryTest, AddData_PartialChunk, TestSize.Level0)
{
    std::string content(100, 'X');
    std::string p = TempFile("add1.bin", content);
    Entry e("", p);
    uint8_t buf[40] = {0};
    size_t before = e.Size();
    e.AddData(buf, sizeof(buf));
    // needSize 减少了 sizeof(buf)
    EXPECT_EQ(e.Size(), before);  // Size 是 header 记录的总大小，不变
    (void)unlink(p.c_str());
}

// AddData：len >= needSize 时只追加 needSize 字节并清零 needSize（IsFinish 变 true）
HWTEST_F(EntryTest, AddData_FullChunk, TestSize.Level0)
{
    std::string content(10, 'Y');
    std::string p = TempFile("add2.bin", content);
    Entry e("", p);
    uint8_t buf[64] = {0};
    e.AddData(buf, sizeof(buf));  // len(64) >= needSize(10)
    EXPECT_TRUE(e.IsFinish());
    (void)unlink(p.c_str());
}

// UpdataName：空 prefix 时直接更新 header 名字
HWTEST_F(EntryTest, UpdataName_NoPrefix, TestSize.Level0)
{
    std::string content = "z";
    std::string p = TempFile("up.dat", content);
    Entry e("", p);
    EXPECT_TRUE(e.UpdataName("renamed.dat"));
    (void)unlink(p.c_str());
}

// CopyPayload：非法文件类型（构造不存在路径）→ 返回 false
HWTEST_F(EntryTest, CopyPayload_InvalidEntry_ReturnsFalse, TestSize.Level0)
{
    Entry e("", workDir + "/not_exist");
    std::ifstream in;
    EXPECT_FALSE(e.CopyPayload(workDir, in));
}

// StripPrefix：str == prefix → 返回空串（全匹配边界）
HWTEST_F(EntryTest, StripPrefix_FullMatch_ReturnsEmpty, TestSize.Level0)
{
    auto r = StripPrefix("/a/b", "/a/b");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r.value(), "");
}

// StripPrefix：prefix 比 str 长 → 返回 nullopt
HWTEST_F(EntryTest, StripPrefix_PrefixLongerThanStr_ReturnsNullopt, TestSize.Level0)
{
    auto r = StripPrefix("/a", "/a/b/c");
    EXPECT_FALSE(r.has_value());
}

// StripPrefix：prefix 为空 → 返回原串
HWTEST_F(EntryTest, StripPrefix_EmptyPrefix_ReturnsOriginal, TestSize.Level0)
{
    auto r = StripPrefix("/a/b/c", "");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r.value(), "/a/b/c");
}

// ReadAndWriteData：buffAppend 为 nullptr → 返回 false
HWTEST_F(EntryTest, ReadAndWriteData_NullBuf_ReturnsFalse, TestSize.Level0)
{
    std::string inFile = TempFile("rw_in.txt", "data");
    std::string outFile = workDir + "/rw_out.txt";
    std::ifstream in(inFile, std::ios::binary);
    std::ofstream out(outFile, std::ios::binary);
    Entry e("", inFile);
    EXPECT_FALSE(e.ReadAndWriteData(in, out, nullptr, 16, 16));
    in.close();
    out.close();
    (void)unlink(inFile.c_str());
    (void)unlink(outFile.c_str());
}

// AddData：needSize 已为 0（IsFinish）→ 不追加数据（覆盖 needSize==0 早返回）
HWTEST_F(EntryTest, AddData_AfterFinish_NoOp, TestSize.Level0)
{
    std::string content(10, 'Z');
    std::string p = TempFile("fin.bin", content);
    Entry e("", p);
    uint8_t buf1[64] = {0};
    e.AddData(buf1, sizeof(buf1));  // 第一次：len(64) >= needSize(10) → IsFinish
    EXPECT_TRUE(e.IsFinish());
    uint8_t buf2[64] = {0};
    EXPECT_NO_FATAL_FAILURE(e.AddData(buf2, sizeof(buf2)));  // 第二次：needSize==0 → 早返回
    EXPECT_TRUE(e.IsFinish());
    (void)unlink(p.c_str());
}

// Entry(data,dataLen) 构造：dataLen < 512 → header.IsInvalid 为 true
HWTEST_F(EntryTest, Entry_DataConstructor_ShortData, TestSize.Level0)
{
    uint8_t data[128] = {0};
    Entry e(data, 128);
    EXPECT_TRUE(e.IsInvalid());
}

// UpdataName：带 prefix 的 Entry → StripPrefix 成功后更新 header name
HWTEST_F(EntryTest, UpdataName_WithPrefix, TestSize.Level0)
{
    std::string content = "abc";
    std::string p = TempFile("pf2.txt", content);
    Entry e("/some/prefix", p);
    EXPECT_TRUE(e.UpdataName("/some/prefix/renamed.txt"));
    (void)unlink(p.c_str());
}

// UpdataName：带 prefix 但 name 不含 prefix → 直接更新 header name
HWTEST_F(EntryTest, UpdataName_WithPrefix_NoMatch, TestSize.Level0)
{
    std::string content = "abc";
    std::string p = TempFile("pf3.txt", content);
    Entry e("/some/prefix", p);
    EXPECT_TRUE(e.UpdataName("/other/path/file.txt"));
    (void)unlink(p.c_str());
}

// GetName：空 prefix → 返回 header.Name()
HWTEST_F(EntryTest, GetName_NoPrefix_ReturnsHeaderName, TestSize.Level0)
{
    std::string content = "abc";
    std::string p = TempFile("noname.txt", content);
    Entry e("", p);
    std::string name = e.GetName();
    EXPECT_FALSE(name.empty());
    (void)unlink(p.c_str());
}
}  // namespace Hdc
