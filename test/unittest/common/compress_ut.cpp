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

#include <fstream>
#include <string>
#include <unistd.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "base.h"
#include "compress.h"

using namespace testing::ext;
using namespace testing;

namespace Hdc {
class CompressTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static std::string workDir;
    static std::string WriteFile(const std::string &name, const std::string &content);
};

std::string CompressTest::workDir;

void CompressTest::SetUpTestCase()
{
    char tmpl[] = "/data/local/tmp/hdc_compress_ut_XXXXXX";
    workDir = mkdtemp(tmpl) ? std::string(tmpl) : "/tmp";
}

void CompressTest::TearDownTestCase()
{
    if (!workDir.empty() && workDir != "/tmp") {
        std::string cmd = "rm -rf " + workDir;
        (void)system(cmd.c_str());
    }
}

void CompressTest::SetUp() {}
void CompressTest::TearDown() {}

std::string CompressTest::WriteFile(const std::string &name, const std::string &content)
{
    std::string p = workDir + "/" + name;
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f << content;
    f.close();
    return p;
}

// AddPath：路径不存在 → lstat 失败 → false
HWTEST_F(CompressTest, AddPath_NotExist_ReturnsFalse, TestSize.Level0)
{
    Compress c;
    EXPECT_FALSE(c.AddPath(workDir + "/not_exist"));
}

// AddPath：普通文件 → AddEntry 成功 → true
HWTEST_F(CompressTest, AddPath_RegularFile_ReturnsTrue, TestSize.Level0)
{
    std::string f = WriteFile("a.txt", "hdc");
    Compress c;
    EXPECT_TRUE(c.AddPath(f));
}

// AddPath：目录 → 扫描子项，空目录 → true
HWTEST_F(CompressTest, AddPath_EmptyDirectory_ReturnsTrue, TestSize.Level0)
{
    std::string d = workDir + "/emptydir";
    (void)mkdir(d.c_str(), 0755);
    Compress c;
    EXPECT_TRUE(c.AddPath(d));
    (void)rmdir(d.c_str());
}

// AddPath：目录含子文件 → 递归加入 → true
HWTEST_F(CompressTest, AddPath_DirWithChild_ReturnsTrue, TestSize.Level0)
{
    std::string d = workDir + "/dir1";
    (void)mkdir(d.c_str(), 0755);
    (void)WriteFile("dir1/child.txt", "x");
    Compress c;
    EXPECT_TRUE(c.AddPath(d));
}

// AddEntry：maxcount 设置后超过上限 → false
HWTEST_F(CompressTest, AddEntry_ExceedMaxCount_ReturnsFalse, TestSize.Level0)
{
    Compress c;
    c.UpdataMaxCount(1);
    // 先加入两条使 entrys.size()>maxcount
    std::string f1 = WriteFile("m1.txt", "a");
    std::string f2 = WriteFile("m2.txt", "b");
    std::string f3 = WriteFile("m3.txt", "c");
    c.AddEntry(f1);
    c.AddEntry(f2);
    EXPECT_FALSE(c.AddEntry(f3));  // entrys.size()(2) > maxcount(1)
}

// AddEntry：path == prefix（根目录）→ 返回 true（忽略根目录分支）
HWTEST_F(CompressTest, AddPath_EqualPrefix_ReturnsTrue, TestSize.Level0)
{
    std::string f = WriteFile("pfx.txt", "z");
    Compress c;
    c.UpdatePrefix(f);
    EXPECT_TRUE(c.AddPath(f));
}

// SaveToFile：localPath 为空 → 默认 tmp.tar；指向目录 → false
HWTEST_F(CompressTest, SaveToFile_DirectoryPath_ReturnsFalse, TestSize.Level0)
{
    std::string d = workDir + "/outdir";
    (void)mkdir(d.c_str(), 0755);
    Compress c;
    EXPECT_FALSE(c.SaveToFile(d));  // 目录 → false
    (void)rmdir(d.c_str());
}

// SaveToFile：合法路径且无条目 → 写出空 tar，返回 true
HWTEST_F(CompressTest, SaveToFile_NoEntries_ReturnsTrue, TestSize.Level0)
{
    Compress c;
    std::string out = workDir + "/res.tar";
    EXPECT_TRUE(c.SaveToFile(out));
    std::ifstream f(out);
    EXPECT_TRUE(f.is_open());
}

// SaveToFile：加入条目后写出 → true
HWTEST_F(CompressTest, SaveToFile_WithEntries_ReturnsTrue, TestSize.Level0)
{
    std::string f = WriteFile("s.txt", "data");
    Compress c;
    EXPECT_TRUE(c.AddPath(f));
    std::string out = workDir + "/res2.tar";
    EXPECT_TRUE(c.SaveToFile(out));
}

// UpdatePrefix / UpdataMaxCount：设置后无返回值，验证不崩溃
HWTEST_F(CompressTest, UpdatePrefix_And_UpdataMaxCount_NoCrash, TestSize.Level0)
{
    Compress c;
    EXPECT_NO_FATAL_FAILURE(c.UpdatePrefix("pfx"));
    EXPECT_NO_FATAL_FAILURE(c.UpdataMaxCount(100));
}
}  // namespace Hdc
