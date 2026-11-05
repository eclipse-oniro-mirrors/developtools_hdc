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
#include "decompress.h"

using namespace testing::ext;
using namespace testing;

namespace Hdc {
class DecompressTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static std::string workDir;
    static std::string WriteFile(const std::string &name, const std::string &content);
};

std::string DecompressTest::workDir;

void DecompressTest::SetUpTestCase()
{
    char tmpl[] = "/tmp/hdc_decomp_ut_XXXXXX";
    workDir = mkdtemp(tmpl) ? std::string(tmpl) : "/tmp";
}

void DecompressTest::TearDownTestCase()
{
    if (!workDir.empty() && workDir != "/tmp") {
        std::string cmd = "rm -rf " + workDir;
        (void)system(cmd.c_str());
    }
}

void DecompressTest::SetUp() {}
void DecompressTest::TearDown() {}

std::string DecompressTest::WriteFile(const std::string &name, const std::string &content)
{
    std::string p = workDir + "/" + name;
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f << content;
    f.close();
    return p;
}

// CheckPath：tar 文件不存在 → lstat 失败 → false
HWTEST_F(DecompressTest, CheckPath_TarNotExist_ReturnsFalse, TestSize.Level0)
{
    Decompress d(workDir + "/not_exist.tar");
    EXPECT_FALSE(d.CheckPath(workDir + "/out"));
}

// CheckPath：tar 路径指向目录 → 非 S_IFREG → ValidateTarFile 失败 → false
HWTEST_F(DecompressTest, CheckPath_TarIsDirectory_ReturnsFalse, TestSize.Level0)
{
    std::string outDir = workDir + "/out1";
    (void)mkdir(outDir.c_str(), 0755);
    Decompress d(workDir);  // tarPath 是目录
    EXPECT_FALSE(d.CheckPath(outDir));
    (void)rmdir(outDir.c_str());
}

// CheckPath：tar 为空文件 → st_size==0 → ValidateTarFile 失败 → false
HWTEST_F(DecompressTest, CheckPath_TarEmpty_ReturnsFalse, TestSize.Level0)
{
    std::string tar = WriteFile("empty.tar", "");
    std::string outDir = workDir + "/out2";
    Decompress d(tar);
    EXPECT_FALSE(d.CheckPath(outDir));
}

// CheckPath：tar 大小非 HEADER_LEN 整数倍 → ValidateTarFile 失败 → false
HWTEST_F(DecompressTest, CheckPath_TarSizeNotAligned_ReturnsFalse, TestSize.Level0)
{
    std::string tar = WriteFile("bad.tar", std::string(7, 'A'));  // 非 512 整数倍
    Decompress d(tar);
    EXPECT_FALSE(d.CheckPath(workDir + "/out3"));
}

// CheckPath：decPath 已存在且为普通文件 → ValidateDecompressPath 失败 → false
HWTEST_F(DecompressTest, CheckPath_DecPathIsFile_ReturnsFalse, TestSize.Level0)
{
    // 构造一个合法 tar（大小为 512 整数倍）使 ValidateTarFile 通过
    std::string tar = WriteFile("ok.tar", std::string(512, '\0'));
    std::string outFile = WriteFile("existfile", "x");
    Decompress d(tar);
    EXPECT_FALSE(d.CheckPath(outFile));
}

// DecompressToLocal：tar 不存在 → false
HWTEST_F(DecompressTest, DecompressToLocal_TarNotExist_ReturnsFalse, TestSize.Level0)
{
    Decompress d(workDir + "/not_exist2.tar");
    EXPECT_FALSE(d.DecompressToLocal(workDir + "/dec1"));
}

// DecompressToLocal：tar 为空 → CheckPath 失败 → false
HWTEST_F(DecompressTest, DecompressToLocal_TarEmpty_ReturnsFalse, TestSize.Level0)
{
    std::string tar = WriteFile("empty2.tar", "");
    Decompress d(tar);
    EXPECT_FALSE(d.DecompressToLocal(workDir + "/dec2"));
}
}  // namespace Hdc
