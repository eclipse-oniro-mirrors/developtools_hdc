#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2025 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import os
import stat
import threading
import time
import logging
import pytest


from utils import GP, run_command_with_timeout, get_shell_result, \
    check_shell, check_version, get_local_path, rmdir, load_gp \


SEP = "/"
MOUNT_POINT = "storage"
TEST_FILE_SIZE = 20 # 20KB

logger = logging.getLogger(__name__)


def create_test_file(file_path, size, random=False):
    flags = os.O_CREAT | os.O_WRONLY | os.O_EXCL
    modes = stat.S_IWUSR | stat.S_IRUSR
    with os.fdopen(os.open(file_path, flags, modes), 'wb') as f:
        if random:
            f.write(os.urandom(size * 1024))  # 100KB
        else:
            f.seek(size * 1024 - 1)  # 移动到文件末尾
            f.write(b'\xff')  # 写入一个零字节


def create_binary_tree(depth, path='.', size=TEST_FILE_SIZE):
    if depth == 0:
        create_test_file(os.path.join(path, f'{size}KB.rand'), size, random=True)
        create_test_file(os.path.join(path, f'{size}KB.same'), size, random=False)
    else:
        # 创建左右子目录
        left_path = os.path.join(path, '1')
        right_path = os.path.join(path, '2')
        os.makedirs(left_path, exist_ok=True)
        os.makedirs(right_path, exist_ok=True)
        
        # 递归创建下一层目录
        create_binary_tree(depth - 1, left_path, size)
        create_binary_tree(depth - 1, right_path, size)


class TestFileNoSpace:
    fd_count = 0
    
    @staticmethod
    def send_file_to_storage():
        if not check_shell(f"shell dd if={SEP}dev/zero bs=500M count=24 of={SEP}storage/it_full.img",
            "space left on device"):
            return False
        re_send_time = 10
        for i in range(1, re_send_time + 1):
            logger.info("send %d times", i)
            output_str, error_str = run_command_with_timeout(f"{GP.hdc_head} "
                f"file send -z {get_local_path('.')} {SEP}{MOUNT_POINT}/it_nospace_{i}", 25)
            if "Command timed out" in error_str:
                logger.warning("error_str: %s", error_str)
                return False
            if "space left on device" not in output_str:
                logger.warning(f"output_str: %s", output_str)
                return False
        return True

    @staticmethod
    def teardown_class():
        check_shell(f"shell rm -rf {SEP}{MOUNT_POINT}/it_*")

    def setup_class(self):
        check_shell(f"shell rm -rf {SEP}{MOUNT_POINT}/it_*")
        check_shell("shell pkill hdcd")
        time.sleep(3)
        run_command_with_timeout(f"{GP.hdc_head} wait", 3) # reboot takes up to 30 seconds
        self.fd_count = get_shell_result(f"shell ls -al {SEP}proc/`pidof hdcd`/fd | wc -l")

    @pytest.mark.L2
    @check_version("Ver: 3.1.0e")
    def test_file_compress_z_fd_leak(self):
        assert self.send_file_to_storage()

    @pytest.mark.L2
    @check_version("Ver: 3.1.0e")
    def test_file_compress_z_fd_proc(self):
        assert not check_shell(f"shell ls -al {SEP}proc/`pidof hdcd`/fd", "it_nospace")

    @pytest.mark.L2
    @check_version("Ver: 3.1.0e")
    def test_file_compress_z_fd_count(self):
        assert get_shell_result(f"shell ls -al {SEP}proc/`pidof hdcd`/fd | wc -l") <= self.fd_count


class TestFileReFullSpace:
    stop_flag = threading.Event()
    fd_count = 0

    @staticmethod
    def teardown_class(self):
        check_shell(f"shell rm -rf {SEP}{MOUNT_POINT}/it_*")
        check_shell(f"shell rm -rf {SEP}{MOUNT_POINT}/gen_*")
        rmdir(get_local_path("tree"))

    def re_create_file(self, num=600):
        for i in range(1, num):
            check_shell(f"shell rm -rf {SEP}{MOUNT_POINT}/it_*;"
                        f" dd if={SEP}dev/zero bs=1M count=10240 of="
                        f"{SEP}storage/it_full.img")
            logger.info("re create file count:%d", i)
            if self.stop_flag.is_set():
                break

    def re_send_file(self):
        re_create_file_thread = threading.Thread(target=self.re_create_file)
        re_create_file_thread.start()
        result = True
        re_send_time = 10
        for i in range(1, re_send_time + 1):
            output_str, error_str = run_command_with_timeout(f"{GP.hdc_head} "
                f"file send -z {get_local_path('.')} {SEP}{MOUNT_POINT}/it_nospace_{i}", 25)
            logger.info("output:%s,error:%s", output_str, error_str)
            if "Command timed out" in error_str:
                logger.warning("Command timed out")
                result = False
                break
            if "Transfer Stop" not in output_str:
                logger.warning("Transfer Stop NOT FOUNT")
                result = False
                break
        self.stop_flag.set()
        re_create_file_thread.join()
        return result

    def setup_class(self):
        if not os.path.exists(get_local_path("tree")):  
            depth = 10  # 目录深度
            create_binary_tree(depth, get_local_path("tree"))
        check_shell(f"shell rm -rf {SEP}{MOUNT_POINT}/it_*")
        check_shell(f"shell rm -rf {SEP}{MOUNT_POINT}/gen_*")
        storage_size = get_shell_result(
            f"shell \"df {SEP}{MOUNT_POINT} | grep {MOUNT_POINT}\"").split()[3]
        logger.info("storage size =%s", storage_size)
        assert int(storage_size) >= 10
        gen_size = int(storage_size) - 10
        logger.info("gen size = %d", gen_size)
        check_shell(f"shell dd if={SEP}dev/zero bs={gen_size}K count=1 of="
                    f"{SEP}{MOUNT_POINT}/gen_{gen_size}.img")
        check_shell("shell pkill hdcd")
        time.sleep(3)
        run_command_with_timeout(f"{GP.hdc_head} wait", 3)
        self.fd_count = get_shell_result(f"shell ls -al {SEP}proc/`pidof hdcd`/fd | wc -l")

    @pytest.mark.L2
    @check_version("Ver: 3.1.0e")
    def test_file_compress_z_processing(self):
        assert self.re_send_file()

    @pytest.mark.L2
    @check_version("Ver: 3.1.0e")
    def test_file_compress_z_fd_proc(self):
        assert not check_shell(f"shell ls -al {SEP}proc/`pidof hdcd`/fd", "it_nospace")

    @pytest.mark.L2
    @check_version("Ver: 3.1.0e")
    def test_file_compress_z_fd_count(self):
        assert get_shell_result(f"shell ls -al {SEP}proc/`pidof hdcd`/fd | wc -l") == self.fd_count