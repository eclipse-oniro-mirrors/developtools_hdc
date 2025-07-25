/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#ifndef HDC_COMMON_H
#define HDC_COMMON_H

#include <algorithm>
#include <assert.h>
#include <atomic>
#include <cctype>
#include <cinttypes>
#include <condition_variable>
#include <cstdarg>
#include <ctime>
#include <fcntl.h>
#include <functional>
#include <list>
#ifdef CONFIG_USE_JEMALLOC_DFX_INIF
#include <malloc.h>
#endif
#include <map>
#include <mutex>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <queue>
#include <set>
#include <stdio.h>
#include <string>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_set>
#include <vector>

using std::condition_variable;
using std::list;
using std::map;
using std::mutex;
using std::string;
using std::vector;

// clang-format off
#include <uv.h>  // libuv 1.35
#ifdef HDC_HOST

#ifdef HARMONY_PROJECT
#include <libusb/libusb.h>
#else  // NOT HARMONY_PROJECT
#include <libusb-1.0/libusb.h>
#endif // END HARMONY_PROJECT

#else // NOT HDC_HOST
#endif // HDC_HOST

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/un.h>
#endif

#include <securec.h>
#include <limits.h>

#include "circle_buffer.h"
#include "define.h"
#include "debug.h"
#include "base.h"
#include "task.h"
#ifdef HDC_SUPPORT_ENCRYPT_TCP
#include "hdc_ssl.h"
#endif
#include "channel.h"
#include "session.h"
#include "auth.h"

#include "tcp.h"
#include "usb.h"
#ifdef HDC_SUPPORT_UART
#include "uart.h"
#endif
#include "file_descriptor.h"

// clang-format on

#endif  // !defined(COMMON_H_INCLUDED)
