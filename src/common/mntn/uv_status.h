/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef __H_UV_STATUS_H__
#define __H_UV_STATUS_H__

// #include "common.h"
#include <cinttypes>
#include <string>
#include <sys/time.h>
// #include <sys/types.h>
// #include <unistd.h>
#include <map>
#include "uv.h"

using std::string;

namespace Hdc {

void DispAllLoopStatus(const string &info);
class LoopStatus {
public:
    LoopStatus(uv_loop_t *loop, const string &loopName);
    ~LoopStatus();
private:
    bool Busy(void) const;
public:
    void HandleStart(const uv_loop_t *loop, const string &handle);
    void HandleEnd(const uv_loop_t *loop);
    void Display(const string &info) const;
private:
    uv_loop_t *mLoop;
    const string mLoopName;
    string mHandleName;
    struct timeval mCallBackTime;
};

class CallStatGuard {
public:
    CallStatGuard(LoopStatus &loopStatus, const uv_loop_t *loop, const string &handle) : mCommitted(false), mLoop(loop), mLoopStatus(loopStatus)
    {
        mLoopStatus.HandleStart(loop, handle);
    }
    ~CallStatGuard() {
        if (mCommitted) {
            return;
        }
        mLoopStatus.HandleEnd(mLoop);
    }
    void Commit(void) {
        if (mCommitted) {
            return;
        }
        mLoopStatus.HandleEnd(mLoop);
        mCommitted = true;
    }
private:
    bool mCommitted;
    const uv_loop_t *mLoop;
    LoopStatus &mLoopStatus;
};

} /* namespace Hdc  */

#endif /* __H_UV_STATUS_H__ */
