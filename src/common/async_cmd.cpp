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
#include "async_cmd.h"

namespace Hdc {
// Do not add thread-specific init op in the following methods as it's running in child thread.
AsyncCmd::AsyncCmd()
{
}

AsyncCmd::~AsyncCmd()
{
    if (childShell != nullptr) {
        delete childShell;
        childShell = nullptr;
    }
    WRITE_LOG(LOG_DEBUG, "~AsyncCmd");
};

bool AsyncCmd::ReadyForRelease()
{
    if (childShell != nullptr && !childShell->ReadyForRelease()) {
        return false;
    }
    if (refCount != 0) {
        return false;
    }
    if (childShell != nullptr) {
        delete childShell;
        childShell = nullptr;
    }
    Base::CloseFd(fd);
    return true;
}

void AsyncCmd::DoRelease()
{
    WRITE_LOG(LOG_DEBUG, "AsyncCmd::DoRelease finish");
    if (childShell != nullptr) {
        childShell->StopWork(false, nullptr);
    }
    if (pid > 0) {
        uv_kill(pid, SIGTERM);
    }
}

bool AsyncCmd::Initial(uv_loop_t *loopIn, const CmdResultCallback callback, uint32_t optionsIn)
{
#if defined _WIN32 || defined HDC_HOST
    WRITE_LOG(LOG_FATAL, "Not support for win32 or host side");
    return false;
#endif
    loop = loopIn;
    resultCallback = callback;
    options = optionsIn;
    return true;
}

bool AsyncCmd::FinishShellProc(const void *context, const bool result, const string exitMsg)
{
    WRITE_LOG(LOG_DEBUG, "FinishShellProc finish");
    AsyncCmd *thisClass = (AsyncCmd *)context;
    thisClass->resultCallback(true, result, thisClass->cmdResult + exitMsg);
    --thisClass->refCount;
    return true;
};

bool AsyncCmd::ChildReadCallback(const void *context, uint8_t *buf, const int size)
{
    AsyncCmd *thisClass = (AsyncCmd *)context;
    if (thisClass->options & OPTION_COMMAND_ONETIME) {
        string s((char *)buf, size);
        thisClass->cmdResult += s;
        return true;
    }
    string s((char *)buf, size);
    return thisClass->resultCallback(false, 0, s);
};

int AsyncCmd::Popen(string command, bool readWrite, int &pid)
{
#ifdef _WIN32
    return ERR_NO_SUPPORT;
#else
    constexpr uint8_t PIPE_READ = 0;
    constexpr uint8_t PIPE_WRITE = 1;
    pid_t childPid;
    int fd[2];
    pipe(fd);

    if ((childPid = fork()) == -1) {
        return ERR_GENERIC;
    }
    if (childPid == 0) {
        Base::DeInitProcess();
        if (readWrite) {
            dup2(fd[PIPE_WRITE], STDOUT_FILENO);
            dup2(fd[PIPE_WRITE], STDERR_FILENO);
        } else {
            dup2(fd[PIPE_READ], STDIN_FILENO);
        }
        Base::CloseFd(fd[PIPE_READ]);
        Base::CloseFd(fd[PIPE_WRITE]);

        setsid();
        setpgid(childPid, childPid);
        string shellPath = Base::GetShellPath();
        execl(shellPath.c_str(), shellPath.c_str(), "-c", command.c_str(), NULL);
        exit(0);
    } else {
        if (readWrite) {
            Base::CloseFd(fd[PIPE_WRITE]);
            fcntl(fd[PIPE_READ], F_SETFD, FD_CLOEXEC);
        } else {
            Base::CloseFd(fd[PIPE_READ]);
            fcntl(fd[PIPE_WRITE], F_SETFD, FD_CLOEXEC);
        }
    }
    pid = childPid;
    if (readWrite) {
        return fd[PIPE_READ];
    } else {
        return fd[PIPE_WRITE];
    }
#endif
}

bool AsyncCmd::ExecuteCommand(const string &command)
{
    string cmd = command;
    Base::Trim(cmd, "\"");
    Base::DeInitProcess();
    if ((fd = Popen(cmd, true, pid)) < 0) {
        return false;
    }
    childShell = new(std::nothrow) HdcFileDescriptor(loop, fd, this, ChildReadCallback, FinishShellProc);
    if (childShell == nullptr) {
        WRITE_LOG(LOG_FATAL, "ExecuteCommand new childShell failed");
        return false;
    }
    if (!childShell->StartWork()) {
        return false;
    }
    ++refCount;
    return true;
}
}  // namespace Hdc
