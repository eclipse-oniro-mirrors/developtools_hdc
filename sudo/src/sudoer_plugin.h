/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

/*
 * libsudoer policy plugin C ABI contract and C++ RAII wrapper.
 * Defines the interface that /system/lib64/libsudoer.z.so must export,
 * plus SudoerPlugin that sudo uses to load and call the plugin via dlopen/dlsym.
 */

#ifndef SUDO_SUDOER_PLUGIN_H
#define SUDO_SUDOER_PLUGIN_H

#ifdef __cplusplus
extern "C" {
#endif

// ---- C ABI: constants and types ----

// PIN maximum length (size of malloc'd reply buffer)
#define PIN_MAX_LEN 256

// Sudoer API version passed to sudoer_policy_open
#define SUDOER_API_VERSION 1u

// Conversation message types
enum SudoerConvMsgType {
    SUDOER_CONV_PROMPT_ECHO_OFF = 1, /* PIN input, echo off */
    SUDOER_CONV_PROMPT_ECHO_ON = 2,  /* normal input, echo on */
    SUDOER_CONV_ERROR_MSG = 3,       /* error display */
    SUDOER_CONV_INFO_MSG = 4,        /* info display */
};

// Policy open/check return values
#define SUDOER_RESULT_OK    1
#define SUDOER_RESULT_FAIL  0
#define SUDOER_RESULT_ERROR (-1)

/*
 * Conversation message (libsudoer -> sudo callback).
 * timeout: max wait seconds for user input (0 = no timeout).
 */
struct SudoerConvMessage {
    int msgType;
    int timeout;
    const char *msg;
};

/*
 * Conversation reply (sudo callback fills). reply is a pointer to a PIN buffer
 * malloc'd by the callback; nullptr when not filled. On success, libsudoer must
 * memset_s and free each non-null reply after use. On failure (-1), the callback
 * has already scrubbed and freed all buffers.
 */
struct SudoerConvReply {
    char *reply;
};

/*
 * Conversation callback: libsudoer calls this during policy check to prompt
 * for PIN. userdata is nullptr (sudoer_policy_open has no userdata parameter);
 * SudoConv falls back to a global context. libsudoer must zero-initialize the
 * replies array before calling. Returns SUDOER_RESULT_OK or SUDOER_RESULT_ERROR.
 */
typedef int (*SudoerConvFn)(int numMsgs, const struct SudoerConvMessage *msgs,
                            struct SudoerConvReply *replies, void *userdata);

/*
 * Print callback: libsudoer calls this for informational/error messages.
 * msgType is a SudoerConvMsgType value; fmt is printf-style.
 */
typedef int (*SudoerPrintFn)(int msgType, const char *fmt, ...);

#ifdef __cplusplus
}  // extern "C"

// ---- C++ RAII wrapper (not part of C ABI) ----

#include <dlfcn.h>

/*
 * Function pointer typedefs for dlsym resolution. Exported symbols are
 * snake_case (sudoer_policy_open/check/close).
 *
 * Open: (version, conversation, sudoPrintf, settings, userInfo, userEnv,
 *        pluginOptions, errstr) -> int
 *   userInfo is NUL-separated key=value pairs, double-NUL terminated.
 *   Returns SUDOER_RESULT_OK on success.
 *
 * Check: (argc, argv, envAdd, commandInfo, argvOut, userEnvOut, errstr) -> int
 *   May call conversation for PIN auth.
 *   Returns OK to allow, FAIL to deny, ERROR on error.
 *
 * Close: (exitStatus, error) -> void
 */
typedef int (*SudoerPolicyOpenFn)(unsigned int version, SudoerConvFn conversation,
                                  SudoerPrintFn sudoPrintf, const char *settings,
                                  const char *userInfo, const char *userEnv,
                                  const char *pluginOptions, const char **errstr);
typedef int (*SudoerPolicyCheckFn)(int argc, char *const argv[], char *const envAdd[],
                                   char ***commandInfo, char ***argvOut,
                                   char ***userEnvOut, const char **errstr);
typedef void (*SudoerPolicyCloseFn)(int exitStatus, int error);

// Parameters for SudoerPlugin::Open (packed to respect param-count guideline)
struct SudoerOpenParams {
    unsigned int version;
    SudoerConvFn conversation;
    SudoerPrintFn sudoPrintf;
    const char *settings;
    const char *userInfo;
    const char *userEnv;
    const char *pluginOptions;
};

// Output from SudoerPlugin::Check (plugin-owned, valid until Close)
struct SudoerCheckResult {
    char **commandInfo = nullptr;
    char **argvOut = nullptr;
    char **userEnvOut = nullptr;
};

/*
 * RAII wrapper for libsudoer policy plugin. Destructor closes the policy
 * session but does NOT dlclose (see ~SudoerPlugin).
 */
struct SudoerPlugin {
    void *dlHandle = nullptr;
    SudoerPolicyOpenFn policyOpen = nullptr;
    SudoerPolicyCheckFn policyCheck = nullptr;
    SudoerPolicyCloseFn policyClose = nullptr;
    bool opened = false;

    // Load libsudoer.z.so and resolve three symbols (RTLD_NOW).
    bool Load()
    {
        const char *libsudoerPath = "/system/lib64/libsudoer.z.so";
        dlHandle = dlopen(libsudoerPath, RTLD_NOW);
        if (dlHandle == nullptr) {
            return false;
        }
        policyOpen = reinterpret_cast<SudoerPolicyOpenFn>(
            dlsym(dlHandle, "sudoer_policy_open"));
        policyCheck = reinterpret_cast<SudoerPolicyCheckFn>(
            dlsym(dlHandle, "sudoer_policy_check"));
        policyClose = reinterpret_cast<SudoerPolicyCloseFn>(
            dlsym(dlHandle, "sudoer_policy_close"));
        if (policyOpen == nullptr || policyCheck == nullptr || policyClose == nullptr) {
            return false;
        }
        return true;
    }

    // Open policy session (calls sudoer_policy_open via dlsym).
    int Open(const SudoerOpenParams &params, const char **errstr)
    {
        if (policyOpen == nullptr) {
            return SUDOER_RESULT_ERROR;
        }
        int ret = policyOpen(params.version, params.conversation, params.sudoPrintf,
                             params.settings, params.userInfo, params.userEnv,
                             params.pluginOptions, errstr);
        if (ret == SUDOER_RESULT_OK) {
            opened = true;
        }
        return ret;
    }

    // Check policy (calls sudoer_policy_check via dlsym).
    int Check(int argc, char *const argv[], char *const envAdd[],
              SudoerCheckResult &result, const char **errstr)
    {
        if (policyCheck == nullptr) {
            return SUDOER_RESULT_ERROR;
        }
        return policyCheck(argc, argv, envAdd, &result.commandInfo,
                           &result.argvOut, &result.userEnvOut, errstr);
    }

    // Close policy session (calls sudoer_policy_close via dlsym if opened). Idempotent.
    void Close(int exitStatus, int error)
    {
        if (opened && policyClose != nullptr) {
            policyClose(exitStatus, error);
            opened = false;
        }
    }

    /*
     * Destructor: close policy session if open. The dlopen handle is NOT
     * dlclose'd — sudo is short-lived; execvp or exit reclaims the .so.
     */
    ~SudoerPlugin()
    {
        Close(0, 0);
    }
};

#endif  // __cplusplus

#endif  // SUDO_SUDOER_PLUGIN_H
