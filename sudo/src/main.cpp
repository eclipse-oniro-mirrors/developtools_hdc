/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include <termios.h>
#include <cstdarg>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <securec.h>
#include <unistd.h>

#include "sudoer_plugin.h"

#if defined(SURPPORT_SELINUX)
#include "selinux/selinux.h"
#endif
#include "os_account_manager.h"
#include "parameters.h"

using namespace OHOS::AccountSA;
using namespace OHOS::system;

namespace {
static const int SUDO_ARG_MAX_NUMS = 4096;
static const std::vector<std::string> DEFAULT_PATH = {"/usr/bin", "/bin", "/system/bin", "/vendor/bin",
    "/usr/local/bin", "/data/app/bin", "/data/service/hnp/bin", "/opt/homebrew"};
static const char *DEFAULT_BASH = "/system/bin/sh";

static void WriteStdErr(const char *str)
{
    (void)fwrite(str, 1, strlen(str), stderr);
    fflush(stderr);
}

// --- TtySession RAII (TASK-8, AD-03): encapsulates g_ttyFp lifecycle ---
class TtySession {
public:
    void Write(const char *str)
    {
        if (str == nullptr) {
            return;
        }
        if (fp_ != nullptr) {
            (void)fwrite(str, 1, strlen(str), fp_);
            fflush(fp_);
            return;
        }
        fp_ = fopen("/dev/tty", "w");
        if (fp_ != nullptr) {
            (void)fwrite(str, 1, strlen(str), fp_);
            fflush(fp_);
            return;
        }
        WriteStdErr(str);
    }

    // Read a line from /dev/tty with ECHO off (termios), for PIN input (TASK-4)
    bool ReadNoEcho(char *buf, size_t bufLen)
    {
        if (buf == nullptr || bufLen == 0) {
            return false;
        }
        EnsureOpenRead();
        if (ttyRd_ == nullptr) {
            return false;
        }
        struct termios oldTermios;
        struct termios newTermios;
        if (tcgetattr(fileno(ttyRd_), &oldTermios) != 0) {
            return false;
        }
        newTermios = oldTermios;
        newTermios.c_lflag &= ~(ECHO | ECHONL);
        if (tcsetattr(fileno(ttyRd_), TCSANOW, &newTermios) != 0) {
            return false;
        }
        char *result = fgets(buf, static_cast<int>(bufLen), ttyRd_);
        (void)tcsetattr(fileno(ttyRd_), TCSANOW, &oldTermios);
        // strip trailing newline
        if (result != nullptr) {
            size_t len = strlen(buf);
            if (len > 0 && buf[len - 1] == '\n') {
                buf[len - 1] = '\0';
            }
            return true;
        }
        (void)memset_s(buf, bufLen, 0, bufLen);
        return false;
    }

    void Close()
    {
        if (fp_ != nullptr) {
            fclose(fp_);
            fp_ = nullptr;
        }
        if (ttyRd_ != nullptr) {
            fclose(ttyRd_);
            ttyRd_ = nullptr;
        }
    }

    ~TtySession()
    {
        Close();
    }

private:
    void EnsureOpenRead()
    {
        if (ttyRd_ == nullptr) {
            ttyRd_ = fopen("/dev/tty", "r");
        }
    }

    FILE *fp_ = nullptr;
    FILE *ttyRd_ = nullptr;
};

/*
 * Conversation context passed as userdata to SudoerConvFn.
 * Tracks TTY session and PIN authentication outcome for error code mapping.
 */
struct SudoerConvContext {
    TtySession *tty;
    bool pinFailed;
};

static SudoerConvContext g_convCtx = {nullptr, false};

/*
 * Handle one conversation message: display text and/or read PIN.
 * For PIN prompts, mallocs a buffer, reads into it, assigns reply->reply;
 * on failure scrubs and frees it. Returns 0 on success, -1 on failure.
 */
static int HandleConvMessage(SudoerConvContext *ctx, const SudoerConvMessage &msg,
                             SudoerConvReply *reply)
{
    if (msg.msg != nullptr) {
        ctx->tty->Write(msg.msg);
    }
    if (msg.msgType == SUDOER_CONV_PROMPT_ECHO_OFF) {
        char *pinBuf = static_cast<char *>(malloc(PIN_MAX_LEN));
        if (pinBuf == nullptr) {
            return -1;
        }
        (void)memset_s(pinBuf, PIN_MAX_LEN, 0, PIN_MAX_LEN);
        if (!ctx->tty->ReadNoEcho(pinBuf, PIN_MAX_LEN)) {
            (void)memset_s(pinBuf, PIN_MAX_LEN, 0, PIN_MAX_LEN);
            free(pinBuf);
            return -1;
        }
        reply->reply = pinBuf;
        ctx->tty->Write("\n");
    }
    return 0;
}

/*
 * Scrub and free non-null reply buffers on SudoConv failure to prevent
 * PIN leakage and double-free.
 */
static void ScrubReplies(SudoerConvReply *replies, int count)
{
    for (int j = 0; j < count; j++) {
        if (replies[j].reply != nullptr) {
            (void)memset_s(replies[j].reply, PIN_MAX_LEN, 0, PIN_MAX_LEN);
            free(replies[j].reply);
            replies[j].reply = nullptr;
        }
    }
}

/*
 * SudoConv callback: libsudoer calls this during policy check to prompt for
 * PIN. On failure, scrubs all filled replies (left all-nullptr) via
 * ScrubReplies to prevent PIN leakage.
 */
static int SudoConv(int numMsgs, const SudoerConvMessage *msgs, SudoerConvReply *replies,
                    void *userdata) noexcept
{
    if (msgs == nullptr || replies == nullptr || numMsgs <= 0) {
        return -1;
    }
    SudoerConvContext *ctx = static_cast<SudoerConvContext *>(userdata);
    if (ctx == nullptr) {
        ctx = &g_convCtx;
    }
    if (ctx->tty == nullptr) {
        return -1;
    }
    for (int i = 0; i < numMsgs; i++) {
        if (HandleConvMessage(ctx, msgs[i], &replies[i]) != 0) {
            ctx->pinFailed = true;
            ScrubReplies(replies, i + 1);
            return -1;
        }
    }
    return 0;
}

// --- Gate checks (TASK-1, TASK-5) ---
static bool IsTtyMode()
{
    return isatty(STDIN_FILENO) == 1;
}

static const char *OUT_OF_MEM = "[E0001] out of memory\n";
static const char *COMMAND_NOT_FOUND = "[E0002] command not found\n";
static const char *USER_VERIFY_FAILED = "[E0003] Sorry, try again. If screen lock password not set, set it first.\n";
static const char *USER_SWITCH_FAILED = "[E0004] Currently logged-in user has switched, please try again.\n";
static const char *TTY_REQUIRED = "[E0005] sudo must be run in a terminal (tty).\n";
static const char *POLICY_LOAD_FAILED = "[E0006] failed to load sudoer policy plugin.\n";
static const char *POLICY_DENIED = "[E0008] sudoer policy check denied.\n";
static const char *PIN_FAILED = "[E0009] command line PIN authentication failed.\n";
static const char *HELP = "sudo - execute command or script as root\n\n"
                       "usage: sudo command ...\n";

// Print buffer size for SudoerPrintFn callback
static const int PRINT_BUF_SIZE = 1024;
// User info string buffer for sudoer_policy_open
static const int USER_INFO_BUF_SIZE = 256;

// Minimum argc for a valid sudo invocation (program name + command)
static const int MIN_ARGC = 2;

static int32_t g_userId = -1;

static std::vector<std::string> envSnapshot;

/*
 * Default table of "bad" variables to remove from the environment.
 */
static std::vector<const std::string> initialBadenvTables = {
    "IFS",
    "CDPATH",
    "LOCALDOMAIN",
    "RES_OPTIONS",
    "HOSTALIASES",
    "NLSPATH",
    "PATH_LOCALE",
    "LD_*",
    "_RLD*",
    "SHLIB_PATH",
    "LDR_*",
    "LIBPATH",
    "AUTHSTATE",
    "DYLD_*",
    "KRB5_CONFIG*",
    "KRB5_KTNAME",
    "VAR_ACE",
    "USR_ACE",
    "DLC_ACE",
    "TERMINFO",             /* terminfo, exclusive path to terminfo files */
    "TERMINFO_DIRS",        /* terminfo, path(s) to terminfo files */
    "TERMPATH",             /* termcap, path(s) to termcap files */
    "TERMCAP",              /* XXX - only if it starts with '/' */
    "ENV",                  /* ksh, file to source before script runs */
    "BASH_ENV",             /* bash, file to source before script runs */
    "PS4",                  /* bash, prefix for lines in xtrace mode */
    "GLOBIGNORE",           /* bash, globbing patterns to ignore */
    "BASHOPTS",             /* bash, initial "shopt -s" options */
    "SHELLOPTS",            /* bash, initial "set -o" options */
    "JAVA_TOOL_OPTIONS",    /* java, extra command line options */
    "PERLIO_DEBUG",         /* perl, debugging output file */
    "PERLLIB",              /* perl, search path for modules/includes */
    "PERL5LIB",             /* perl 5, search path for modules/includes */
    "PERL5OPT",             /* perl 5, extra command line options */
    "PERL5DB",              /* perl 5, command used to load debugger */
    "FPATH",                /* ksh, search path for functions */
    "NULLCMD",              /* zsh, command for null file redirection */
    "READNULLCMD",          /* zsh, command for null file redirection */
    "ZDOTDIR",              /* zsh, search path for dot files */
    "TMPPREFIX",            /* zsh, prefix for temporary files */
    "PYTHONHOME",           /* python, module search path */
    "PYTHONPATH",           /* python, search path */
    "PYTHONINSPECT",        /* python, allow inspection */
    "PYTHONUSERBASE",       /* python, per user site-packages directory */
    "RUBYLIB",              /* ruby, library load path */
    "RUBYOPT",              /* ruby, extra command line options */
    "*=()*"                 /* bash functions */
};

/*
 * Default table of variables to check for '%' and '/' characters.
 */
static std::vector<std::string> initialCheckenvTables = {
    "COLORTERM",
    "LANG",
    "LANGUAGE",
    "LC_*",
    "LINGUAS",
    "TERM",
    "TZ"
};

enum class CmdType : int32_t {
    INVALID = -1,
    SCRIPT = 0,
    BINARY = 1
};

}

static void WriteStdErrFmtWithStr(const std::string& format, const std::string& error)
{
    fprintf(stderr, format.c_str(), error.c_str());
    fflush(stderr);
}

/*
 * SudoerPrintFn callback: libsudoer calls this for informational/error
 * messages; formats printf-style and writes to stderr.
 */
static int SudoerPrint(int msgType, const char *fmt, ...) noexcept
{
    (void)msgType;
    if (fmt == nullptr) {
        return 0;
    }
    char buf[PRINT_BUF_SIZE];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf_s(buf, sizeof(buf), sizeof(buf) - 1, fmt, ap);
    va_end(ap);
    if (n > 0) {
        WriteStdErr(buf);
    }
    return n;
}

static TtySession *g_ttySession = nullptr;  // set by main(), used by legacy WriteTty/CloseTty

static void WriteTty(const char *str)
{
    if (g_ttySession != nullptr) {
        g_ttySession->Write(str);
    } else {
        WriteStdErr(str);
    }
}

static char *StrDup(const char *str)
{
    int ret;
    char *result = new(std::nothrow)char[strlen(str) + 1];
    if (result == nullptr) {
        WriteStdErr(OUT_OF_MEM);
        exit(1);
    }
    ret = strcpy_s(result, strlen(str) + 1, str);
    if (ret != 0) {
        WriteStdErr(OUT_OF_MEM);
        exit(1);
    }
    return result;
}

static void FreeArgvNew(char **argvNew)
{
    char **p = nullptr;
    for (p = argvNew; *p != nullptr; p++) {
        delete [] *p;
    }
    delete [] argvNew;
}

/**
 * elf magic number: 0x7f, 'E', 'L', 'F'
 */
static bool IsElf(const std::string& path)
{
    char canonicalPath[PATH_MAX] = { 0 };
    if (realpath(path.c_str(), canonicalPath) == nullptr) {
        return false;
    }

    std::ifstream file(canonicalPath, std::ios::binary);
    if (!file) {
        return false;
    }

    const int magicCount = 4;
    const char magicNum[magicCount] = {0x7f, 'E', 'L', 'F'};
    unsigned char magic[magicCount];
    file.read(reinterpret_cast<char*>(magic), magicCount);
    if (file.gcount() < magicCount) {
        return false;
    }

    for (int i = 0; i < magicCount; i++) {
        if (magic[i] != magicNum[i]) {
            return false;
        }
    }
    return true;
}

/*
 * Find cmd from DEFAULT_PATH
 * return:
 * -1 (not exists | not support exec)
 * 0 (.sh file)
 * 1 (elf file)
*/
static CmdType GetCmdInPath(char *cmd, int cmdBufLen)
{
    std::string cmdStr(cmd);
    struct stat st;

    if (cmdStr.find('/') != std::string::npos) {
        if (stat(cmdStr.c_str(), &st) == 0 && S_ISREG(st.st_mode)) {
            if (IsElf(cmdStr)) {
                return CmdType::BINARY;
            }
            return CmdType::SCRIPT;
        } else {
            WriteTty(COMMAND_NOT_FOUND);
            return CmdType::INVALID;
        }
    }

    for (const auto &path : DEFAULT_PATH) {
        std::string cmdPath = path.empty() ? cmd : path + "/" + cmd;
        if (stat(cmdPath.c_str(), &st) == 0 && S_ISREG(st.st_mode)) {
            size_t len = cmdPath.length();
            int ret = memcpy_s(cmd, cmdBufLen - 1, cmdPath.c_str(), len);
            if (ret != EOK) {
                WriteTty(COMMAND_NOT_FOUND);
                return CmdType::INVALID;
            }
            return CmdType::BINARY;
        }
    }

    WriteTty(COMMAND_NOT_FOUND);
    return CmdType::INVALID;
}

static char** NewCStringArray(int size)
{
    if (size <= 0 || size > SUDO_ARG_MAX_NUMS) {
        return nullptr;
    }
    char** array = new(std::nothrow) char* [size];
    if (array == nullptr) {
        WriteStdErr(OUT_OF_MEM);
        return nullptr;
    }
    (void)memset_s(array, sizeof(char*) * size, 0, sizeof(char*) * size);
    return array;
}

static char** ParseShCCmd(int argc, char* argv[])
{
    int argvNewIndex = 0;
    int startCopyArgvIndex = 3;
    // sudo {"sh", "-c", "xxxx", nullptr}
    char** argvTmp = NewCStringArray(argc + 1);
    if (argvTmp == nullptr) {
        return nullptr;
    }

    argvTmp[argvNewIndex++] = StrDup(DEFAULT_BASH);
    argvTmp[argvNewIndex++] = StrDup(argv[startCopyArgvIndex - 1]);

    for (int i = startCopyArgvIndex; i < argc; i++) {
        argvTmp[argvNewIndex++] = StrDup(argv[i]);
    }
    argvTmp[argvNewIndex] = nullptr;

    return argvTmp;
}

static char** ParseBinaryCmd(int argc, char* argv[], const char* cmd)
{
    int argvNewIndex = 0;
    int startCopyArgvIndex = 2;
    // sudo {"execSh", "xxxx", nullptr}
    char** argvTmp = NewCStringArray(argc + 1);
    if (argvTmp == nullptr) {
        return nullptr;
    }

    argvTmp[argvNewIndex++] = StrDup(cmd);
    
    for (int i = startCopyArgvIndex; i < argc; i++) {
        argvTmp[argvNewIndex++] = StrDup(argv[i]);
    }
    argvTmp[argvNewIndex] = nullptr;

    return argvTmp;
}

static char** ParseScriptCmd(int argc, char* argv[])
{
    int argvNewIndex = 0;
    int startCopyArgvIndex = 1;
    const int argcAdd = 3;
    const char* shStr = "sh";
    const char* cStr = "-c";
    // sudo {"xxxx", nullptr} => sudo {"sh", "-c", "xxxx", nullptr}
    char** argvTmp = NewCStringArray(argc + argcAdd);
    if (argvTmp == nullptr) {
        return nullptr;
    }

    argvTmp[argvNewIndex++] = StrDup(shStr);
    argvTmp[argvNewIndex++] = StrDup(cStr);

    for (int i = startCopyArgvIndex; i < argc; i++) {
        argvTmp[argvNewIndex++] = StrDup(argv[i]);
    }
    argvTmp[argvNewIndex] = nullptr;

    return argvTmp;
}

static char **ParseCmd(int argc, char* argv[])
{
    bool isShc = false;
    const int argcCountLimit = 3;
    const int idxTwo = 2;

    if ((argc <= 0) || (argc > SUDO_ARG_MAX_NUMS)) {
        return nullptr;
    }

    // sudo sh -c xxxx
    if (argc >= argcCountLimit && strcmp(argv[1], "sh") == 0 && strcmp(argv[idxTwo], "-c") == 0) { //3:argc of main
        isShc = true;
        return ParseShCCmd(argc, argv);
    }

    /*
     * if not "sudo sh -c xxxx", just as "sudo xxxx"
     * 1. check xxxx by DEFAULT_PATH firstly.
     * 2. if not 1, exec shell file.
    */
    if (!isShc) {
        char cmd[PATH_MAX + 1] = {0};
        int ret = sprintf_s(cmd, PATH_MAX + 1, "%s", argv[1]);
        if (ret < 0) {
            return nullptr;
        }
        auto type = GetCmdInPath(cmd, PATH_MAX + 1);
        switch (type) {
            case CmdType::BINARY:
                return ParseBinaryCmd(argc, argv, cmd);
            case CmdType::SCRIPT: {
                return ParseScriptCmd(argc, argv);
            }
            default:
                return nullptr;
        }
    }

    return nullptr;
}

static bool SetUidGid(void)
{
    if (setuid(0) != 0) {
        return false;
    }
    if (setegid(0) != 0) {
        return false;
    }
    if (setgid(0) != 0) {
        return false;
    }
    return true;
}

static int32_t GetUserId()
{
    std::vector<int32_t> ids;

    OHOS::ErrCode err = OsAccountManager::QueryActiveOsAccountIds(ids);
    if (err != 0) {
        WriteStdErr("get os account local id failed\n");
        return -1;
    }
    if (ids.empty()) {
        WriteStdErr("os account return is empty!\n");
        return -1;
    }
    return ids[0];
}

// Map error code string to the predefined message constant.
static void WriteLocalizedError(TtySession &tty, const char *errorCode)
{
    static const std::unordered_map<std::string, const char *> ERROR_MAP = {
        {"E0003", USER_VERIFY_FAILED},
        {"E0005", TTY_REQUIRED},
        {"E0006", POLICY_LOAD_FAILED},
        {"E0008", POLICY_DENIED},
        {"E0009", PIN_FAILED},
    };
    auto it = ERROR_MAP.find(errorCode);
    if (it != ERROR_MAP.end()) {
        tty.Write(it->second);
        return;
    }
    // Not a mapped code: print verbatim (e.g. plugin errstr), ensure trailing newline.
    size_t len = strlen(errorCode);
    tty.Write(errorCode);
    if (len == 0 || errorCode[len - 1] != '\n') {
        tty.Write("\n");
    }
}

static bool UpdateEnvironmentPath()
{
    if (unsetenv("PATH") != 0) {
        WriteStdErrFmtWithStr("unsetenv failed!error message:%s\n", std::strerror(errno));
        return false;
    }

    std::string newPath;
    for (const auto &pathDir : DEFAULT_PATH) {
        if (!newPath.empty()) {
            newPath += ":";
        }
        newPath += pathDir;
    }

    if (!newPath.empty() && setenv("PATH", newPath.c_str(), 1) != 0) {
        WriteStdErrFmtWithStr("setenv failed!error message:%s\n", std::strerror(errno));
        return false;
    }

    return true;
}

static void SaveEnvSnapshot()
{
    for (int i = 0; environ[i] != nullptr; ++i) {
        envSnapshot.push_back(environ[i]);
    }
}

static bool MatchWithWildcard(const std::string& pattern, const std::string& value)
{
    size_t pIdx = 0;
    size_t vIdx = 0;
    size_t lastStar = std::string::npos;
    size_t lastMatch = 0;
    bool sawSep = false;

    size_t patternSize = pattern.size();
    size_t valueSize = value.size();

    while ((pIdx < patternSize && vIdx <= valueSize)) {
        char pChar = (pIdx < patternSize) ? pattern[pIdx] : '\0';
        char vChar = (vIdx < valueSize) ? value[vIdx] : '\0';

        if (pChar == '*') { // 跳过连续的 '*'
            while (pIdx < patternSize && pattern[pIdx] == '*') {
                pIdx++;
            }

            if (pIdx >= patternSize) { // '*'在pattern末尾，匹配任意内容
                return true;
            }

            lastStar = pIdx - 1;
            lastMatch = vIdx;

            if (((pIdx < patternSize) && (pattern[pIdx] == '='))) {
                sawSep = true;
            }
            continue;
        }
        if (pChar == vChar) {
            if (pChar == '=') {
                sawSep = true;
            }
            pIdx++;
            vIdx++;
        } else if (lastStar != std::string::npos) {
            pIdx = lastStar + 1;
            lastMatch++;
            vIdx = lastMatch;

            if (vIdx < valueSize) {
                char nextPatternChar = (pIdx < patternSize) ? pattern[pIdx] : '\0';
                if (nextPatternChar != '\0') {
                    while ((sawSep) && (vIdx < valueSize) && (value[vIdx] != nextPatternChar)) {
                        vIdx++;
                    }
                }
            }
        } else {
            return false;
        }
    }
    while ((pIdx < patternSize) && pattern[pIdx] == '*') {
        pIdx++;
    }
    return pIdx >= patternSize && vIdx >= valueSize;
}

static bool MatchesEnvPattern(const std::string& value, const std::string& pattern)
{
    size_t startPos = pattern.find('*');
    bool isWild = (startPos != std::string::npos);
    size_t len = (isWild) ? startPos : pattern.size();

    bool match = false;

    if (isWild) {
        match = MatchWithWildcard(pattern, value);
    } else {
        if (strncmp(pattern.c_str(), value.c_str(), len) == 0) {
            match = true;
        }
    }

    return match;
}

static bool MatchesEnvDel(const std::string& envItem)
{
    for (const auto& badItem : initialBadenvTables) {
        if (!badItem.empty()) {
            bool result = MatchesEnvPattern(envItem, badItem);
            if (result) {
                return result;
            }
        }
    }
    return false;
}

static bool TzIsSafe(std::string tzItem)
{
    if (!tzItem.empty() && tzItem[0] == ':') {
        tzItem = tzItem.substr(1);
    }

    if (!tzItem.empty() && tzItem[0] == '/') {
        return false;
    }

    char lastCh = '/';
    for (size_t i = 0; i < tzItem.size(); ++i) {
        char ch = tzItem[i];
        if (std::isspace(static_cast<unsigned char>(ch)) || !std::isprint(static_cast<unsigned char>(ch))) {
            return false;
        }
        if ((lastCh == '/') &&
            (ch == '.') &&
            (i + 1 < tzItem.size()) &&
            (tzItem[i + 1] == '.')) {
            const size_t next = i + 2;
            const bool isEndOrSlash = (next ==  tzItem.size() || tzItem[next] == '/');
            if (isEndOrSlash) {
                return false;
            }
        }
        lastCh = ch;
    }
    if (tzItem.size() >= PATH_MAX) {
        return false;
    }
    return true;
}

static bool CheckValueSafety(const std::string& value, const std::string& pattern)
{
    if (value.empty() || pattern.empty()) {
        return true;
    }
    
    bool result = MatchesEnvPattern(value, pattern);
    if (result) {
        size_t eqPos = value.find('=');
        if ((eqPos != std::string::npos) && (eqPos + 1 < value.size())) {
            std::string val = value.substr(eqPos + 1);
            if (val.find_first_of("/%") != std::string::npos) {
                return false;
            }
        }
    }
    return true;
}

static bool MatchesEnvCheckPattern(const std::string& value, const std::string& pattern)
{
    bool keepItem = true;
    int tzLength = 3;

    if (strncmp(value.c_str(), "TZ=", tzLength) == 0) {
        keepItem = TzIsSafe(value);
    } else {
        keepItem = CheckValueSafety(value, pattern);
    }
    return keepItem;
}

static bool MatchesEnvCheck(const std::string& envItem)
{
    for (const auto& checkItem : initialCheckenvTables) {
        if (!checkItem.empty()) {
            bool result = MatchesEnvCheckPattern(envItem, checkItem);
            if (!result) {
                return true;
            }
        }
    }
    return false;
}

static bool UpdateEnv()
{
    SaveEnvSnapshot();
    for (const auto& envItem : envSnapshot) {
        size_t sepPos = envItem.find('=');
        std::string envName = (sepPos == std::string::npos) ? envItem : envItem.substr(0, sepPos);
        if (envName.empty()) {
            return false;
        }

        bool delResult = MatchesEnvDel(envItem);
        if (delResult) {
            if (unsetenv(envName.c_str()) != 0) {
                WriteStdErrFmtWithStr("unsetenv failed for %s\n", envName);
            }
            continue;
        }

        bool checkResult = MatchesEnvCheck(envItem);
        if (checkResult) {
            if (unsetenv(envName.c_str()) != 0) {
                WriteStdErrFmtWithStr("unsetenv failed for %s\n", envName);
            }
            continue;
        }
    }
    return true;
}

static bool IsPcMode()
{
    return GetParameter("settings.sceneboard.ispcmode", "true") == "true";
}

/*
 * Check preconditions after TtySession is created: TTY mode, minor mode,
 * env path, user ID, argc. Returns true if all pass.
 */
static bool CheckGates(TtySession &ttySession, int argc)
{
    if (!IsTtyMode()) {
        WriteLocalizedError(ttySession, "E0005");
        return false;
    }
    if (!UpdateEnvironmentPath()) {
        return false;
    }
    g_userId = GetUserId();
    if (g_userId == -1) {
        return false;
    }
    if (argc < MIN_ARGC) {
        ttySession.Write(HELP);
        return false;
    }
    return true;
}

/*
 * Build userInfo for sudoer_policy_open: NUL-separated key=value pairs with
 * double-NUL terminator. Keys: user_id, gid, pid, ppid, sid, tty.
 */
static bool BuildUserInfo(char *buf, size_t bufSize)
{
    size_t off = 0;
    /*
     * Local helper: append one "key=int\0" entry, advancing off.
     */
    auto appendInt = [&buf, &bufSize, &off](const char *key, int val) -> bool {
        int n = snprintf_s(buf + off, bufSize - off, bufSize - off - 1,
                           "%s=%d", key, val);
        if (n < 0) {
            return false;
        }
        off += static_cast<size_t>(n) + 1;
        return true;
    };
    if (!appendInt("user_id", static_cast<int>(g_userId)) ||
        !appendInt("gid", static_cast<int>(getgid())) ||
        !appendInt("pid", static_cast<int>(getpid())) ||
        !appendInt("ppid", static_cast<int>(getppid())) ||
        !appendInt("sid", static_cast<int>(getsid(0)))) {
        return false;
    }
    const char *ttyName = ttyname(STDIN_FILENO);
    if (ttyName != nullptr) {
        int n = snprintf_s(buf + off, bufSize - off, bufSize - off - 1,
                           "tty=%s", ttyName);
        if (n < 0) {
            return false;
        }
        off += static_cast<size_t>(n) + 1;
    }
    if (off >= bufSize) {
        return false;
    }
    buf[off] = '\0';  // second NUL: list terminator
    return true;
}

/*
 * Run policy plugin: Load, Open, Check. Returns nullptr on success, or an
 * error string on failure (plugin errstr if non-empty, else mapped E000x).
 */
static const char *RunPolicyCheck(SudoerPlugin &plugin, TtySession &ttySession,
                                  char **argvNew)
{
    if (!plugin.Load()) {
        return "E0006";
    }
    g_convCtx.tty = &ttySession;
    g_convCtx.pinFailed = false;
    char userInfo[USER_INFO_BUF_SIZE];
    if (!BuildUserInfo(userInfo, sizeof(userInfo))) {
        return "E0006";
    }
    SudoerOpenParams openParams = {SUDOER_API_VERSION, SudoConv, SudoerPrint,
                                   "", userInfo, "", ""};
    const char *errstr = nullptr;
    if (plugin.Open(openParams, &errstr) != SUDOER_RESULT_OK) {
        return (errstr != nullptr && errstr[0] != '\0') ? errstr : "E0006";
    }
    int newArgc = 0;
    while (argvNew[newArgc] != nullptr) {
        ++newArgc;
    }
    SudoerCheckResult result;
    int checkRet = plugin.Check(newArgc, argvNew, nullptr, result, &errstr);
    if (checkRet == SUDOER_RESULT_OK) {
        return nullptr;
    }
    if (errstr != nullptr && errstr[0] != '\0') {
        return errstr;
    }
    if (g_convCtx.pinFailed) {
        return "E0009";
    }
    return (checkRet == SUDOER_RESULT_FAIL) ? "E0008" : "E0003";
}

/*
 * Execute command as root after policy approval: SELinux, UpdateEnv, execvp.
 * Does not return on success.
 */
static int ExecPrivileged(char **argvNew)
{
#if defined(SURPPORT_SELINUX)
    if (setcon("u:r:sudo_execv_label:s0") != 0) {
        WriteStdErr("set SEHarmony label failed\n");
        FreeArgvNew(argvNew);
        return 1;
    }
#endif
    if (!UpdateEnv()) {
        WriteStdErr("UpdateEnv failed\n");
        FreeArgvNew(argvNew);
        return 1;
    }
    execvp(argvNew[0], argvNew);
    WriteStdErr("execvp failed\n");
    FreeArgvNew(argvNew);
    return 1;
}

/*
 * Main flow: IsPcMode → isatty(E0005) → UpdateEnvPath → GetUserId →
 * argc(HELP) → ParseCmd(E0002) → SetUidGid(E0004) → PolicyPlugin →
 * Close → SELinux → UpdateEnv → execvp.
 */
int main(int argc, char* argv[])
{
    if (!IsPcMode()) {
        WriteStdErr("sudo is only supported in PC mode.\n");
        return 1;
    }
    TtySession ttySession;
    g_ttySession = &ttySession;
    if (!CheckGates(ttySession, argc)) {
        g_ttySession = nullptr;
        return 1;
    }
    char **argvNew = ParseCmd(argc, argv);
    if (argvNew == nullptr) {
        g_ttySession = nullptr;
        return 1;
    }
    if (!SetUidGid()) {
        WriteStdErr(USER_SWITCH_FAILED);
        FreeArgvNew(argvNew);
        g_ttySession = nullptr;
        return 1;
    }
    SudoerPlugin plugin;
    const char *policyErr = RunPolicyCheck(plugin, ttySession, argvNew);
    if (policyErr != nullptr) {
        WriteLocalizedError(ttySession, policyErr);
        FreeArgvNew(argvNew);
        g_ttySession = nullptr;
        return 1;
    }
    plugin.Close(0, 0);
    ttySession.Close();
    g_ttySession = nullptr;
    return ExecPrivileged(argvNew);
}
