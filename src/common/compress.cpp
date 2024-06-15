#include "compress.h"

#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

namespace Hdc {
bool Compress::AddPath(std::string path)
{
    if (!fs::exists(path)) {
        WRITE_LOG(LOG_FATAL, "%s is not exist", path.c_str());
        return false;
    }

    if (fs::is_regular_file(path)) {
        return AddEntry(path);
    }

    if (!AddEntry(path)) {
        return false;
    }

    for (const auto& entry : fs::directory_iterator(path)) {
        if (!AddPath(entry.path().string())) {
            return false;
        }
    }
    return true;
}

bool Compress::AddEntry(std::string path)
{
    if (this->max_count > 0 && this->entrys.size() > this->max_count) {
        WRITE_LOG(LOG_FATAL, "Exceeded the set maximum value, the maximum value is set to %zu", this->max_count);
        return false;
    }
    if (this->prefix.length() > 0 && path == this->prefix) {
        LOGI("Ignoring compressed root directory");
        return true;
    }
    Entry entry(this->prefix, path);
    WRITE_LOG(LOG_INFO, "AddEntry %s", path.c_str());
    /* memdump(); */
    entrys.push_back(entry);

    return true;
}

bool Compress::SaveToFile(std::string localPath)
{
    if (localPath.length() <= 0) {
        localPath = "tmp.tar";
    }

    if (fs::exists(localPath) && fs::is_directory(localPath)) {
        return false;
    }

    std::ofstream file(localPath.c_str(), std::ios::out | std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    WRITE_LOG(LOG_INFO, "SaveToFile entrys len : %u", entrys.size());
    for (auto& entry : entrys) {
        entry.WriteToTar(file);
    }
    file.close();
    return true;
}

void Compress::UpdataPrefix(std::string prefix)
{
    this->prefix = prefix;
}

void Compress::UpdataMaxCount(size_t maxCount)
{
    this->max_count = maxCount;
}
}
