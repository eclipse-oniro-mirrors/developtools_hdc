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

#ifndef __H_TLV_H__
#define __H_TLV_H__

#include "common.h"
// #include <cstdint>
// #include <map>
// #include <set>

namespace Hdc {

struct TLV {
    uint32_t tag;
    uint32_t len;
    uint8_t *val;
};

class TlvBuf {
public:
    // construct a empty TlvBuf object with valid tags
    TlvBuf(std::set<uint32_t> validtags);
    // construct a TlvBuf object from a TLV buffer with valid tags
    TlvBuf(uint8_t *tlvs, uint32_t size, std::set<uint32_t> validtags);
    ~TlvBuf();
public:
    bool Append(const struct TLV *t, const uint32_t size);
    bool Append(const uint32_t tag, const uint32_t len, const uint8_t *val);
    uint32_t GetBufSize(void) const;
    bool CopyToBuf(uint8_t *dst, const uint32_t size) const;
    // // the caller must free the memory pointed by the return value if not null
    struct TLV *FindTlv(const uint32_t tag) const;
    // // if return true, invalid_tags is empty, else the invalid tags will bring out by invalid_tags
    bool ContainInvalidTag(void) const;
    void Clear(void);
    void Display(void) const;
private:
    // key is the tag
    std::map<uint32_t, struct TLV> mTlvMap;
    std::set<uint32_t> mValidTags;
};

}

#endif
