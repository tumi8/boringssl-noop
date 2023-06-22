// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tag.h"

#include "fillins/check.h"

namespace bssl::der {

Tag ContextSpecificConstructed(uint8_t tag_number) {
  DCHECK_EQ(tag_number, tag_number & kTagNumberMask);
  return (tag_number & kTagNumberMask) | kTagConstructed | kTagContextSpecific;
}

Tag ContextSpecificPrimitive(uint8_t base) {
  DCHECK_EQ(base, base & kTagNumberMask);
  return (base & kTagNumberMask) | kTagPrimitive | kTagContextSpecific;
}

bool IsConstructed(Tag tag) {
  return (tag & kTagConstructionMask) == kTagConstructed;
}

}  // namespace bssl::der
