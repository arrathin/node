// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

#include "util.h"

#include "string_bytes.h"
#include <string.h>
#include <unistd.h>

namespace node {

Utf8Value::Utf8Value(v8::Handle<v8::Value> value)
  : length_(0), str_(NULL) {
  if (value.IsEmpty())
    return;

  v8::Local<v8::String> val_ = value->ToString();
  if (val_.IsEmpty())
    return;

  // Allocate enough space to include the null terminator
  size_t len = StringBytes::StorageSize(val_, UTF8) + 1;

  char* str = static_cast<char*>(calloc(1, len));

  int flags = WRITE_UTF8_FLAGS;
  flags |= ~v8::String::NO_NULL_TERMINATION;

  length_ = val_->WriteUtf8(str,
                            len,
                            0,
                            flags);

  str_ = reinterpret_cast<char*>(str);
}

//Assumption is that Utf8Value contains chars in
//the range ASCII range (0x0 ... 0x7f)
NativeEncodingValue::NativeEncodingValue(Utf8Value &val)
  : length_(0), str_(NULL) {
    length_ = val.length_;
    str_ = (char *)malloc(sizeof(char) * length_ + 1);
    assert(str_ != NULL);
    memcpy(str_, val.str_, length_);
    str_[length_] = NULL;
    __a2e_s(str_);
  }

NativeEncodingValue::NativeEncodingValue(const Utf8Value &val)
  : length_(0), str_(NULL) {
    length_ = val.length_;
    str_ = (char *)malloc(sizeof(char) * length_ + 1);
    assert(str_ != NULL);
    memcpy(str_, val.str_, length_);
    str_[length_] = NULL;
    __a2e_s(str_);
  }

}  // namespace node
