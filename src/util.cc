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
#ifdef __MVS__
#ifndef _AE_BIMODAL
#define _AE_BIMODAL 1
#endif
#include "zos.h"
#endif
#include "util.h"
#include "string_bytes.h"
#include "node_buffer.h"
#include "node_internals.h"
#include "uv.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>

namespace node {

using v8::Isolate;
using v8::Local;
using v8::String;
using v8::Value;

template <typename T>
static void MakeUtf8String(Isolate* isolate,
                           Local<Value> value,
                           T* target) {
  Local<String> string = value->ToString(isolate);
  if (string.IsEmpty())
    return;

  const size_t storage = StringBytes::StorageSize(isolate, string, UTF8) + 1;
  target->AllocateSufficientStorage(storage);
  const int flags =
      String::NO_NULL_TERMINATION | String::REPLACE_INVALID_UTF8;
  const int length = string->WriteUtf8(target->out(), storage, 0, flags);
  target->SetLengthAndZeroTerminate(length);
}

Utf8Value::Utf8Value(Isolate* isolate, Local<Value> value) {
  if (value.IsEmpty())
    return;

  MakeUtf8String(isolate, value, this);
}


NativeEncodingValue::NativeEncodingValue(Isolate* isolate, Local<Value> value) {
  if (value.IsEmpty())
    return;

  MakeUtf8String(isolate, value, this);
#ifdef __MVS__
  __a2e_l(out(), length());
#endif
}


E2A::E2A(const char* val)
  : length_(strlen(val)) {
    str_ = (char *)malloc(sizeof(char) * length_ + 1);
    assert(str_ != NULL);
    memcpy(str_, val, length_);
    str_[length_] = NULL;
#ifdef __MVS__
    __e2a_l(str_, length_);
#endif
}


E2A::E2A(const char* val, unsigned len)
  : length_(len) {
    str_ = (char *)malloc(sizeof(char) * length_ + 1);
    assert(str_ != NULL);
    memcpy(str_, val, length_);
    str_[length_] = NULL;
#ifdef __MVS__
    __e2a_l(str_, length_);
#endif
}

E2A::E2A(const char* prefix, const char* val)
  : length_(0) {
    int prelen = strlen(prefix);
    int vallen = strlen(val);
    length_ = prelen + vallen;

    str_ = (char *)malloc(sizeof(char) * length_ + 1);
    assert(str_ != NULL);
    memcpy(str_, prefix, prelen);
    memcpy(str_ + prelen, val, vallen);
    str_[length_] = NULL;
#ifdef __MVS__
    __e2a_l(str_ + prelen, vallen);
#endif
}

A2E::A2E(const char * val)
  : length_(strlen(val)) {
    str_ = (char *)malloc(sizeof(char) * length_ + 1);
    assert(str_ != NULL);
    memcpy(str_, val, length_);
    str_[length_] = NULL;
#ifdef __MVS__
    __a2e_l(str_, length_);
#endif
  }

A2E::A2E(const char * val, unsigned len) 
  : length_(len) {
    str_ = (char *)malloc(sizeof(char) * length_ + 1);
    assert(str_ != NULL);
    memcpy(str_, val, length_);
    str_[length_] = NULL;
#ifdef __MVS__
    __a2e_l(str_, length_);
#endif
  }
TwoByteValue::TwoByteValue(Isolate* isolate, Local<Value> value) {
  if (value.IsEmpty()) {
    return;
  }

  Local<String> string = value->ToString(isolate);
  if (string.IsEmpty())
    return;

  // Allocate enough space to include the null terminator
  const size_t storage = string->Length() + 1;
  AllocateSufficientStorage(storage);

  const int flags =
      String::NO_NULL_TERMINATION | String::REPLACE_INVALID_UTF8;
  const int length = string->Write(out(), 0, storage, flags);
  SetLengthAndZeroTerminate(length);
}

BufferValue::BufferValue(Isolate* isolate, Local<Value> value) {
  // Slightly different take on Utf8Value. If value is a String,
  // it will return a Utf8 encoded string. If value is a Buffer,
  // it will copy the data out of the Buffer as is.
  if (value.IsEmpty()) {
    // Dereferencing this object will return nullptr.
    Invalidate();
    return;
  }

  if (value->IsString()) {
    MakeUtf8String(isolate, value, this);
  } else if (Buffer::HasInstance(value)) {
    const size_t len = Buffer::Length(value);
    // Leave place for the terminating '\0' byte.
    AllocateSufficientStorage(len + 1);
    memcpy(out(), Buffer::Data(value), len);
    SetLengthAndZeroTerminate(len);
  } else {
    Invalidate();
  }
#ifdef __MVS__
  __a2e_l(out(), length());
#endif
}

void LowMemoryNotification() {
  if (v8_initialized) {
    auto isolate = v8::Isolate::GetCurrent();
    if (isolate != nullptr) {
      isolate->LowMemoryNotification();
    }
  }
}

std::string GetHumanReadableProcessName() {
  char name[1024];
  GetHumanReadableProcessName(&name);
  return name;
}

void GetHumanReadableProcessName(char (*name)[1024]) {
  char title[1024] = "Node.js";
  uv_get_process_title(title, sizeof(title));
  __snprintf_a(*name, sizeof(*name), "%s[%u]", title, uv_os_getpid());
}

}  // namespace node
