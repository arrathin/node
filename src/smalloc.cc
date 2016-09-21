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

#include "smalloc.h"

#include "env.h"
#include "env-inl.h"
#include "node.h"
#include "node_internals.h"
#include "v8-profiler.h"
#include "v8.h"

#include <string.h>
#include <assert.h>

#define ALLOC_ID (0xA10C)

namespace node {
namespace smalloc {

using v8::Context;
using v8::External;
using v8::ExternalArrayType;
using v8::FunctionCallbackInfo;
using v8::Handle;
using v8::HandleScope;
using v8::HeapProfiler;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::Persistent;
using v8::RetainedObjectInfo;
using v8::Uint32;
using v8::Value;
using v8::WeakCallbackData;
using v8::kExternalUint8Array;


class CallbackInfo {
 public:
  static inline void Free(char* data, void* hint);
  static inline CallbackInfo* New(Isolate* isolate,
                                  Handle<Object> object,
                                  FreeCallback callback,
                                  void* hint = 0);
  inline void Dispose(Isolate* isolate);
  inline Persistent<Object>* persistent();
 private:
  static void WeakCallback(const WeakCallbackData<Object, CallbackInfo>&);
  inline void WeakCallback(Isolate* isolate, Local<Object> object);
  inline CallbackInfo(Isolate* isolate,
                      Handle<Object> object,
                      FreeCallback callback,
                      void* hint);
  ~CallbackInfo();
  Persistent<Object> persistent_;
  FreeCallback const callback_;
  void* const hint_;
  DISALLOW_COPY_AND_ASSIGN(CallbackInfo);
};


void CallbackInfo::Free(char* data, void*) {
  ::free(data);
}


CallbackInfo* CallbackInfo::New(Isolate* isolate,
                                Handle<Object> object,
                                FreeCallback callback,
                                void* hint) {
  return new CallbackInfo(isolate, object, callback, hint);
}


void CallbackInfo::Dispose(Isolate* isolate) {
  WeakCallback(isolate, PersistentToLocal(isolate, persistent_));
}


Persistent<Object>* CallbackInfo::persistent() {
  return &persistent_;
}


CallbackInfo::CallbackInfo(Isolate* isolate,
                           Handle<Object> object,
                           FreeCallback callback,
                           void* hint)
    : persistent_(isolate, object),
      callback_(callback),
      hint_(hint) {
  persistent_.SetWeak(this, WeakCallback);
  persistent_.SetWrapperClassId(ALLOC_ID);
  persistent_.MarkIndependent();
}


CallbackInfo::~CallbackInfo() {
  persistent_.Reset();
}


void CallbackInfo::WeakCallback(
    const WeakCallbackData<Object, CallbackInfo>& data) {
  data.GetParameter()->WeakCallback(data.GetIsolate(), data.GetValue());
}


void CallbackInfo::WeakCallback(Isolate* isolate, Local<Object> object) {
  void* array_data = object->GetIndexedPropertiesExternalArrayData();
  size_t array_length = object->GetIndexedPropertiesExternalArrayDataLength();
  enum ExternalArrayType array_type =
      object->GetIndexedPropertiesExternalArrayDataType();
  size_t array_size = ExternalArraySize(array_type);
  CHECK_GT(array_size, 0);
  if (array_size > 1 && array_data != NULL) {
    CHECK_GT(array_length * array_size, array_length);  // Overflow check.
    array_length *= array_size;
  }
  object->SetIndexedPropertiesToExternalArrayData(NULL, array_type, 0);
  int64_t change_in_bytes = -static_cast<int64_t>(array_length + sizeof(*this));
  isolate->AdjustAmountOfExternalAllocatedMemory(change_in_bytes);
  callback_(static_cast<char*>(array_data), hint_);
  delete this;
}


// return size of external array type, or 0 if unrecognized
size_t ExternalArraySize(enum ExternalArrayType type) {
  switch (type) {
    case v8::kExternalUint8Array:
      return sizeof(uint8_t);
    case v8::kExternalInt8Array:
      return sizeof(int8_t);
    case v8::kExternalInt16Array:
      return sizeof(int16_t);
    case v8::kExternalUint16Array:
      return sizeof(uint16_t);
    case v8::kExternalInt32Array:
      return sizeof(int32_t);
    case v8::kExternalUint32Array:
      return sizeof(uint32_t);
    case v8::kExternalFloat32Array:
      return sizeof(float);   // NOLINT(runtime/sizeof)
    case v8::kExternalFloat64Array:
      return sizeof(double);  // NOLINT(runtime/sizeof)
    case v8::kExternalUint8ClampedArray:
      return sizeof(uint8_t);
  }
  return 0;
}


// copyOnto(source, source_start, dest, dest_start, copy_length)
void CopyOnto(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args.GetIsolate());
  HandleScope scope(env->isolate());

  if (!args[0]->IsObject())
    return env->ThrowTypeError("\x73\x6f\x75\x72\x63\x65\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x6e\x20\x6f\x62\x6a\x65\x63\x74");
  if (!args[2]->IsObject())
    return env->ThrowTypeError("\x64\x65\x73\x74\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x6e\x20\x6f\x62\x6a\x65\x63\x74");

  Local<Object> source = args[0].As<Object>();
  Local<Object> dest = args[2].As<Object>();

  if (!source->HasIndexedPropertiesInExternalArrayData())
    return env->ThrowError("\x73\x6f\x75\x72\x63\x65\x20\x68\x61\x73\x20\x6e\x6f\x20\x65\x78\x74\x65\x72\x6e\x61\x6c\x20\x61\x72\x72\x61\x79\x20\x64\x61\x74\x61");
  if (!dest->HasIndexedPropertiesInExternalArrayData())
    return env->ThrowError("\x64\x65\x73\x74\x20\x68\x61\x73\x20\x6e\x6f\x20\x65\x78\x74\x65\x72\x6e\x61\x6c\x20\x61\x72\x72\x61\x79\x20\x64\x61\x74\x61");

  size_t source_start = args[1]->Uint32Value();
  size_t dest_start = args[3]->Uint32Value();
  size_t copy_length = args[4]->Uint32Value();
  char* source_data = static_cast<char*>(
      source->GetIndexedPropertiesExternalArrayData());
  char* dest_data = static_cast<char*>(
      dest->GetIndexedPropertiesExternalArrayData());

  size_t source_length = source->GetIndexedPropertiesExternalArrayDataLength();
  enum ExternalArrayType source_type =
    source->GetIndexedPropertiesExternalArrayDataType();
  size_t source_size = ExternalArraySize(source_type);

  size_t dest_length = dest->GetIndexedPropertiesExternalArrayDataLength();
  enum ExternalArrayType dest_type =
    dest->GetIndexedPropertiesExternalArrayDataType();
  size_t dest_size = ExternalArraySize(dest_type);

  // optimization for Uint8 arrays (i.e. Buffers)
  if (source_size != 1 || dest_size != 1) {
    if (source_size == 0)
      return env->ThrowTypeError("\x75\x6e\x6b\x6e\x6f\x77\x6e\x20\x73\x6f\x75\x72\x63\x65\x20\x65\x78\x74\x65\x72\x6e\x61\x6c\x20\x61\x72\x72\x61\x79\x20\x74\x79\x70\x65");
    if (dest_size == 0)
      return env->ThrowTypeError("\x75\x6e\x6b\x6e\x6f\x77\x6e\x20\x64\x65\x73\x74\x20\x65\x78\x74\x65\x72\x6e\x61\x6c\x20\x61\x72\x72\x61\x79\x20\x74\x79\x70\x65");

    if (source_length * source_size < source_length)
      return env->ThrowRangeError("\x73\x6f\x75\x72\x63\x65\x5f\x6c\x65\x6e\x67\x74\x68\x20\x2a\x20\x73\x6f\x75\x72\x63\x65\x5f\x73\x69\x7a\x65\x20\x6f\x76\x65\x72\x66\x6c\x6f\x77");
    if (copy_length * source_size < copy_length)
      return env->ThrowRangeError("\x63\x6f\x70\x79\x5f\x6c\x65\x6e\x67\x74\x68\x20\x2a\x20\x73\x6f\x75\x72\x63\x65\x5f\x73\x69\x7a\x65\x20\x6f\x76\x65\x72\x66\x6c\x6f\x77");
    if (dest_length * dest_size < dest_length)
      return env->ThrowRangeError("\x64\x65\x73\x74\x5f\x6c\x65\x6e\x67\x74\x68\x20\x2a\x20\x64\x65\x73\x74\x5f\x73\x69\x7a\x65\x20\x6f\x76\x65\x72\x66\x6c\x6f\x77");

    source_length *= source_size;
    copy_length *= source_size;
    dest_length *= dest_size;
  }

  // necessary to check in case (source|dest)_start _and_ copy_length overflow
  if (copy_length > source_length)
    return env->ThrowRangeError("\x63\x6f\x70\x79\x5f\x6c\x65\x6e\x67\x74\x68\x20\x3e\x20\x73\x6f\x75\x72\x63\x65\x5f\x6c\x65\x6e\x67\x74\x68");
  if (copy_length > dest_length)
    return env->ThrowRangeError("\x63\x6f\x70\x79\x5f\x6c\x65\x6e\x67\x74\x68\x20\x3e\x20\x64\x65\x73\x74\x5f\x6c\x65\x6e\x67\x74\x68");
  if (source_start > source_length)
    return env->ThrowRangeError("\x73\x6f\x75\x72\x63\x65\x5f\x73\x74\x61\x72\x74\x20\x3e\x20\x73\x6f\x75\x72\x63\x65\x5f\x6c\x65\x6e\x67\x74\x68");
  if (dest_start > dest_length)
    return env->ThrowRangeError("\x64\x65\x73\x74\x5f\x73\x74\x61\x72\x74\x20\x3e\x20\x64\x65\x73\x74\x5f\x6c\x65\x6e\x67\x74\x68");

  // now we can guarantee these will catch oob access and *_start overflow
  if (source_start + copy_length > source_length)
    return env->ThrowRangeError("\x73\x6f\x75\x72\x63\x65\x5f\x73\x74\x61\x72\x74\x20\x2b\x20\x63\x6f\x70\x79\x5f\x6c\x65\x6e\x67\x74\x68\x20\x3e\x20\x73\x6f\x75\x72\x63\x65\x5f\x6c\x65\x6e\x67\x74\x68");
  if (dest_start + copy_length > dest_length)
    return env->ThrowRangeError("\x64\x65\x73\x74\x5f\x73\x74\x61\x72\x74\x20\x2b\x20\x63\x6f\x70\x79\x5f\x6c\x65\x6e\x67\x74\x68\x20\x3e\x20\x64\x65\x73\x74\x5f\x6c\x65\x6e\x67\x74\x68");

  memmove(dest_data + dest_start, source_data + source_start, copy_length);
}


// dest will always be same type as source
// for internal use:
//    dest._data = sliceOnto(source, dest, start, end);
void SliceOnto(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args.GetIsolate());
  HandleScope scope(env->isolate());

  Local<Object> source = args[0].As<Object>();
  Local<Object> dest = args[1].As<Object>();

  assert(source->HasIndexedPropertiesInExternalArrayData());
  assert(!dest->HasIndexedPropertiesInExternalArrayData());

  char* source_data = static_cast<char*>(
      source->GetIndexedPropertiesExternalArrayData());
  size_t source_len = source->GetIndexedPropertiesExternalArrayDataLength();
  enum ExternalArrayType source_type =
    source->GetIndexedPropertiesExternalArrayDataType();
  size_t source_size = ExternalArraySize(source_type);

  assert(source_size != 0);

  size_t start = args[2]->Uint32Value();
  size_t end = args[3]->Uint32Value();
  size_t length = end - start;

  if (source_size > 1) {
    assert(length * source_size >= length);
    length *= source_size;
  }

  assert(source_data != NULL || length == 0);
  assert(end <= source_len);
  assert(start <= end);

  dest->SetIndexedPropertiesToExternalArrayData(source_data + start,
                                                source_type,
                                                length);
  args.GetReturnValue().Set(source);
}


// for internal use:
//    alloc(obj, n[, type]);
void Alloc(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args.GetIsolate());
  HandleScope scope(env->isolate());

  Local<Object> obj = args[0].As<Object>();

  // can't perform this check in JS
  if (obj->HasIndexedPropertiesInExternalArrayData())
    return env->ThrowTypeError("\x6f\x62\x6a\x65\x63\x74\x20\x61\x6c\x72\x65\x61\x64\x79\x20\x68\x61\x73\x20\x65\x78\x74\x65\x72\x6e\x61\x6c\x20\x61\x72\x72\x61\x79\x20\x64\x61\x74\x61");

  size_t length = args[1]->Uint32Value();
  enum ExternalArrayType array_type;

  // it's faster to not pass the default argument then use Uint32Value
  if (args[2]->IsUndefined()) {
    array_type = kExternalUint8Array;
  } else {
    array_type = static_cast<ExternalArrayType>(args[2]->Uint32Value());
    size_t type_length = ExternalArraySize(array_type);
    assert(type_length * length >= length);
    length *= type_length;
  }

  Alloc(env, obj, length, array_type);
  args.GetReturnValue().Set(obj);
}


void Alloc(Environment* env,
           Handle<Object> obj,
           size_t length,
           enum ExternalArrayType type) {
  size_t type_size = ExternalArraySize(type);

  assert(length <= kMaxLength);
  assert(type_size > 0);

  if (length == 0)
    return Alloc(env, obj, NULL, length, type);

  char* data = static_cast<char*>(malloc(length));
  if (data == NULL) {
    FatalError("\x6e\x6f\x64\x65\x3a\x3a\x73\x6d\x61\x6c\x6c\x6f\x63\x3a\x3a\x41\x6c\x6c\x6f\x63\x28\x76\x38\x3a\x3a\x48\x61\x6e\x64\x6c\x65\x3c\x76\x38\x3a\x3a\x4f\x62\x6a\x65\x63\x74\x3e\x2c\x20\x73\x69\x7a\x65\x5f\x74\x2c"
               "\x20\x76\x38\x3a\x3a\x45\x78\x74\x65\x72\x6e\x61\x6c\x41\x72\x72\x61\x79\x54\x79\x70\x65\x29", "\x4f\x75\x74\x20\x4f\x66\x20\x4d\x65\x6d\x6f\x72\x79");
  }

  Alloc(env, obj, data, length, type);
}


void Alloc(Environment* env,
           Handle<Object> obj,
           char* data,
           size_t length,
           enum ExternalArrayType type) {
  assert(!obj->HasIndexedPropertiesInExternalArrayData());
  env->isolate()->AdjustAmountOfExternalAllocatedMemory(length);
  size_t size = length / ExternalArraySize(type);
  obj->SetIndexedPropertiesToExternalArrayData(data, type, size);
  CallbackInfo::New(env->isolate(), obj, CallbackInfo::Free);
}


// for internal use: dispose(obj);
void AllocDispose(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args.GetIsolate());
  AllocDispose(env, args[0].As<Object>());
}


void AllocDispose(Environment* env, Handle<Object> obj) {
  HandleScope handle_scope(env->isolate());

  if (env->using_smalloc_alloc_cb()) {
    Local<Value> ext_v = obj->GetHiddenValue(env->smalloc_p_string());
    if (ext_v->IsExternal()) {
      Local<External> ext = ext_v.As<External>();
      CallbackInfo* info = static_cast<CallbackInfo*>(ext->Value());
      info->Dispose(env->isolate());
      return;
    }
  }

  char* data = static_cast<char*>(obj->GetIndexedPropertiesExternalArrayData());
  size_t length = obj->GetIndexedPropertiesExternalArrayDataLength();
  enum ExternalArrayType array_type =
    obj->GetIndexedPropertiesExternalArrayDataType();
  size_t array_size = ExternalArraySize(array_type);

  assert(array_size > 0);
  assert(length * array_size >= length);

  length *= array_size;

  if (data != NULL) {
    obj->SetIndexedPropertiesToExternalArrayData(NULL,
                                                 kExternalUint8Array,
                                                 0);
    free(data);
  }
  if (length != 0) {
    int64_t change_in_bytes = -static_cast<int64_t>(length);
    env->isolate()->AdjustAmountOfExternalAllocatedMemory(change_in_bytes);
  }
}


void Alloc(Environment* env,
           Handle<Object> obj,
           size_t length,
           FreeCallback fn,
           void* hint,
           enum ExternalArrayType type) {
  assert(length <= kMaxLength);

  size_t type_size = ExternalArraySize(type);

  assert(type_size > 0);
  assert(length * type_size >= length);

  length *= type_size;

  char* data = new char[length];
  Alloc(env, obj, data, length, fn, hint, type);
}


void Alloc(Environment* env,
           Handle<Object> obj,
           char* data,
           size_t length,
           FreeCallback fn,
           void* hint,
           enum ExternalArrayType type) {
  assert(!obj->HasIndexedPropertiesInExternalArrayData());
  Isolate* isolate = env->isolate();
  HandleScope handle_scope(isolate);
  env->set_using_smalloc_alloc_cb(true);
  CallbackInfo* info = CallbackInfo::New(isolate, obj, fn, hint);
  obj->SetHiddenValue(env->smalloc_p_string(), External::New(isolate, info));
  isolate->AdjustAmountOfExternalAllocatedMemory(length + sizeof(*info));
  size_t size = length / ExternalArraySize(type);
  obj->SetIndexedPropertiesToExternalArrayData(data, type, size);
}


void HasExternalData(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args.GetIsolate());
  args.GetReturnValue().Set(args[0]->IsObject() &&
                            HasExternalData(env, args[0].As<Object>()));
}


bool HasExternalData(Environment* env, Local<Object> obj) {
  return obj->HasIndexedPropertiesInExternalArrayData();
}

void IsTypedArray(const FunctionCallbackInfo<Value>& args) {
  args.GetReturnValue().Set(args[0]->IsTypedArray());
}

void AllocTruncate(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args.GetIsolate());
  HandleScope scope(env->isolate());

  Local<Object> obj = args[0].As<Object>();

  // can't perform this check in JS
  if (!obj->HasIndexedPropertiesInExternalArrayData())
    return env->ThrowTypeError("\x6f\x62\x6a\x65\x63\x74\x20\x68\x61\x73\x20\x6e\x6f\x20\x65\x78\x74\x65\x72\x6e\x61\x6c\x20\x61\x72\x72\x61\x79\x20\x64\x61\x74\x61");

  char* data = static_cast<char*>(obj->GetIndexedPropertiesExternalArrayData());
  enum ExternalArrayType array_type =
      obj->GetIndexedPropertiesExternalArrayDataType();
  int length = obj->GetIndexedPropertiesExternalArrayDataLength();

  unsigned int new_len = args[1]->Uint32Value();
  if (new_len > kMaxLength)
    return env->ThrowRangeError("\x74\x72\x75\x6e\x63\x61\x74\x65\x20\x6c\x65\x6e\x67\x74\x68\x20\x69\x73\x20\x62\x69\x67\x67\x65\x72\x20\x74\x68\x61\x6e\x20\x6b\x4d\x61\x78\x4c\x65\x6e\x67\x74\x68");

  if (static_cast<int>(new_len) > length)
    return env->ThrowRangeError("\x74\x72\x75\x6e\x63\x61\x74\x65\x20\x6c\x65\x6e\x67\x74\x68\x20\x69\x73\x20\x62\x69\x67\x67\x65\x72\x20\x74\x68\x61\x6e\x20\x63\x75\x72\x72\x65\x6e\x74\x20\x6f\x6e\x65");

  obj->SetIndexedPropertiesToExternalArrayData(data,
                                               array_type,
                                               static_cast<int>(new_len));
}



class RetainedAllocInfo: public RetainedObjectInfo {
 public:
  explicit RetainedAllocInfo(Handle<Value> wrapper);

  virtual void Dispose();
  virtual bool IsEquivalent(RetainedObjectInfo* other);
  virtual intptr_t GetHash();
  virtual const char* GetLabel();
  virtual intptr_t GetSizeInBytes();

 private:
  static const char label_[];
  char* data_;
  int length_;
};


const char RetainedAllocInfo::label_[] = "\x73\x6d\x61\x6c\x6c\x6f\x63";


RetainedAllocInfo::RetainedAllocInfo(Handle<Value> wrapper) {
  Local<Object> obj = wrapper->ToObject();
  length_ = obj->GetIndexedPropertiesExternalArrayDataLength();
  data_ = static_cast<char*>(obj->GetIndexedPropertiesExternalArrayData());
}


void RetainedAllocInfo::Dispose() {
  delete this;
}


bool RetainedAllocInfo::IsEquivalent(RetainedObjectInfo* other) {
  return label_ == other->GetLabel() &&
         data_ == static_cast<RetainedAllocInfo*>(other)->data_;
}


intptr_t RetainedAllocInfo::GetHash() {
  return reinterpret_cast<intptr_t>(data_);
}


const char* RetainedAllocInfo::GetLabel() {
  return label_;
}


intptr_t RetainedAllocInfo::GetSizeInBytes() {
  return length_;
}


RetainedObjectInfo* WrapperInfo(uint16_t class_id, Handle<Value> wrapper) {
  return new RetainedAllocInfo(wrapper);
}


// User facing API.

void Alloc(Isolate* isolate,
           Handle<Object> obj,
           size_t length,
           enum ExternalArrayType type) {
  Alloc(Environment::GetCurrent(isolate), obj, length, type);
}


void Alloc(Isolate* isolate,
           Handle<Object> obj,
           char* data,
           size_t length,
           enum ExternalArrayType type) {
  Alloc(Environment::GetCurrent(isolate), obj, data, length, type);
}


void Alloc(Isolate* isolate,
           Handle<Object> obj,
           size_t length,
           FreeCallback fn,
           void* hint,
           enum ExternalArrayType type) {
  Alloc(Environment::GetCurrent(isolate), obj, length, fn, hint, type);
}


void Alloc(Isolate* isolate,
           Handle<Object> obj,
           char* data,
           size_t length,
           FreeCallback fn,
           void* hint,
           enum ExternalArrayType type) {
  Alloc(Environment::GetCurrent(isolate), obj, data, length, fn, hint, type);
}


void AllocDispose(Isolate* isolate, Handle<Object> obj) {
  AllocDispose(Environment::GetCurrent(isolate), obj);
}


bool HasExternalData(Isolate* isolate, Local<Object> obj) {
  return HasExternalData(Environment::GetCurrent(isolate), obj);
}


void Initialize(Handle<Object> exports,
                Handle<Value> unused,
                Handle<Context> context) {
  Environment* env = Environment::GetCurrent(context);

  NODE_SET_METHOD(exports, "\x63\x6f\x70\x79\x4f\x6e\x74\x6f", CopyOnto);
  NODE_SET_METHOD(exports, "\x73\x6c\x69\x63\x65\x4f\x6e\x74\x6f", SliceOnto);

  NODE_SET_METHOD(exports, "\x61\x6c\x6c\x6f\x63", Alloc);
  NODE_SET_METHOD(exports, "\x64\x69\x73\x70\x6f\x73\x65", AllocDispose);
  NODE_SET_METHOD(exports, "\x74\x72\x75\x6e\x63\x61\x74\x65", AllocTruncate);

  NODE_SET_METHOD(exports, "\x68\x61\x73\x45\x78\x74\x65\x72\x6e\x61\x6c\x44\x61\x74\x61", HasExternalData);
  NODE_SET_METHOD(exports, "\x69\x73\x54\x79\x70\x65\x64\x41\x72\x72\x61\x79", IsTypedArray);

  exports->Set(FIXED_ONE_BYTE_STRING(env->isolate(), "\x6b\x4d\x61\x78\x4c\x65\x6e\x67\x74\x68"),
               Uint32::NewFromUnsigned(env->isolate(), kMaxLength));

  HeapProfiler* heap_profiler = env->isolate()->GetHeapProfiler();
  heap_profiler->SetWrapperClassInfoProvider(ALLOC_ID, WrapperInfo);
}


}  // namespace smalloc
}  // namespace node

NODE_MODULE_CONTEXT_AWARE_BUILTIN(smalloc, node::smalloc::Initialize)
