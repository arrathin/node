#include "node.h"
#include "env-inl.h"
#include "util-inl.h"
#include "v8.h"
#include <unistd.h>

namespace node {

using v8::Array;
using v8::ArrayBuffer;
using v8::Context;
using v8::FunctionCallbackInfo;
using v8::HeapSpaceStatistics;
using v8::HeapStatistics;
using v8::Isolate;
using v8::Local;
using v8::NewStringType;
using v8::Object;
using v8::String;
using v8::Uint32;
using v8::V8;
using v8::Value;

#define HEAP_STATISTICS_PROPERTIES(V)                                         \
  V(0, total_heap_size, kTotalHeapSizeIndex)                                  \
  V(1, total_heap_size_executable, kTotalHeapSizeExecutableIndex)             \
  V(2, total_physical_size, kTotalPhysicalSizeIndex)                          \
  V(3, total_available_size, kTotalAvailableSize)                             \
  V(4, used_heap_size, kUsedHeapSizeIndex)                                    \
  V(5, heap_size_limit, kHeapSizeLimitIndex)

#define V(a, b, c) +1
static const size_t kHeapStatisticsPropertiesCount =
    HEAP_STATISTICS_PROPERTIES(V);
#undef V

#define HEAP_SPACE_STATISTICS_PROPERTIES(V)                                   \
  V(0, space_size, kSpaceSizeIndex)                                           \
  V(1, space_used_size, kSpaceUsedSizeIndex)                                  \
  V(2, space_available_size, kSpaceAvailableSizeIndex)                        \
  V(3, physical_space_size, kPhysicalSpaceSizeIndex)

#define V(a, b, c) +1
static const size_t kHeapSpaceStatisticsPropertiesCount =
    HEAP_SPACE_STATISTICS_PROPERTIES(V);
#undef V

// Will be populated in InitializeV8Bindings.
static size_t number_of_heap_spaces = 0;


void UpdateHeapStatisticsArrayBuffer(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  HeapStatistics s;
  env->isolate()->GetHeapStatistics(&s);
  double* const buffer = env->heap_statistics_buffer();
#define V(index, name, _) buffer[index] = static_cast<double>(s.name());
  HEAP_STATISTICS_PROPERTIES(V)
#undef V
}


void UpdateHeapSpaceStatisticsBuffer(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  HeapSpaceStatistics s;
  Isolate* const isolate = env->isolate();
  double* buffer = env->heap_space_statistics_buffer();

  for (size_t i = 0; i < number_of_heap_spaces; i++) {
    isolate->GetHeapSpaceStatistics(&s, i);
    size_t const property_offset = i * kHeapSpaceStatisticsPropertiesCount;
#define V(index, name, _) buffer[property_offset + index] = \
                              static_cast<double>(s.name());
      HEAP_SPACE_STATISTICS_PROPERTIES(V)
#undef V
  }
}


void SetFlagsFromString(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  if (args.Length() < 1)
    return env->ThrowTypeError("\x76\x38\x20\x66\x6c\x61\x67\x20\x69\x73\x20\x72\x65\x71\x75\x69\x72\x65\x64");
  if (!args[0]->IsString())
    return env->ThrowTypeError("\x76\x38\x20\x66\x6c\x61\x67\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x20\x73\x74\x72\x69\x6e\x67");

  String::Utf8Value flags(args[0]);
  V8::SetFlagsFromString(*flags, flags.length());
}


void InitializeV8Bindings(Local<Object> target,
                          Local<Value> unused,
                          Local<Context> context) {
  Environment* env = Environment::GetCurrent(context);

  env->SetMethod(target,
                 "\x75\x70\x64\x61\x74\x65\x48\x65\x61\x70\x53\x74\x61\x74\x69\x73\x74\x69\x63\x73\x41\x72\x72\x61\x79\x42\x75\x66\x66\x65\x72",
                 UpdateHeapStatisticsArrayBuffer);

  env->set_heap_statistics_buffer(new double[kHeapStatisticsPropertiesCount]);

  const size_t heap_statistics_buffer_byte_length =
      sizeof(*env->heap_statistics_buffer()) * kHeapStatisticsPropertiesCount;

  target->Set(FIXED_ONE_BYTE_STRING(env->isolate(),
                                    "\x68\x65\x61\x70\x53\x74\x61\x74\x69\x73\x74\x69\x63\x73\x41\x72\x72\x61\x79\x42\x75\x66\x66\x65\x72"),
              ArrayBuffer::New(env->isolate(),
                               env->heap_statistics_buffer(),
                               heap_statistics_buffer_byte_length));

#define V(i, _, name)                                                         \
  target->Set(FIXED_ONE_BYTE_STRING(env->isolate(), USTR(#name)),                   \
              Uint32::NewFromUnsigned(env->isolate(), i));

  HEAP_STATISTICS_PROPERTIES(V)
#undef V

  target->Set(FIXED_ONE_BYTE_STRING(env->isolate(),
                                    "\x6b\x48\x65\x61\x70\x53\x70\x61\x63\x65\x53\x74\x61\x74\x69\x73\x74\x69\x63\x73\x50\x72\x6f\x70\x65\x72\x74\x69\x65\x73\x43\x6f\x75\x6e\x74"),
              Uint32::NewFromUnsigned(env->isolate(),
                                      kHeapSpaceStatisticsPropertiesCount));

  number_of_heap_spaces = env->isolate()->NumberOfHeapSpaces();

  // Heap space names are extracted once and exposed to JavaScript to
  // avoid excessive creation of heap space name Strings.
  HeapSpaceStatistics s;
  const Local<Array> heap_spaces = Array::New(env->isolate(),
                                              number_of_heap_spaces);
  for (size_t i = 0; i < number_of_heap_spaces; i++) {
    env->isolate()->GetHeapSpaceStatistics(&s, i);
    Local<String> heap_space_name = String::NewFromUtf8(env->isolate(),
                                                        s.space_name(),
                                                        NewStringType::kNormal)
                                        .ToLocalChecked();
    heap_spaces->Set(i, heap_space_name);
  }
  target->Set(FIXED_ONE_BYTE_STRING(env->isolate(), "\x6b\x48\x65\x61\x70\x53\x70\x61\x63\x65\x73"),
              heap_spaces);

  env->SetMethod(target,
                 "\x75\x70\x64\x61\x74\x65\x48\x65\x61\x70\x53\x70\x61\x63\x65\x53\x74\x61\x74\x69\x73\x74\x69\x63\x73\x41\x72\x72\x61\x79\x42\x75\x66\x66\x65\x72",
                 UpdateHeapSpaceStatisticsBuffer);

  env->set_heap_space_statistics_buffer(
    new double[kHeapSpaceStatisticsPropertiesCount * number_of_heap_spaces]);

  const size_t heap_space_statistics_buffer_byte_length =
      sizeof(*env->heap_space_statistics_buffer()) *
      kHeapSpaceStatisticsPropertiesCount *
      number_of_heap_spaces;

  target->Set(FIXED_ONE_BYTE_STRING(env->isolate(),
                                    "\x68\x65\x61\x70\x53\x70\x61\x63\x65\x53\x74\x61\x74\x69\x73\x74\x69\x63\x73\x41\x72\x72\x61\x79\x42\x75\x66\x66\x65\x72"),
              ArrayBuffer::New(env->isolate(),
                               env->heap_space_statistics_buffer(),
                               heap_space_statistics_buffer_byte_length));

#define V(i, _, name)                                                         \
  target->Set(FIXED_ONE_BYTE_STRING(env->isolate(), USTR(#name)),                   \
              Uint32::NewFromUnsigned(env->isolate(), i));

  HEAP_SPACE_STATISTICS_PROPERTIES(V)
#undef V

  env->SetMethod(target, "\x73\x65\x74\x46\x6c\x61\x67\x73\x46\x72\x6f\x6d\x53\x74\x72\x69\x6e\x67", SetFlagsFromString);
}

}  // namespace node

NODE_MODULE_CONTEXT_AWARE_BUILTIN(v8, node::InitializeV8Bindings)
