#include "tty_wrap.h"

#include "env-inl.h"
#include "handle_wrap.h"
#include "node_buffer.h"
#include "node_wrap.h"
#include "req-wrap-inl.h"
#include "stream_wrap.h"
#include "util-inl.h"

namespace node {

using v8::Array;
using v8::Context;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::Integer;
using v8::Local;
using v8::Object;
using v8::Value;


void TTYWrap::Initialize(Local<Object> target,
                         Local<Value> unused,
                         Local<Context> context) {
  Environment* env = Environment::GetCurrent(context);

  Local<FunctionTemplate> t = env->NewFunctionTemplate(New);
  t->SetClassName(FIXED_ONE_BYTE_STRING(env->isolate(), "\x54\x54\x59"));
  t->InstanceTemplate()->SetInternalFieldCount(1);

  env->SetProtoMethod(t, "\x63\x6c\x6f\x73\x65", HandleWrap::Close);
  env->SetProtoMethod(t, "\x75\x6e\x72\x65\x66", HandleWrap::Unref);
  env->SetProtoMethod(t, "\x68\x61\x73\x52\x65\x66", HandleWrap::HasRef);

  StreamWrap::AddMethods(env, t, StreamBase::kFlagNoShutdown);

  env->SetProtoMethod(t, "\x67\x65\x74\x57\x69\x6e\x64\x6f\x77\x53\x69\x7a\x65", TTYWrap::GetWindowSize);
  env->SetProtoMethod(t, "\x73\x65\x74\x52\x61\x77\x4d\x6f\x64\x65", SetRawMode);

  env->SetMethod(target, "\x69\x73\x54\x54\x59", IsTTY);
  env->SetMethod(target, "\x67\x75\x65\x73\x73\x48\x61\x6e\x64\x6c\x65\x54\x79\x70\x65", GuessHandleType);

  target->Set(FIXED_ONE_BYTE_STRING(env->isolate(), "\x54\x54\x59"), t->GetFunction());
  env->set_tty_constructor_template(t);
}


uv_tty_t* TTYWrap::UVHandle() {
  return &handle_;
}


void TTYWrap::GuessHandleType(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  int fd = args[0]->Int32Value();
  CHECK_GE(fd, 0);

  uv_handle_type t = uv_guess_handle(fd);
  const char* type = nullptr;

  switch (t) {
  case UV_TCP: type = "\x54\x43\x50"; break;
  case UV_TTY: type = "\x54\x54\x59"; break;
  case UV_UDP: type = "\x55\x44\x50"; break;
  case UV_FILE: type = "\x46\x49\x4c\x45"; break;
  case UV_NAMED_PIPE: type = "\x50\x49\x50\x45"; break;
  case UV_UNKNOWN_HANDLE: type = "\x55\x4e\x4b\x4e\x4f\x57\x4e"; break;
  default:
    ABORT();
  }

  args.GetReturnValue().Set(OneByteString(env->isolate(), type));
}


void TTYWrap::IsTTY(const FunctionCallbackInfo<Value>& args) {
  int fd = args[0]->Int32Value();
  CHECK_GE(fd, 0);
  bool rc = uv_guess_handle(fd) == UV_TTY;
  args.GetReturnValue().Set(rc);
}


void TTYWrap::GetWindowSize(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  TTYWrap* wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap,
                          args.Holder(),
                          args.GetReturnValue().Set(UV_EBADF));
  CHECK(args[0]->IsArray());

  int width, height;
  int err = uv_tty_get_winsize(&wrap->handle_, &width, &height);

  if (err == 0) {
    Local<v8::Array> a = args[0].As<Array>();
    a->Set(0, Integer::New(env->isolate(), width));
    a->Set(1, Integer::New(env->isolate(), height));
  }

  args.GetReturnValue().Set(err);
}


void TTYWrap::SetRawMode(const FunctionCallbackInfo<Value>& args) {
  TTYWrap* wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap,
                          args.Holder(),
                          args.GetReturnValue().Set(UV_EBADF));
  int err = uv_tty_set_mode(&wrap->handle_, args[0]->IsTrue());
  args.GetReturnValue().Set(err);
}


void TTYWrap::New(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  // This constructor should not be exposed to public javascript.
  // Therefore we assert that we are not trying to call this as a
  // normal function.
  CHECK(args.IsConstructCall());

  int fd = args[0]->Int32Value();
  CHECK_GE(fd, 0);

  TTYWrap* wrap = new TTYWrap(env, args.This(), fd, args[1]->IsTrue());
  wrap->UpdateWriteQueueSize();
}


TTYWrap::TTYWrap(Environment* env, Local<Object> object, int fd, bool readable)
    : StreamWrap(env,
                 object,
                 reinterpret_cast<uv_stream_t*>(&handle_),
                 AsyncWrap::PROVIDER_TTYWRAP) {
  uv_tty_init(env->event_loop(), &handle_, fd, readable);
}

}  // namespace node

NODE_MODULE_CONTEXT_AWARE_BUILTIN(tty_wrap, node::TTYWrap::Initialize)
