#include "pipe_wrap.h"

#include "async-wrap.h"
#include "connection_wrap.h"
#include "env-inl.h"
#include "handle_wrap.h"
#include "node.h"
#include "node_buffer.h"
#include "node_wrap.h"
#include "connect_wrap.h"
#include "stream_wrap.h"
#include "util-inl.h"
#include <unistd.h>

namespace node {

using v8::Context;
using v8::EscapableHandleScope;
using v8::External;
using v8::Function;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::HandleScope;
using v8::Local;
using v8::Object;
using v8::Value;


Local<Object> PipeWrap::Instantiate(Environment* env, AsyncWrap* parent) {
  EscapableHandleScope handle_scope(env->isolate());
  CHECK_EQ(false, env->pipe_constructor_template().IsEmpty());
  Local<Function> constructor = env->pipe_constructor_template()->GetFunction();
  CHECK_EQ(false, constructor.IsEmpty());
  Local<Value> ptr = External::New(env->isolate(), parent);
  Local<Object> instance =
      constructor->NewInstance(env->context(), 1, &ptr).ToLocalChecked();
  return handle_scope.Escape(instance);
}


void PipeWrap::Initialize(Local<Object> target,
                          Local<Value> unused,
                          Local<Context> context) {
  Environment* env = Environment::GetCurrent(context);

  Local<FunctionTemplate> t = env->NewFunctionTemplate(New);
  t->SetClassName(FIXED_ONE_BYTE_STRING(env->isolate(), "\x50\x69\x70\x65"));
  t->InstanceTemplate()->SetInternalFieldCount(1);

  env->SetProtoMethod(t, "\x63\x6c\x6f\x73\x65", HandleWrap::Close);
  env->SetProtoMethod(t, "\x75\x6e\x72\x65\x66", HandleWrap::Unref);
  env->SetProtoMethod(t, "\x72\x65\x66", HandleWrap::Ref);
  env->SetProtoMethod(t, "\x68\x61\x73\x52\x65\x66", HandleWrap::HasRef);

#ifdef _WIN32
  StreamWrap::AddMethods(env, t);
#else
  StreamWrap::AddMethods(env, t, StreamBase::kFlagHasWritev);
#endif

  env->SetProtoMethod(t, "\x62\x69\x6e\x64", Bind);
  env->SetProtoMethod(t, "\x6c\x69\x73\x74\x65\x6e", Listen);
  env->SetProtoMethod(t, "\x63\x6f\x6e\x6e\x65\x63\x74", Connect);
  env->SetProtoMethod(t, "\x6f\x70\x65\x6e", Open);

#ifdef _WIN32
  env->SetProtoMethod(t, "\x73\x65\x74\x50\x65\x6e\x64\x69\x6e\x67\x49\x6e\x73\x74\x61\x6e\x63\x65\x73", SetPendingInstances);
#endif

  target->Set(FIXED_ONE_BYTE_STRING(env->isolate(), "\x50\x69\x70\x65"), t->GetFunction());
  env->set_pipe_constructor_template(t);

  // Create FunctionTemplate for PipeConnectWrap.
  auto constructor = [](const FunctionCallbackInfo<Value>& args) {
    CHECK(args.IsConstructCall());
  };
  auto cwt = FunctionTemplate::New(env->isolate(), constructor);
  cwt->InstanceTemplate()->SetInternalFieldCount(1);
  cwt->SetClassName(FIXED_ONE_BYTE_STRING(env->isolate(), "\x50\x69\x70\x65\x43\x6f\x6e\x6e\x65\x63\x74\x57\x72\x61\x70"));
  target->Set(FIXED_ONE_BYTE_STRING(env->isolate(), "\x50\x69\x70\x65\x43\x6f\x6e\x6e\x65\x63\x74\x57\x72\x61\x70"),
              cwt->GetFunction());
}


void PipeWrap::New(const FunctionCallbackInfo<Value>& args) {
  // This constructor should not be exposed to public javascript.
  // Therefore we assert that we are not trying to call this as a
  // normal function.
  CHECK(args.IsConstructCall());
  Environment* env = Environment::GetCurrent(args);
  if (args[0]->IsExternal()) {
    void* ptr = args[0].As<External>()->Value();
    new PipeWrap(env, args.This(), false, static_cast<AsyncWrap*>(ptr));
  } else {
    new PipeWrap(env, args.This(), args[0]->IsTrue(), nullptr);
  }
}


PipeWrap::PipeWrap(Environment* env,
                   Local<Object> object,
                   bool ipc,
                   AsyncWrap* parent)
    : ConnectionWrap(env,
                     object,
                     AsyncWrap::PROVIDER_PIPEWRAP,
                     parent) {
  int r = uv_pipe_init(env->event_loop(), &handle_, ipc);
  CHECK_EQ(r, 0);  // How do we proxy this error up to javascript?
                   // Suggestion: uv_pipe_init() returns void.
  UpdateWriteQueueSize();
}


void PipeWrap::Bind(const FunctionCallbackInfo<Value>& args) {
  PipeWrap* wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());
  node::Utf8Value name(args.GetIsolate(), args[0]);
#ifdef __MVS__
  __a2e_s(*name);
#endif
  int err = uv_pipe_bind(&wrap->handle_, *name);
  args.GetReturnValue().Set(err);
}


#ifdef _WIN32
void PipeWrap::SetPendingInstances(const FunctionCallbackInfo<Value>& args) {
  PipeWrap* wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());
  int instances = args[0]->Int32Value();
  uv_pipe_pending_instances(&wrap->handle_, instances);
}
#endif


void PipeWrap::Listen(const FunctionCallbackInfo<Value>& args) {
  PipeWrap* wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());
  int backlog = args[0]->Int32Value();
  int err = uv_listen(reinterpret_cast<uv_stream_t*>(&wrap->handle_),
                      backlog,
                      OnConnection);
  args.GetReturnValue().Set(err);
}


void PipeWrap::Open(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  PipeWrap* wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());

  int fd = args[0]->Int32Value();

  int err = uv_pipe_open(&wrap->handle_, fd);

  if (err != 0)
    env->isolate()->ThrowException(UVException(err, "\x75\x76\x5f\x70\x69\x70\x65\x5f\x6f\x70\x65\x6e"));
}


void PipeWrap::Connect(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  PipeWrap* wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());

  CHECK(args[0]->IsObject());
  CHECK(args[1]->IsString());

  Local<Object> req_wrap_obj = args[0].As<Object>();
  node::Utf8Value name(env->isolate(), args[1]);

  ConnectWrap* req_wrap =
      new ConnectWrap(env, req_wrap_obj, AsyncWrap::PROVIDER_PIPECONNECTWRAP);
#ifdef __MVS__
  __a2e_s(*name);
#endif
  uv_pipe_connect(req_wrap->req(),
                  &wrap->handle_,
                  *name,
                  AfterConnect);
  req_wrap->Dispatched();

  args.GetReturnValue().Set(0);  // uv_pipe_connect() doesn't return errors.
}


}  // namespace node

NODE_MODULE_CONTEXT_AWARE_BUILTIN(pipe_wrap, node::PipeWrap::Initialize)
