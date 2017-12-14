#include "tcp_wrap.h"

#include "connection_wrap.h"
#include "env-inl.h"
#include "handle_wrap.h"
#include "node_buffer.h"
#include "node_wrap.h"
#include "connect_wrap.h"
#include "stream_wrap.h"
#include "util-inl.h"

#include <stdlib.h>
#include <unistd.h>


namespace node {

using v8::Boolean;
using v8::Context;
using v8::EscapableHandleScope;
using v8::External;
using v8::Function;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::HandleScope;
using v8::Integer;
using v8::Local;
using v8::Object;
using v8::String;
using v8::Value;


Local<Object> TCPWrap::Instantiate(Environment* env, AsyncWrap* parent) {
  EscapableHandleScope handle_scope(env->isolate());
  CHECK_EQ(env->tcp_constructor_template().IsEmpty(), false);
  Local<Function> constructor = env->tcp_constructor_template()->GetFunction();
  CHECK_EQ(constructor.IsEmpty(), false);
  Local<Value> ptr = External::New(env->isolate(), parent);
  Local<Object> instance =
      constructor->NewInstance(env->context(), 1, &ptr).ToLocalChecked();
  return handle_scope.Escape(instance);
}


void TCPWrap::Initialize(Local<Object> target,
                         Local<Value> unused,
                         Local<Context> context) {
  Environment* env = Environment::GetCurrent(context);

  Local<FunctionTemplate> t = env->NewFunctionTemplate(New);
  t->SetClassName(FIXED_ONE_BYTE_STRING(env->isolate(), "\x54\x43\x50"));
  t->InstanceTemplate()->SetInternalFieldCount(1);

  // Init properties
  t->InstanceTemplate()->Set(String::NewFromUtf8(env->isolate(), "\x72\x65\x61\x64\x69\x6e\x67"),
                             Boolean::New(env->isolate(), false));
  t->InstanceTemplate()->Set(env->owner_string(), Null(env->isolate()));
  t->InstanceTemplate()->Set(env->onread_string(), Null(env->isolate()));
  t->InstanceTemplate()->Set(env->onconnection_string(), Null(env->isolate()));


  env->SetProtoMethod(t, "\x63\x6c\x6f\x73\x65", HandleWrap::Close);

  env->SetProtoMethod(t, "\x72\x65\x66", HandleWrap::Ref);
  env->SetProtoMethod(t, "\x75\x6e\x72\x65\x66", HandleWrap::Unref);
  env->SetProtoMethod(t, "\x68\x61\x73\x52\x65\x66", HandleWrap::HasRef);

  StreamWrap::AddMethods(env, t, StreamBase::kFlagHasWritev);

  env->SetProtoMethod(t, "\x6f\x70\x65\x6e", Open);
  env->SetProtoMethod(t, "\x62\x69\x6e\x64", Bind);
  env->SetProtoMethod(t, "\x6c\x69\x73\x74\x65\x6e", Listen);
  env->SetProtoMethod(t, "\x63\x6f\x6e\x6e\x65\x63\x74", Connect);
  env->SetProtoMethod(t, "\x62\x69\x6e\x64\x36", Bind6);
  env->SetProtoMethod(t, "\x63\x6f\x6e\x6e\x65\x63\x74\x36", Connect6);
  env->SetProtoMethod(t, "\x67\x65\x74\x73\x6f\x63\x6b\x6e\x61\x6d\x65",
                      GetSockOrPeerName<TCPWrap, uv_tcp_getsockname>);
  env->SetProtoMethod(t, "\x67\x65\x74\x70\x65\x65\x72\x6e\x61\x6d\x65",
                      GetSockOrPeerName<TCPWrap, uv_tcp_getpeername>);
  env->SetProtoMethod(t, "\x73\x65\x74\x4e\x6f\x44\x65\x6c\x61\x79", SetNoDelay);
  env->SetProtoMethod(t, "\x73\x65\x74\x4b\x65\x65\x70\x41\x6c\x69\x76\x65", SetKeepAlive);

#ifdef _WIN32
  env->SetProtoMethod(t, "\x73\x65\x74\x53\x69\x6d\x75\x6c\x74\x61\x6e\x65\x6f\x75\x73\x41\x63\x63\x65\x70\x74\x73", SetSimultaneousAccepts);
#endif

  target->Set(FIXED_ONE_BYTE_STRING(env->isolate(), "\x54\x43\x50"), t->GetFunction());
  env->set_tcp_constructor_template(t);

  // Create FunctionTemplate for TCPConnectWrap.
  auto constructor = [](const FunctionCallbackInfo<Value>& args) {
    CHECK(args.IsConstructCall());
  };
  auto cwt = FunctionTemplate::New(env->isolate(), constructor);
  cwt->InstanceTemplate()->SetInternalFieldCount(1);
  cwt->SetClassName(FIXED_ONE_BYTE_STRING(env->isolate(), "\x54\x43\x50\x43\x6f\x6e\x6e\x65\x63\x74\x57\x72\x61\x70"));
  target->Set(FIXED_ONE_BYTE_STRING(env->isolate(), "\x54\x43\x50\x43\x6f\x6e\x6e\x65\x63\x74\x57\x72\x61\x70"),
              cwt->GetFunction());
}


void TCPWrap::New(const FunctionCallbackInfo<Value>& args) {
  // This constructor should not be exposed to public javascript.
  // Therefore we assert that we are not trying to call this as a
  // normal function.
  CHECK(args.IsConstructCall());
  Environment* env = Environment::GetCurrent(args);
  TCPWrap* wrap;
  if (args.Length() == 0) {
    wrap = new TCPWrap(env, args.This(), nullptr);
  } else if (args[0]->IsExternal()) {
    void* ptr = args[0].As<External>()->Value();
    wrap = new TCPWrap(env, args.This(), static_cast<AsyncWrap*>(ptr));
  } else {
    UNREACHABLE();
  }
  CHECK(wrap);
}


TCPWrap::TCPWrap(Environment* env, Local<Object> object, AsyncWrap* parent)
    : ConnectionWrap(env,
                     object,
                     AsyncWrap::PROVIDER_TCPWRAP,
                     parent) {
  int r = uv_tcp_init(env->event_loop(), &handle_);
  CHECK_EQ(r, 0);  // How do we proxy this error up to javascript?
                   // Suggestion: uv_tcp_init() returns void.
  UpdateWriteQueueSize();
}


TCPWrap::~TCPWrap() {
  CHECK(persistent().IsEmpty());
}


void TCPWrap::SetNoDelay(const FunctionCallbackInfo<Value>& args) {
  TCPWrap* wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap,
                          args.Holder(),
                          args.GetReturnValue().Set(UV_EBADF));
  int enable = static_cast<int>(args[0]->BooleanValue());
  int err = uv_tcp_nodelay(&wrap->handle_, enable);
  args.GetReturnValue().Set(err);
}


void TCPWrap::SetKeepAlive(const FunctionCallbackInfo<Value>& args) {
  TCPWrap* wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap,
                          args.Holder(),
                          args.GetReturnValue().Set(UV_EBADF));
  int enable = args[0]->Int32Value();
  unsigned int delay = args[1]->Uint32Value();
  int err = uv_tcp_keepalive(&wrap->handle_, enable, delay);
  args.GetReturnValue().Set(err);
}


#ifdef _WIN32
void TCPWrap::SetSimultaneousAccepts(const FunctionCallbackInfo<Value>& args) {
  TCPWrap* wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap,
                          args.Holder(),
                          args.GetReturnValue().Set(UV_EBADF));
  bool enable = args[0]->BooleanValue();
  int err = uv_tcp_simultaneous_accepts(&wrap->handle_, enable);
  args.GetReturnValue().Set(err);
}
#endif


void TCPWrap::Open(const FunctionCallbackInfo<Value>& args) {
  TCPWrap* wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap,
                          args.Holder(),
                          args.GetReturnValue().Set(UV_EBADF));
  int fd = static_cast<int>(args[0]->IntegerValue());
  uv_tcp_open(&wrap->handle_, fd);
}


void TCPWrap::Bind(const FunctionCallbackInfo<Value>& args) {
  TCPWrap* wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap,
                          args.Holder(),
                          args.GetReturnValue().Set(UV_EBADF));
  node::NativeEncodingValue ip_address(args.GetIsolate(), args[0]);
  int port = args[1]->Int32Value();
  sockaddr_in addr;
  int err = uv_ip4_addr(*ip_address, port, &addr);
  if (err == 0) {
    err = uv_tcp_bind(&wrap->handle_,
                      reinterpret_cast<const sockaddr*>(&addr),
                      0);
  }
  args.GetReturnValue().Set(err);
}


void TCPWrap::Bind6(const FunctionCallbackInfo<Value>& args) {
  TCPWrap* wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap,
                          args.Holder(),
                          args.GetReturnValue().Set(UV_EBADF));
  node::NativeEncodingValue ip6_address(args.GetIsolate(), args[0]);
  int port = args[1]->Int32Value();
  sockaddr_in6 addr;
  int err = uv_ip6_addr(*ip6_address, port, &addr);
  if (err == 0) {
    err = uv_tcp_bind(&wrap->handle_,
                      reinterpret_cast<const sockaddr*>(&addr),
                      0);
  }
  args.GetReturnValue().Set(err);
}


void TCPWrap::Listen(const FunctionCallbackInfo<Value>& args) {
  TCPWrap* wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap,
                          args.Holder(),
                          args.GetReturnValue().Set(UV_EBADF));
  int backlog = args[0]->Int32Value();
  int err = uv_listen(reinterpret_cast<uv_stream_t*>(&wrap->handle_),
                      backlog,
                      OnConnection);
  args.GetReturnValue().Set(err);
}


void TCPWrap::Connect(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  TCPWrap* wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap,
                          args.Holder(),
                          args.GetReturnValue().Set(UV_EBADF));

  CHECK(args[0]->IsObject());
  CHECK(args[1]->IsString());
  CHECK(args[2]->IsUint32());

  Local<Object> req_wrap_obj = args[0].As<Object>();
  node::NativeEncodingValue ip_address(env->isolate(), args[1]);
  int port = args[2]->Uint32Value();

  sockaddr_in addr;
  int err = uv_ip4_addr(*ip_address, port, &addr);

  if (err == 0) {
    ConnectWrap* req_wrap =
        new ConnectWrap(env, req_wrap_obj, AsyncWrap::PROVIDER_TCPCONNECTWRAP);
    err = uv_tcp_connect(req_wrap->req(),
                         &wrap->handle_,
                         reinterpret_cast<const sockaddr*>(&addr),
                         AfterConnect);
    req_wrap->Dispatched();
    if (err)
      delete req_wrap;
  }

  args.GetReturnValue().Set(err);
}


void TCPWrap::Connect6(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  TCPWrap* wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap,
                          args.Holder(),
                          args.GetReturnValue().Set(UV_EBADF));

  CHECK(args[0]->IsObject());
  CHECK(args[1]->IsString());
  CHECK(args[2]->IsUint32());

  Local<Object> req_wrap_obj = args[0].As<Object>();
  node::NativeEncodingValue ip_address(env->isolate(), args[1]);
  int port = args[2]->Int32Value();

  sockaddr_in6 addr;
  int err = uv_ip6_addr(*ip_address, port, &addr);

  if (err == 0) {
    ConnectWrap* req_wrap =
        new ConnectWrap(env, req_wrap_obj, AsyncWrap::PROVIDER_TCPCONNECTWRAP);
    err = uv_tcp_connect(req_wrap->req(),
                         &wrap->handle_,
                         reinterpret_cast<const sockaddr*>(&addr),
                         AfterConnect);
    req_wrap->Dispatched();
    if (err)
      delete req_wrap;
  }

  args.GetReturnValue().Set(err);
}


// also used by udp_wrap.cc
Local<Object> AddressToJS(Environment* env,
                          const sockaddr* addr,
                          Local<Object> info) {
  EscapableHandleScope scope(env->isolate());
  char ip[INET6_ADDRSTRLEN];
  const sockaddr_in *a4;
  const sockaddr_in6 *a6;
  int port;

  if (info.IsEmpty())
    info = Object::New(env->isolate());

  switch (addr->sa_family) {
  case AF_INET6:
    a6 = reinterpret_cast<const sockaddr_in6*>(addr);
    uv_inet_ntop(AF_INET6, &a6->sin6_addr, ip, sizeof ip);
    port = ntohs(a6->sin6_port);
#ifdef __MVS__    
    __e2a_s(ip);
#endif
    info->Set(env->address_string(), OneByteString(env->isolate(), ip));
    info->Set(env->family_string(), env->ipv6_string());
    info->Set(env->port_string(), Integer::New(env->isolate(), port));
    break;

  case AF_INET:
    a4 = reinterpret_cast<const sockaddr_in*>(addr);
    uv_inet_ntop(AF_INET, &a4->sin_addr, ip, sizeof ip);
    port = ntohs(a4->sin_port);
#ifdef __MVS__ 
    __e2a_s(ip);
#endif
    info->Set(env->address_string(), OneByteString(env->isolate(), ip));
    info->Set(env->family_string(), env->ipv4_string());
    info->Set(env->port_string(), Integer::New(env->isolate(), port));
    break;

  default:
    info->Set(env->address_string(), String::Empty(env->isolate()));
  }

  return scope.Escape(info);
}


}  // namespace node

NODE_MODULE_CONTEXT_AWARE_BUILTIN(tcp_wrap, node::TCPWrap::Initialize)
