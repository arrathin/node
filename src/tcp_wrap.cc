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

#include "tcp_wrap.h"

#include "env.h"
#include "env-inl.h"
#include "handle_wrap.h"
#include "node_buffer.h"
#include "node_wrap.h"
#include "req_wrap.h"
#include "stream_wrap.h"
#include "util.h"
#include "util-inl.h"

#include <unistd.h>
#include <stdlib.h>


namespace node {

using v8::Context;
using v8::EscapableHandleScope;
using v8::External;
using v8::Function;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::Handle;
using v8::HandleScope;
using v8::Integer;
using v8::Local;
using v8::Object;
using v8::PropertyAttribute;
using v8::String;
using v8::Undefined;
using v8::Value;
using v8::Boolean;


class TCPConnectWrap : public ReqWrap<uv_connect_t> {
 public:
  TCPConnectWrap(Environment* env, Local<Object> req_wrap_obj);
};


TCPConnectWrap::TCPConnectWrap(Environment* env, Local<Object> req_wrap_obj)
    : ReqWrap<uv_connect_t>(env, req_wrap_obj, AsyncWrap::PROVIDER_TCPWRAP) {
  Wrap(req_wrap_obj, this);
}


static void NewTCPConnectWrap(const FunctionCallbackInfo<Value>& args) {
  CHECK(args.IsConstructCall());
}


Local<Object> TCPWrap::Instantiate(Environment* env, AsyncWrap* parent) {
  EscapableHandleScope handle_scope(env->isolate());
  assert(env->tcp_constructor_template().IsEmpty() == false);
  Local<Function> constructor = env->tcp_constructor_template()->GetFunction();
  assert(constructor.IsEmpty() == false);
  Local<Value> ptr = External::New(env->isolate(), parent);
  Local<Object> instance = constructor->NewInstance(1, &ptr);
  assert(instance.IsEmpty() == false);
  return handle_scope.Escape(instance);
}


void TCPWrap::Initialize(Handle<Object> target,
                         Handle<Value> unused,
                         Handle<Context> context) {
  Environment* env = Environment::GetCurrent(context);

  Local<FunctionTemplate> t = FunctionTemplate::New(env->isolate(), New);
  t->SetClassName(FIXED_ONE_BYTE_STRING(env->isolate(), "\x54\x43\x50"));
  t->InstanceTemplate()->SetInternalFieldCount(1);

  enum PropertyAttribute attributes =
      static_cast<PropertyAttribute>(v8::ReadOnly | v8::DontDelete);
  t->InstanceTemplate()->SetAccessor(env->fd_string(),
                                     StreamWrap::GetFD,
                                     NULL,
                                     Handle<Value>(),
                                     v8::DEFAULT,
                                     attributes);

  // Init properties
  t->InstanceTemplate()->Set(String::NewFromUtf8(env->isolate(), "\x72\x65\x61\x64\x69\x6e\x67"),
                             Boolean::New(env->isolate(), false));
  t->InstanceTemplate()->Set(String::NewFromUtf8(env->isolate(), "\x6f\x77\x6e\x65\x72"),
                             Null(env->isolate()));
  t->InstanceTemplate()->Set(String::NewFromUtf8(env->isolate(), "\x6f\x6e\x72\x65\x61\x64"),
                             Null(env->isolate()));
  t->InstanceTemplate()->Set(String::NewFromUtf8(env->isolate(),
                                                 "\x6f\x6e\x63\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e"),
                             Null(env->isolate()));


  NODE_SET_PROTOTYPE_METHOD(t, "\x63\x6c\x6f\x73\x65", HandleWrap::Close);

  NODE_SET_PROTOTYPE_METHOD(t, "\x72\x65\x66", HandleWrap::Ref);
  NODE_SET_PROTOTYPE_METHOD(t, "\x75\x6e\x72\x65\x66", HandleWrap::Unref);

  NODE_SET_PROTOTYPE_METHOD(t, "\x72\x65\x61\x64\x53\x74\x61\x72\x74", StreamWrap::ReadStart);
  NODE_SET_PROTOTYPE_METHOD(t, "\x72\x65\x61\x64\x53\x74\x6f\x70", StreamWrap::ReadStop);
  NODE_SET_PROTOTYPE_METHOD(t, "\x73\x68\x75\x74\x64\x6f\x77\x6e", StreamWrap::Shutdown);

  NODE_SET_PROTOTYPE_METHOD(t, "\x77\x72\x69\x74\x65\x42\x75\x66\x66\x65\x72", StreamWrap::WriteBuffer);
  NODE_SET_PROTOTYPE_METHOD(t,
                            "\x77\x72\x69\x74\x65\x41\x73\x63\x69\x69\x53\x74\x72\x69\x6e\x67",
                            StreamWrap::WriteAsciiString);
  NODE_SET_PROTOTYPE_METHOD(t, "\x77\x72\x69\x74\x65\x55\x74\x66\x38\x53\x74\x72\x69\x6e\x67", StreamWrap::WriteUtf8String);
  NODE_SET_PROTOTYPE_METHOD(t, "\x77\x72\x69\x74\x65\x55\x63\x73\x32\x53\x74\x72\x69\x6e\x67", StreamWrap::WriteUcs2String);
  NODE_SET_PROTOTYPE_METHOD(t,
                            "\x77\x72\x69\x74\x65\x42\x69\x6e\x61\x72\x79\x53\x74\x72\x69\x6e\x67",
                            StreamWrap::WriteBinaryString);
  NODE_SET_PROTOTYPE_METHOD(t, "\x77\x72\x69\x74\x65\x76", StreamWrap::Writev);

  NODE_SET_PROTOTYPE_METHOD(t, "\x6f\x70\x65\x6e", Open);
  NODE_SET_PROTOTYPE_METHOD(t, "\x62\x69\x6e\x64", Bind);
  NODE_SET_PROTOTYPE_METHOD(t, "\x6c\x69\x73\x74\x65\x6e", Listen);
  NODE_SET_PROTOTYPE_METHOD(t, "\x63\x6f\x6e\x6e\x65\x63\x74", Connect);
  NODE_SET_PROTOTYPE_METHOD(t, "\x62\x69\x6e\x64\x36", Bind6);
  NODE_SET_PROTOTYPE_METHOD(t, "\x63\x6f\x6e\x6e\x65\x63\x74\x36", Connect6);
  NODE_SET_PROTOTYPE_METHOD(t, "\x67\x65\x74\x73\x6f\x63\x6b\x6e\x61\x6d\x65", GetSockName);
  NODE_SET_PROTOTYPE_METHOD(t, "\x67\x65\x74\x70\x65\x65\x72\x6e\x61\x6d\x65", GetPeerName);
  NODE_SET_PROTOTYPE_METHOD(t, "\x73\x65\x74\x4e\x6f\x44\x65\x6c\x61\x79", SetNoDelay);
  NODE_SET_PROTOTYPE_METHOD(t, "\x73\x65\x74\x4b\x65\x65\x70\x41\x6c\x69\x76\x65", SetKeepAlive);

#ifdef _WIN32
  NODE_SET_PROTOTYPE_METHOD(t,
                            "\x73\x65\x74\x53\x69\x6d\x75\x6c\x74\x61\x6e\x65\x6f\x75\x73\x41\x63\x63\x65\x70\x74\x73",
                            SetSimultaneousAccepts);
#endif

  target->Set(FIXED_ONE_BYTE_STRING(env->isolate(), "\x54\x43\x50"), t->GetFunction());
  env->set_tcp_constructor_template(t);

  // Create FunctionTemplate for TCPConnectWrap.
  Local<FunctionTemplate> cwt =
      FunctionTemplate::New(env->isolate(), NewTCPConnectWrap);
  cwt->InstanceTemplate()->SetInternalFieldCount(1);
  cwt->SetClassName(FIXED_ONE_BYTE_STRING(env->isolate(), "\x54\x43\x50\x43\x6f\x6e\x6e\x65\x63\x74\x57\x72\x61\x70"));
  target->Set(FIXED_ONE_BYTE_STRING(env->isolate(), "\x54\x43\x50\x43\x6f\x6e\x6e\x65\x63\x74\x57\x72\x61\x70"),
              cwt->GetFunction());
}


uv_tcp_t* TCPWrap::UVHandle() {
  return &handle_;
}


void TCPWrap::New(const FunctionCallbackInfo<Value>& args) {
  // This constructor should not be exposed to public javascript.
  // Therefore we assert that we are not trying to call this as a
  // normal function.
  assert(args.IsConstructCall());
  Environment* env = Environment::GetCurrent(args.GetIsolate());
  TCPWrap* wrap;
  if (args.Length() == 0) {
    wrap = new TCPWrap(env, args.This(), NULL);
  } else if (args[0]->IsExternal()) {
    void* ptr = args[0].As<External>()->Value();
    wrap = new TCPWrap(env, args.This(), static_cast<AsyncWrap*>(ptr));
  } else {
    UNREACHABLE();
  }
  assert(wrap);
}


TCPWrap::TCPWrap(Environment* env, Handle<Object> object, AsyncWrap* parent)
    : StreamWrap(env,
                 object,
                 reinterpret_cast<uv_stream_t*>(&handle_),
                 AsyncWrap::PROVIDER_TCPWRAP,
                 parent) {
  int r = uv_tcp_init(env->event_loop(), &handle_);
  assert(r == 0);  // How do we proxy this error up to javascript?
                   // Suggestion: uv_tcp_init() returns void.
  UpdateWriteQueueSize();
}


TCPWrap::~TCPWrap() {
  assert(persistent().IsEmpty());
}


void TCPWrap::GetSockName(const FunctionCallbackInfo<Value>& args) {
  HandleScope handle_scope(args.GetIsolate());
  Environment* env = Environment::GetCurrent(args.GetIsolate());
  struct sockaddr_storage address;

  TCPWrap* wrap = Unwrap<TCPWrap>(args.Holder());

  assert(args[0]->IsObject());
  Local<Object> out = args[0].As<Object>();

  int addrlen = sizeof(address);
  int err = uv_tcp_getsockname(&wrap->handle_,
                               reinterpret_cast<sockaddr*>(&address),
                               &addrlen);
  if (err == 0) {
    const sockaddr* addr = reinterpret_cast<const sockaddr*>(&address);
    AddressToJS(env, addr, out);
  }

  args.GetReturnValue().Set(err);
}


void TCPWrap::GetPeerName(const FunctionCallbackInfo<Value>& args) {
  HandleScope handle_scope(args.GetIsolate());
  Environment* env = Environment::GetCurrent(args.GetIsolate());
  struct sockaddr_storage address;

  TCPWrap* wrap = Unwrap<TCPWrap>(args.Holder());

  assert(args[0]->IsObject());
  Local<Object> out = args[0].As<Object>();

  int addrlen = sizeof(address);
  int err = uv_tcp_getpeername(&wrap->handle_,
                               reinterpret_cast<sockaddr*>(&address),
                               &addrlen);
  if (err == 0) {
    const sockaddr* addr = reinterpret_cast<const sockaddr*>(&address);
    AddressToJS(env, addr, out);
  }

  args.GetReturnValue().Set(err);
}


void TCPWrap::SetNoDelay(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args.GetIsolate());
  HandleScope scope(env->isolate());

  TCPWrap* wrap = Unwrap<TCPWrap>(args.Holder());

  int enable = static_cast<int>(args[0]->BooleanValue());
  int err = uv_tcp_nodelay(&wrap->handle_, enable);
  args.GetReturnValue().Set(err);
}


void TCPWrap::SetKeepAlive(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args.GetIsolate());
  HandleScope scope(env->isolate());

  TCPWrap* wrap = Unwrap<TCPWrap>(args.Holder());

  int enable = args[0]->Int32Value();
  unsigned int delay = args[1]->Uint32Value();

  int err = uv_tcp_keepalive(&wrap->handle_, enable, delay);
  args.GetReturnValue().Set(err);
}


#ifdef _WIN32
void TCPWrap::SetSimultaneousAccepts(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args.GetIsolate());
  HandleScope scope(env->isolate());

  TCPWrap* wrap = Unwrap<TCPWrap>(args.Holder());

  bool enable = args[0]->BooleanValue();
  int err = uv_tcp_simultaneous_accepts(&wrap->handle_, enable);
  args.GetReturnValue().Set(err);
}
#endif


void TCPWrap::Open(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args.GetIsolate());
  HandleScope scope(env->isolate());
  TCPWrap* wrap = Unwrap<TCPWrap>(args.Holder());
  int fd = static_cast<int>(args[0]->IntegerValue());
  uv_tcp_open(&wrap->handle_, fd);
}


void TCPWrap::Bind(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args.GetIsolate());
  HandleScope scope(env->isolate());

  TCPWrap* wrap = Unwrap<TCPWrap>(args.Holder());

  node::Utf8Value ip_address(args[0]);
  node::NativeEncodingValue native_ip_address(ip_address);
  int port = args[1]->Int32Value();

  sockaddr_in addr;
  int err = uv_ip4_addr(*native_ip_address, port, &addr);
  if (err == 0) {
    err = uv_tcp_bind(&wrap->handle_,
                      reinterpret_cast<const sockaddr*>(&addr),
                      0);
  }

  args.GetReturnValue().Set(err);
}


void TCPWrap::Bind6(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args.GetIsolate());
  HandleScope scope(env->isolate());

  TCPWrap* wrap = Unwrap<TCPWrap>(args.Holder());

  node::Utf8Value ip6_address(args[0]);
  node::NativeEncodingValue native_ip6_address(ip6_address);
  int port = args[1]->Int32Value();

  sockaddr_in6 addr;
  int err = uv_ip6_addr(*native_ip6_address, port, &addr);
  if (err == 0) {
    err = uv_tcp_bind(&wrap->handle_,
                      reinterpret_cast<const sockaddr*>(&addr),
                      0);
  }

  args.GetReturnValue().Set(err);
}


void TCPWrap::Listen(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args.GetIsolate());
  HandleScope scope(env->isolate());

  TCPWrap* wrap = Unwrap<TCPWrap>(args.Holder());

  int backlog = args[0]->Int32Value();
  int err = uv_listen(reinterpret_cast<uv_stream_t*>(&wrap->handle_),
                      backlog,
                      OnConnection);
  args.GetReturnValue().Set(err);
}


void TCPWrap::OnConnection(uv_stream_t* handle, int status) {
  TCPWrap* tcp_wrap = static_cast<TCPWrap*>(handle->data);
  assert(&tcp_wrap->handle_ == reinterpret_cast<uv_tcp_t*>(handle));
  Environment* env = tcp_wrap->env();

  HandleScope handle_scope(env->isolate());
  Context::Scope context_scope(env->context());

  // We should not be getting this callback if someone as already called
  // uv_close() on the handle.
  assert(tcp_wrap->persistent().IsEmpty() == false);

  Local<Value> argv[2] = {
    Integer::New(env->isolate(), status),
    Undefined(env->isolate())
  };

  if (status == 0) {
    // Instantiate the client javascript object and handle.
    Local<Object> client_obj =
        Instantiate(env, static_cast<AsyncWrap*>(tcp_wrap));

    // Unwrap the client javascript object.
    TCPWrap* wrap = Unwrap<TCPWrap>(client_obj);
    uv_stream_t* client_handle = reinterpret_cast<uv_stream_t*>(&wrap->handle_);
    if (uv_accept(handle, client_handle))
      return;

    // Successful accept. Call the onconnection callback in JavaScript land.
    argv[1] = client_obj;
  }

  tcp_wrap->MakeCallback(env->onconnection_string(), ARRAY_SIZE(argv), argv);
}


void TCPWrap::AfterConnect(uv_connect_t* req, int status) {
  TCPConnectWrap* req_wrap = static_cast<TCPConnectWrap*>(req->data);
  TCPWrap* wrap = static_cast<TCPWrap*>(req->handle->data);
  assert(req_wrap->env() == wrap->env());
  Environment* env = wrap->env();

  HandleScope handle_scope(env->isolate());
  Context::Scope context_scope(env->context());

  // The wrap and request objects should still be there.
  assert(req_wrap->persistent().IsEmpty() == false);
  assert(wrap->persistent().IsEmpty() == false);

  Local<Object> req_wrap_obj = req_wrap->object();
  Local<Value> argv[5] = {
    Integer::New(env->isolate(), status),
    wrap->object(),
    req_wrap_obj,
    v8::True(env->isolate()),
    v8::True(env->isolate())
  };

  req_wrap->MakeCallback(env->oncomplete_string(), ARRAY_SIZE(argv), argv);

  delete req_wrap;
}


void TCPWrap::Connect(const FunctionCallbackInfo<Value>& args) {
  HandleScope handle_scope(args.GetIsolate());
  Environment* env = Environment::GetCurrent(args.GetIsolate());

  TCPWrap* wrap = Unwrap<TCPWrap>(args.Holder());

  assert(args[0]->IsObject());
  assert(args[1]->IsString());
  assert(args[2]->IsUint32());

  Local<Object> req_wrap_obj = args[0].As<Object>();
  node::Utf8Value ip_address(args[1]);
  node::NativeEncodingValue native_ip_address(ip_address);
  int port = args[2]->Uint32Value();

  sockaddr_in addr;
  int err = uv_ip4_addr(*native_ip_address, port, &addr);

  if (err == 0) {
    TCPConnectWrap* req_wrap = new TCPConnectWrap(env, req_wrap_obj);
    err = uv_tcp_connect(&req_wrap->req_,
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
  HandleScope handle_scope(args.GetIsolate());
  Environment* env = Environment::GetCurrent(args.GetIsolate());

  TCPWrap* wrap = Unwrap<TCPWrap>(args.Holder());

  assert(args[0]->IsObject());
  assert(args[1]->IsString());
  assert(args[2]->IsUint32());

  Local<Object> req_wrap_obj = args[0].As<Object>();
  node::Utf8Value ip_address(args[1]);
  node::NativeEncodingValue native_ip_address(ip_address);
  int port = args[2]->Int32Value();

  sockaddr_in6 addr;
  int err = uv_ip6_addr(*native_ip_address, port, &addr);

  if (err == 0) {
    TCPConnectWrap* req_wrap = new TCPConnectWrap(env, req_wrap_obj);
    err = uv_tcp_connect(&req_wrap->req_,
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
    __e2a_s(ip);
    info->Set(env->address_string(), OneByteString(env->isolate(), ip));
    info->Set(env->family_string(), env->ipv6_string());
    info->Set(env->port_string(), Integer::New(env->isolate(), port));
    break;

  case AF_INET:
    a4 = reinterpret_cast<const sockaddr_in*>(addr);
    uv_inet_ntop(AF_INET, &a4->sin_addr, ip, sizeof ip);
    port = ntohs(a4->sin_port);
    __e2a_s(ip);
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
