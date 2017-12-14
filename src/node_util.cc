#include "node.h"
#include "node_watchdog.h"
#include "v8.h"
#include "env-inl.h"

namespace node {
namespace util {

using v8::Array;
using v8::Context;
using v8::FunctionCallbackInfo;
using v8::Local;
using v8::Object;
using v8::Private;
using v8::Proxy;
using v8::String;
using v8::Value;


#define VALUE_METHOD_MAP(V)                                                   \
  V(isArrayBuffer, IsArrayBuffer)                                             \
  V(isDataView, IsDataView)                                                   \
  V(isDate, IsDate)                                                           \
  V(isMap, IsMap)                                                             \
  V(isMapIterator, IsMapIterator)                                             \
  V(isPromise, IsPromise)                                                     \
  V(isRegExp, IsRegExp)                                                       \
  V(isSet, IsSet)                                                             \
  V(isSetIterator, IsSetIterator)                                             \
  V(isSharedArrayBuffer, IsSharedArrayBuffer)                                 \
  V(isTypedArray, IsTypedArray)


#define V(_, ucname) \
  static void ucname(const FunctionCallbackInfo<Value>& args) {               \
    CHECK_EQ(1, args.Length());                                               \
    args.GetReturnValue().Set(args[0]->ucname());                             \
  }

  VALUE_METHOD_MAP(V)
#undef V

static void GetProxyDetails(const FunctionCallbackInfo<Value>& args) {
  // Return undefined if it's not a proxy.
  if (!args[0]->IsProxy())
    return;

  Local<Proxy> proxy = args[0].As<Proxy>();

  Local<Array> ret = Array::New(args.GetIsolate(), 2);
  ret->Set(0, proxy->GetTarget());
  ret->Set(1, proxy->GetHandler());

  args.GetReturnValue().Set(ret);
}

static void GetHiddenValue(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  if (!args[0]->IsObject())
    return env->ThrowTypeError("\x6f\x62\x6a\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x6e\x20\x6f\x62\x6a\x65\x63\x74");

  if (!args[1]->IsString())
    return env->ThrowTypeError("\x6e\x61\x6d\x65\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x20\x73\x74\x72\x69\x6e\x67");

  Local<Object> obj = args[0].As<Object>();
  Local<String> name = args[1].As<String>();
  auto private_symbol = Private::ForApi(env->isolate(), name);
  auto maybe_value = obj->GetPrivate(env->context(), private_symbol);

  args.GetReturnValue().Set(maybe_value.ToLocalChecked());
}

static void SetHiddenValue(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  if (!args[0]->IsObject())
    return env->ThrowTypeError("\x6f\x62\x6a\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x6e\x20\x6f\x62\x6a\x65\x63\x74");

  if (!args[1]->IsString())
    return env->ThrowTypeError("\x6e\x61\x6d\x65\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x20\x73\x74\x72\x69\x6e\x67");

  Local<Object> obj = args[0].As<Object>();
  Local<String> name = args[1].As<String>();
  auto private_symbol = Private::ForApi(env->isolate(), name);
  auto maybe_value = obj->SetPrivate(env->context(), private_symbol, args[2]);

  args.GetReturnValue().Set(maybe_value.FromJust());
}


void StartSigintWatchdog(const FunctionCallbackInfo<Value>& args) {
  int ret = SigintWatchdogHelper::GetInstance()->Start();
  if (ret != 0) {
    Environment* env = Environment::GetCurrent(args);
    env->ThrowErrnoException(ret, "\x53\x74\x61\x72\x74\x53\x69\x67\x69\x6e\x74\x57\x61\x74\x63\x68\x64\x6f\x67");
  }
}


void StopSigintWatchdog(const FunctionCallbackInfo<Value>& args) {
  bool had_pending_signals = SigintWatchdogHelper::GetInstance()->Stop();
  args.GetReturnValue().Set(had_pending_signals);
}


void WatchdogHasPendingSigint(const FunctionCallbackInfo<Value>& args) {
  bool ret = SigintWatchdogHelper::GetInstance()->HasPendingSignal();
  args.GetReturnValue().Set(ret);
}


void Initialize(Local<Object> target,
                Local<Value> unused,
                Local<Context> context) {
  Environment* env = Environment::GetCurrent(context);

#define V(lcname, ucname) env->SetMethod(target, NODE_STRINGIFY(lcname), ucname);
  VALUE_METHOD_MAP(V)
#undef V

  env->SetMethod(target, "\x67\x65\x74\x48\x69\x64\x64\x65\x6e\x56\x61\x6c\x75\x65", GetHiddenValue);
  env->SetMethod(target, "\x73\x65\x74\x48\x69\x64\x64\x65\x6e\x56\x61\x6c\x75\x65", SetHiddenValue);
  env->SetMethod(target, "\x67\x65\x74\x50\x72\x6f\x78\x79\x44\x65\x74\x61\x69\x6c\x73", GetProxyDetails);

  env->SetMethod(target, "\x73\x74\x61\x72\x74\x53\x69\x67\x69\x6e\x74\x57\x61\x74\x63\x68\x64\x6f\x67", StartSigintWatchdog);
  env->SetMethod(target, "\x73\x74\x6f\x70\x53\x69\x67\x69\x6e\x74\x57\x61\x74\x63\x68\x64\x6f\x67", StopSigintWatchdog);
  env->SetMethod(target, "\x77\x61\x74\x63\x68\x64\x6f\x67\x48\x61\x73\x50\x65\x6e\x64\x69\x6e\x67\x53\x69\x67\x69\x6e\x74", WatchdogHasPendingSigint);
}

}  // namespace util
}  // namespace node

NODE_MODULE_CONTEXT_AWARE_BUILTIN(util, node::util::Initialize)
