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

#include "node.h"
#include "node_internals.h"
#include "node_watchdog.h"
#include "base-object.h"
#include "base-object-inl.h"
#include "env.h"
#include "env-inl.h"
#include "util.h"
#include "util-inl.h"
#include "v8-debug.h"

namespace node {

using v8::AccessType;
using v8::Array;
using v8::Boolean;
using v8::Context;
using v8::Debug;
using v8::EscapableHandleScope;
using v8::External;
using v8::Function;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::Handle;
using v8::HandleScope;
using v8::Integer;
using v8::Isolate;
using v8::Local;
using v8::None;
using v8::Object;
using v8::ObjectTemplate;
using v8::Persistent;
using v8::PropertyCallbackInfo;
using v8::Script;
using v8::ScriptCompiler;
using v8::ScriptOrigin;
using v8::String;
using v8::TryCatch;
using v8::UnboundScript;
using v8::V8;
using v8::Value;
using v8::WeakCallbackData;


class ContextifyContext {
 protected:
  enum Kind {
    kSandbox,
    kContext,
    kProxyGlobal
  };

  Environment* const env_;
  Persistent<Object> sandbox_;
  Persistent<Context> context_;
  Persistent<Object> proxy_global_;
  int references_;

 public:
  explicit ContextifyContext(Environment* env, Local<Object> sandbox)
      : env_(env),
        sandbox_(env->isolate(), sandbox),
        context_(env->isolate(), CreateV8Context(env)),
        // Wait for sandbox_, proxy_global_, and context_ to die
        references_(0) {
    sandbox_.SetWeak(this, WeakCallback<Object, kSandbox>);
    sandbox_.MarkIndependent();
    references_++;

    // Allocation failure or maximum call stack size reached
    if (context_.IsEmpty())
      return;
    context_.SetWeak(this, WeakCallback<Context, kContext>);
    context_.MarkIndependent();
    references_++;

    proxy_global_.Reset(env->isolate(), context()->Global());
    proxy_global_.SetWeak(this, WeakCallback<Object, kProxyGlobal>);
    proxy_global_.MarkIndependent();
    references_++;
  }


  ~ContextifyContext() {
    context_.Reset();
    proxy_global_.Reset();
    sandbox_.Reset();
  }


  inline Environment* env() const {
    return env_;
  }


  inline Local<Context> context() const {
    return PersistentToLocal(env()->isolate(), context_);
  }


  // XXX(isaacs): This function only exists because of a shortcoming of
  // the V8 SetNamedPropertyHandler function.
  //
  // It does not provide a way to intercept Object.defineProperty(..)
  // calls.  As a result, these properties are not copied onto the
  // contextified sandbox when a new global property is added via either
  // a function declaration or a Object.defineProperty(global, ...) call.
  //
  // Note that any function declarations or Object.defineProperty()
  // globals that are created asynchronously (in a setTimeout, callback,
  // etc.) will happen AFTER the call to copy properties, and thus not be
  // caught.
  //
  // The way to properly fix this is to add some sort of a
  // Object::SetNamedDefinePropertyHandler() function that takes a callback,
  // which receives the property name and property descriptor as arguments.
  //
  // Luckily, such situations are rare, and asynchronously-added globals
  // weren't supported by Node's VM module until 0.12 anyway.  But, this
  // should be fixed properly in V8, and this copy function should be
  // removed once there is a better way.
  void CopyProperties() {
    HandleScope scope(env()->isolate());

    Local<Context> context = PersistentToLocal(env()->isolate(), context_);
    Local<Object> global = context->Global()->GetPrototype()->ToObject();
    Local<Object> sandbox = PersistentToLocal(env()->isolate(), sandbox_);

    Local<Function> clone_property_method;

    Local<Array> names = global->GetOwnPropertyNames();
    int length = names->Length();
    for (int i = 0; i < length; i++) {
      Local<String> key = names->Get(i)->ToString();
      bool has = sandbox->HasOwnProperty(key);
      if (!has) {
        // Could also do this like so:
        //
        // PropertyAttribute att = global->GetPropertyAttributes(key_v);
        // Local<Value> val = global->Get(key_v);
        // sandbox->ForceSet(key_v, val, att);
        //
        // However, this doesn't handle ES6-style properties configured with
        // Object.defineProperty, and that's exactly what we're up against at
        // this point.  ForceSet(key,val,att) only supports value properties
        // with the ES3-style attribute flags (DontDelete/DontEnum/ReadOnly),
        // which doesn't faithfully capture the full range of configurations
        // that can be done using Object.defineProperty.
        if (clone_property_method.IsEmpty()) {
          Local<String> code = FIXED_ONE_BYTE_STRING(env()->isolate(),
              "\x28\x66\x75\x6e\x63\x74\x69\x6f\x6e\x20\x63\x6c\x6f\x6e\x65\x50\x72\x6f\x70\x65\x72\x74\x79\x28\x73\x6f\x75\x72\x63\x65\x2c\x20\x6b\x65\x79\x2c\x20\x74\x61\x72\x67\x65\x74\x29\x20\x7b\xa"
              "\x20\x20\x69\x66\x20\x28\x6b\x65\x79\x20\x3d\x3d\x3d\x20\x27\x50\x72\x6f\x78\x79\x27\x29\x20\x72\x65\x74\x75\x72\x6e\x3b\xa"
              "\x20\x20\x74\x72\x79\x20\x7b\xa"
              "\x20\x20\x20\x20\x76\x61\x72\x20\x64\x65\x73\x63\x20\x3d\x20\x4f\x62\x6a\x65\x63\x74\x2e\x67\x65\x74\x4f\x77\x6e\x50\x72\x6f\x70\x65\x72\x74\x79\x44\x65\x73\x63\x72\x69\x70\x74\x6f\x72\x28\x73\x6f\x75\x72\x63\x65\x2c\x20\x6b\x65\x79\x29\x3b\xa"
              "\x20\x20\x20\x20\x69\x66\x20\x28\x64\x65\x73\x63\x2e\x76\x61\x6c\x75\x65\x20\x3d\x3d\x3d\x20\x73\x6f\x75\x72\x63\x65\x29\x20\x64\x65\x73\x63\x2e\x76\x61\x6c\x75\x65\x20\x3d\x20\x74\x61\x72\x67\x65\x74\x3b\xa"
              "\x20\x20\x20\x20\x4f\x62\x6a\x65\x63\x74\x2e\x64\x65\x66\x69\x6e\x65\x50\x72\x6f\x70\x65\x72\x74\x79\x28\x74\x61\x72\x67\x65\x74\x2c\x20\x6b\x65\x79\x2c\x20\x64\x65\x73\x63\x29\x3b\xa"
              "\x20\x20\x7d\x20\x63\x61\x74\x63\x68\x20\x28\x65\x29\x20\x7b\xa"
              "\x20\x20\x20\x2f\x2f\x20\x43\x61\x74\x63\x68\x20\x73\x65\x61\x6c\x65\x64\x20\x70\x72\x6f\x70\x65\x72\x74\x69\x65\x73\x20\x65\x72\x72\x6f\x72\x73\xa"
              "\x20\x20\x7d\xa"
              "\x7d\x29");

          Local<String> fname = FIXED_ONE_BYTE_STRING(env()->isolate(),
              "\x62\x69\x6e\x64\x69\x6e\x67\x3a\x73\x63\x72\x69\x70\x74");
          Local<Script> script = Script::Compile(code, fname);
          clone_property_method = Local<Function>::Cast(script->Run());
          assert(clone_property_method->IsFunction());
        }
        Local<Value> args[] = { global, key, sandbox };
        clone_property_method->Call(global, ARRAY_SIZE(args), args);
      }
    }
  }


  // This is an object that just keeps an internal pointer to this
  // ContextifyContext.  It's passed to the NamedPropertyHandler.  If we
  // pass the main JavaScript context object we're embedded in, then the
  // NamedPropertyHandler will store a reference to it forever and keep it
  // from getting gc'd.
  Local<Value> CreateDataWrapper(Environment* env) {
    EscapableHandleScope scope(env->isolate());
    Local<Object> wrapper =
        env->script_data_constructor_function()->NewInstance();
    if (wrapper.IsEmpty())
      return scope.Escape(Local<Value>::New(env->isolate(), Handle<Value>()));

    Wrap(wrapper, this);
    return scope.Escape(wrapper);
  }


  Local<Context> CreateV8Context(Environment* env) {
    EscapableHandleScope scope(env->isolate());
    Local<FunctionTemplate> function_template =
        FunctionTemplate::New(env->isolate());
    function_template->SetHiddenPrototype(true);

    Local<Object> sandbox = PersistentToLocal(env->isolate(), sandbox_);
    function_template->SetClassName(sandbox->GetConstructorName());

    Local<ObjectTemplate> object_template =
        function_template->InstanceTemplate();
    object_template->SetNamedPropertyHandler(GlobalPropertyGetterCallback,
                                             GlobalPropertySetterCallback,
                                             GlobalPropertyQueryCallback,
                                             GlobalPropertyDeleterCallback,
                                             GlobalPropertyEnumeratorCallback,
                                             CreateDataWrapper(env));
    object_template->SetAccessCheckCallbacks(GlobalPropertyNamedAccessCheck,
                                             GlobalPropertyIndexedAccessCheck);

    Local<Context> ctx = Context::New(env->isolate(), NULL, object_template);
    if (!ctx.IsEmpty())
      ctx->SetSecurityToken(env->context()->GetSecurityToken());

    env->AssignToContext(ctx);

    return scope.Escape(ctx);
  }


  static void Init(Environment* env, Local<Object> target) {
    Local<FunctionTemplate> function_template =
        FunctionTemplate::New(env->isolate());
    function_template->InstanceTemplate()->SetInternalFieldCount(1);
    env->set_script_data_constructor_function(function_template->GetFunction());

    NODE_SET_METHOD(target, "\x72\x75\x6e\x49\x6e\x44\x65\x62\x75\x67\x43\x6f\x6e\x74\x65\x78\x74", RunInDebugContext);
    NODE_SET_METHOD(target, "\x6d\x61\x6b\x65\x43\x6f\x6e\x74\x65\x78\x74", MakeContext);
    NODE_SET_METHOD(target, "\x69\x73\x43\x6f\x6e\x74\x65\x78\x74", IsContext);
  }


  static void RunInDebugContext(const FunctionCallbackInfo<Value>& args) {
    HandleScope scope(args.GetIsolate());
    Local<String> script_source(args[0]->ToString());
    if (script_source.IsEmpty())
      return;  // Exception pending.
    Context::Scope context_scope(Debug::GetDebugContext());
    Local<Script> script = Script::Compile(script_source);
    if (script.IsEmpty())
      return;  // Exception pending.
    args.GetReturnValue().Set(script->Run());
  }


  static void MakeContext(const FunctionCallbackInfo<Value>& args) {
    Environment* env = Environment::GetCurrent(args.GetIsolate());
    HandleScope scope(env->isolate());

    if (!args[0]->IsObject()) {
      return env->ThrowTypeError("\x73\x61\x6e\x64\x62\x6f\x78\x20\x61\x72\x67\x75\x6d\x65\x6e\x74\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x6e\x20\x6f\x62\x6a\x65\x63\x74\x2e");
    }
    Local<Object> sandbox = args[0].As<Object>();

    Local<String> hidden_name =
        FIXED_ONE_BYTE_STRING(env->isolate(), "\x5f\x63\x6f\x6e\x74\x65\x78\x74\x69\x66\x79\x48\x69\x64\x64\x65\x6e");

    // Don't allow contextifying a sandbox multiple times.
    assert(sandbox->GetHiddenValue(hidden_name).IsEmpty());

    TryCatch try_catch;
    ContextifyContext* context = new ContextifyContext(env, sandbox);

    if (try_catch.HasCaught()) {
      try_catch.ReThrow();
      return;
    }

    if (context->context().IsEmpty())
      return;

    Local<External> hidden_context = External::New(env->isolate(), context);
    sandbox->SetHiddenValue(hidden_name, hidden_context);
  }


  static void IsContext(const FunctionCallbackInfo<Value>& args) {
    Environment* env = Environment::GetCurrent(args.GetIsolate());
    HandleScope scope(env->isolate());

    if (!args[0]->IsObject()) {
      env->ThrowTypeError("\x73\x61\x6e\x64\x62\x6f\x78\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x6e\x20\x6f\x62\x6a\x65\x63\x74");
      return;
    }
    Local<Object> sandbox = args[0].As<Object>();

    Local<String> hidden_name =
        FIXED_ONE_BYTE_STRING(env->isolate(), "\x5f\x63\x6f\x6e\x74\x65\x78\x74\x69\x66\x79\x48\x69\x64\x64\x65\x6e");

    args.GetReturnValue().Set(!sandbox->GetHiddenValue(hidden_name).IsEmpty());
  }


  template <class T, Kind kind>
  static void WeakCallback(const WeakCallbackData<T, ContextifyContext>& data) {
    ContextifyContext* context = data.GetParameter();
    if (kind == kSandbox)
      context->sandbox_.ClearWeak();
    else if (kind == kContext)
      context->context_.ClearWeak();
    else
      context->proxy_global_.ClearWeak();

    if (--context->references_ == 0)
      delete context;
  }


  static ContextifyContext* ContextFromContextifiedSandbox(
      Isolate* isolate,
      const Local<Object>& sandbox) {
    Local<String> hidden_name =
        FIXED_ONE_BYTE_STRING(isolate, "\x5f\x63\x6f\x6e\x74\x65\x78\x74\x69\x66\x79\x48\x69\x64\x64\x65\x6e");
    Local<Value> context_external_v = sandbox->GetHiddenValue(hidden_name);
    if (context_external_v.IsEmpty() || !context_external_v->IsExternal()) {
      return NULL;
    }
    Local<External> context_external = context_external_v.As<External>();

    return static_cast<ContextifyContext*>(context_external->Value());
  }


  static bool GlobalPropertyNamedAccessCheck(Local<Object> host,
                                             Local<Value> key,
                                             AccessType type,
                                             Local<Value> data) {
    return true;
  }


  static bool GlobalPropertyIndexedAccessCheck(Local<Object> host,
                                               uint32_t key,
                                               AccessType type,
                                               Local<Value> data) {
    return true;
  }


  static void GlobalPropertyGetterCallback(
      Local<String> property,
      const PropertyCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    HandleScope scope(isolate);

    ContextifyContext* ctx =
        Unwrap<ContextifyContext>(args.Data().As<Object>());

    Local<Object> sandbox = PersistentToLocal(isolate, ctx->sandbox_);
    Local<Value> rv = sandbox->GetRealNamedProperty(property);
    if (rv.IsEmpty()) {
      Local<Object> proxy_global = PersistentToLocal(isolate,
                                                     ctx->proxy_global_);
      rv = proxy_global->GetRealNamedProperty(property);
    }
    if (!rv.IsEmpty() && rv == ctx->sandbox_) {
      rv = PersistentToLocal(isolate, ctx->proxy_global_);
    }

    args.GetReturnValue().Set(rv);
  }


  static void GlobalPropertySetterCallback(
      Local<String> property,
      Local<Value> value,
      const PropertyCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    HandleScope scope(isolate);

    ContextifyContext* ctx =
        Unwrap<ContextifyContext>(args.Data().As<Object>());

    PersistentToLocal(isolate, ctx->sandbox_)->Set(property, value);
  }


  static void GlobalPropertyQueryCallback(
      Local<String> property,
      const PropertyCallbackInfo<Integer>& args) {
    Isolate* isolate = args.GetIsolate();
    HandleScope scope(isolate);

    ContextifyContext* ctx =
        Unwrap<ContextifyContext>(args.Data().As<Object>());

    Local<Object> sandbox = PersistentToLocal(isolate, ctx->sandbox_);
    Local<Object> proxy_global = PersistentToLocal(isolate,
                                                   ctx->proxy_global_);

    bool in_sandbox = sandbox->GetRealNamedProperty(property).IsEmpty();
    bool in_proxy_global =
        proxy_global->GetRealNamedProperty(property).IsEmpty();
    if (!in_sandbox || !in_proxy_global) {
      args.GetReturnValue().Set(None);
    }
  }


  static void GlobalPropertyDeleterCallback(
      Local<String> property,
      const PropertyCallbackInfo<Boolean>& args) {
    Isolate* isolate = args.GetIsolate();
    HandleScope scope(isolate);

    ContextifyContext* ctx =
        Unwrap<ContextifyContext>(args.Data().As<Object>());

    bool success = PersistentToLocal(isolate,
                                     ctx->sandbox_)->Delete(property);
    args.GetReturnValue().Set(success);
  }


  static void GlobalPropertyEnumeratorCallback(
      const PropertyCallbackInfo<Array>& args) {
    HandleScope scope(args.GetIsolate());

    ContextifyContext* ctx =
        Unwrap<ContextifyContext>(args.Data().As<Object>());

    Local<Object> sandbox = PersistentToLocal(args.GetIsolate(), ctx->sandbox_);
    args.GetReturnValue().Set(sandbox->GetPropertyNames());
  }
};

class ContextifyScript : public BaseObject {
 private:
  Persistent<UnboundScript> script_;

 public:
  static void Init(Environment* env, Local<Object> target) {
    HandleScope scope(env->isolate());
    Local<String> class_name =
        FIXED_ONE_BYTE_STRING(env->isolate(), "\x43\x6f\x6e\x74\x65\x78\x74\x69\x66\x79\x53\x63\x72\x69\x70\x74");

    Local<FunctionTemplate> script_tmpl = FunctionTemplate::New(env->isolate(),
                                                                New);
    script_tmpl->InstanceTemplate()->SetInternalFieldCount(1);
    script_tmpl->SetClassName(class_name);
    NODE_SET_PROTOTYPE_METHOD(script_tmpl, "\x72\x75\x6e\x49\x6e\x43\x6f\x6e\x74\x65\x78\x74", RunInContext);
    NODE_SET_PROTOTYPE_METHOD(script_tmpl,
                              "\x72\x75\x6e\x49\x6e\x54\x68\x69\x73\x43\x6f\x6e\x74\x65\x78\x74",
                              RunInThisContext);

    target->Set(class_name, script_tmpl->GetFunction());
    env->set_script_context_constructor_template(script_tmpl);
  }


  // args: code, [options]
  static void New(const FunctionCallbackInfo<Value>& args) {
    Environment* env = Environment::GetCurrent(args.GetIsolate());
    HandleScope scope(env->isolate());

    if (!args.IsConstructCall()) {
      return env->ThrowError("\x4d\x75\x73\x74\x20\x63\x61\x6c\x6c\x20\x76\x6d\x2e\x53\x63\x72\x69\x70\x74\x20\x61\x73\x20\x61\x20\x63\x6f\x6e\x73\x74\x72\x75\x63\x74\x6f\x72\x2e");
    }

    ContextifyScript* contextify_script =
        new ContextifyScript(env, args.This());

    TryCatch try_catch;
    Local<String> code = args[0]->ToString();
    Local<String> filename = GetFilenameArg(args, 1);
    bool display_errors = GetDisplayErrorsArg(args, 1);
    if (try_catch.HasCaught()) {
      try_catch.ReThrow();
      return;
    }

    ScriptOrigin origin(filename);
    ScriptCompiler::Source source(code, origin);
    Local<UnboundScript> v8_script =
        ScriptCompiler::CompileUnbound(env->isolate(), &source);

    if (v8_script.IsEmpty()) {
      if (display_errors) {
        AppendExceptionLine(env, try_catch.Exception(), try_catch.Message());
      }
      try_catch.ReThrow();
      return;
    }
    contextify_script->script_.Reset(env->isolate(), v8_script);
  }


  static bool InstanceOf(Environment* env, const Local<Value>& value) {
    return !value.IsEmpty() &&
           env->script_context_constructor_template()->HasInstance(value);
  }


  // args: [options]
  static void RunInThisContext(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    HandleScope handle_scope(isolate);

    // Assemble arguments
    TryCatch try_catch;
    uint64_t timeout = GetTimeoutArg(args, 0);
    bool display_errors = GetDisplayErrorsArg(args, 0);
    if (try_catch.HasCaught()) {
      try_catch.ReThrow();
      return;
    }

    // Do the eval within this context
    Environment* env = Environment::GetCurrent(isolate);
    EvalMachine(env, timeout, display_errors, args, try_catch);
  }

  // args: sandbox, [options]
  static void RunInContext(const FunctionCallbackInfo<Value>& args) {
    Environment* env = Environment::GetCurrent(args.GetIsolate());
    HandleScope scope(env->isolate());

    int64_t timeout;
    bool display_errors;

    // Assemble arguments
    if (!args[0]->IsObject()) {
      return env->ThrowTypeError(
          "\x63\x6f\x6e\x74\x65\x78\x74\x69\x66\x69\x65\x64\x53\x61\x6e\x64\x62\x6f\x78\x20\x61\x72\x67\x75\x6d\x65\x6e\x74\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x6e\x20\x6f\x62\x6a\x65\x63\x74\x2e");
    }

    Local<Object> sandbox = args[0].As<Object>();
    {
      TryCatch try_catch;
      timeout = GetTimeoutArg(args, 1);
      display_errors = GetDisplayErrorsArg(args, 1);
      if (try_catch.HasCaught()) {
        try_catch.ReThrow();
        return;
      }
    }

    // Get the context from the sandbox
    ContextifyContext* contextify_context =
        ContextifyContext::ContextFromContextifiedSandbox(env->isolate(),
                                                          sandbox);
    if (contextify_context == NULL) {
      return env->ThrowTypeError(
          "\x73\x61\x6e\x64\x62\x6f\x78\x20\x61\x72\x67\x75\x6d\x65\x6e\x74\x20\x6d\x75\x73\x74\x20\x68\x61\x76\x65\x20\x62\x65\x65\x6e\x20\x63\x6f\x6e\x76\x65\x72\x74\x65\x64\x20\x74\x6f\x20\x61\x20\x63\x6f\x6e\x74\x65\x78\x74\x2e");
    }

    if (contextify_context->context().IsEmpty())
      return;

    {
      TryCatch try_catch;
      // Do the eval within the context
      Context::Scope context_scope(contextify_context->context());
      if (EvalMachine(contextify_context->env(),
                      timeout,
                      display_errors,
                      args,
                      try_catch)) {
        contextify_context->CopyProperties();
      }

      if (try_catch.HasCaught()) {
        try_catch.ReThrow();
        return;
      }
    }
  }

  static int64_t GetTimeoutArg(const FunctionCallbackInfo<Value>& args,
                               const int i) {
    if (args[i]->IsUndefined() || args[i]->IsString()) {
      return -1;
    }
    if (!args[i]->IsObject()) {
      Environment::ThrowTypeError(args.GetIsolate(),
                                  "\x6f\x70\x74\x69\x6f\x6e\x73\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x6e\x20\x6f\x62\x6a\x65\x63\x74");
      return -1;
    }

    Local<String> key = FIXED_ONE_BYTE_STRING(args.GetIsolate(), "\x74\x69\x6d\x65\x6f\x75\x74");
    Local<Value> value = args[i].As<Object>()->Get(key);
    if (value->IsUndefined()) {
      return -1;
    }
    int64_t timeout = value->IntegerValue();

    if (timeout <= 0) {
      Environment::ThrowRangeError(args.GetIsolate(),
                                   "\x74\x69\x6d\x65\x6f\x75\x74\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x20\x70\x6f\x73\x69\x74\x69\x76\x65\x20\x6e\x75\x6d\x62\x65\x72");
      return -1;
    }
    return timeout;
  }


  static bool GetDisplayErrorsArg(const FunctionCallbackInfo<Value>& args,
                                  const int i) {
    if (args[i]->IsUndefined() || args[i]->IsString()) {
      return true;
    }
    if (!args[i]->IsObject()) {
      Environment::ThrowTypeError(args.GetIsolate(),
                                  "\x6f\x70\x74\x69\x6f\x6e\x73\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x6e\x20\x6f\x62\x6a\x65\x63\x74");
      return false;
    }

    Local<String> key = FIXED_ONE_BYTE_STRING(args.GetIsolate(),
                                              "\x64\x69\x73\x70\x6c\x61\x79\x45\x72\x72\x6f\x72\x73");
    Local<Value> value = args[i].As<Object>()->Get(key);

    return value->IsUndefined() ? true : value->BooleanValue();
  }


  static Local<String> GetFilenameArg(const FunctionCallbackInfo<Value>& args,
                                      const int i) {
    Local<String> defaultFilename =
        FIXED_ONE_BYTE_STRING(args.GetIsolate(), "\x65\x76\x61\x6c\x6d\x61\x63\x68\x69\x6e\x65\x2e\x3c\x61\x6e\x6f\x6e\x79\x6d\x6f\x75\x73\x3e");

    if (args[i]->IsUndefined()) {
      return defaultFilename;
    }
    if (args[i]->IsString()) {
      return args[i].As<String>();
    }
    if (!args[i]->IsObject()) {
      Environment::ThrowTypeError(args.GetIsolate(),
                                  "\x6f\x70\x74\x69\x6f\x6e\x73\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x6e\x20\x6f\x62\x6a\x65\x63\x74");
      return Local<String>();
    }

    Local<String> key = FIXED_ONE_BYTE_STRING(args.GetIsolate(), "\x66\x69\x6c\x65\x6e\x61\x6d\x65");
    Local<Value> value = args[i].As<Object>()->Get(key);

    return value->IsUndefined() ? defaultFilename : value->ToString();
  }


  static bool EvalMachine(Environment* env,
                          const int64_t timeout,
                          const bool display_errors,
                          const FunctionCallbackInfo<Value>& args,
                          TryCatch& try_catch) {
    if (!ContextifyScript::InstanceOf(env, args.Holder())) {
      env->ThrowTypeError(
          "\x53\x63\x72\x69\x70\x74\x20\x6d\x65\x74\x68\x6f\x64\x73\x20\x63\x61\x6e\x20\x6f\x6e\x6c\x79\x20\x62\x65\x20\x63\x61\x6c\x6c\x65\x64\x20\x6f\x6e\x20\x73\x63\x72\x69\x70\x74\x20\x69\x6e\x73\x74\x61\x6e\x63\x65\x73\x2e");
      return false;
    }

    ContextifyScript* wrapped_script = Unwrap<ContextifyScript>(args.Holder());
    Local<UnboundScript> unbound_script =
        PersistentToLocal(env->isolate(), wrapped_script->script_);
    Local<Script> script = unbound_script->BindToCurrentContext();

    Local<Value> result;
    if (timeout != -1) {
      Watchdog wd(env, timeout);
      result = script->Run();
    } else {
      result = script->Run();
    }

    if (try_catch.HasCaught() && try_catch.HasTerminated()) {
      V8::CancelTerminateExecution(env->isolate());
      env->ThrowError("\x53\x63\x72\x69\x70\x74\x20\x65\x78\x65\x63\x75\x74\x69\x6f\x6e\x20\x74\x69\x6d\x65\x64\x20\x6f\x75\x74\x2e");
      try_catch.ReThrow();
      return false;
    }

    if (result.IsEmpty()) {
      // Error occurred during execution of the script.
      if (display_errors) {
        AppendExceptionLine(env, try_catch.Exception(), try_catch.Message());
      }
      try_catch.ReThrow();
      return false;
    }

    args.GetReturnValue().Set(result);
    return true;
  }


  ContextifyScript(Environment* env, Local<Object> object)
      : BaseObject(env, object) {
    MakeWeak<ContextifyScript>(this);
  }


  ~ContextifyScript() {
    script_.Reset();
  }
};


void InitContextify(Handle<Object> target,
                    Handle<Value> unused,
                    Handle<Context> context) {
  Environment* env = Environment::GetCurrent(context);
  ContextifyContext::Init(env, target);
  ContextifyScript::Init(env, target);
}

}  // namespace node

NODE_MODULE_CONTEXT_AWARE_BUILTIN(contextify, node::InitContextify);
