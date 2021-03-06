#include "node.h"
#include "node_internals.h"
#include "node_watchdog.h"
#include "base-object-inl.h"
#include "env.h"
#include "env-inl.h"
#include "util-inl.h"
#include "v8-debug.h"

namespace node {

using v8::Array;
using v8::ArrayBuffer;
using v8::Boolean;
using v8::Context;
using v8::Debug;
using v8::EscapableHandleScope;
using v8::External;
using v8::Function;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::HandleScope;
using v8::Integer;
using v8::Just;
using v8::Local;
using v8::Maybe;
using v8::MaybeLocal;
using v8::Name;
using v8::NamedPropertyHandlerConfiguration;
using v8::Nothing;
using v8::Object;
using v8::ObjectTemplate;
using v8::Persistent;
using v8::PropertyAttribute;
using v8::PropertyCallbackInfo;
using v8::Script;
using v8::ScriptCompiler;
using v8::ScriptOrigin;
using v8::String;
using v8::TryCatch;
using v8::Uint8Array;
using v8::UnboundScript;
using v8::Value;
using v8::WeakCallbackInfo;


class ContextifyContext {
 protected:
  // V8 reserves the first field in context objects for the debugger. We use the
  // second field to hold a reference to the sandbox object.
  enum { kSandboxObjectIndex = 1 };

  Environment* const env_;
  Persistent<Context> context_;

 public:
  ContextifyContext(Environment* env, Local<Object> sandbox_obj) : env_(env) {
    Local<Context> v8_context = CreateV8Context(env, sandbox_obj);
    context_.Reset(env->isolate(), v8_context);

    // Allocation failure or maximum call stack size reached
    if (context_.IsEmpty())
      return;
    context_.SetWeak(this, WeakCallback, v8::WeakCallbackType::kParameter);
    context_.MarkIndependent();
  }


  ~ContextifyContext() {
    context_.Reset();
  }


  inline Environment* env() const {
    return env_;
  }


  inline Local<Context> context() const {
    return PersistentToLocal(env()->isolate(), context_);
  }


  inline Local<Object> global_proxy() const {
    return context()->Global();
  }


  inline Local<Object> sandbox() const {
    return Local<Object>::Cast(context()->GetEmbedderData(kSandboxObjectIndex));
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
    Local<Object> global =
        context->Global()->GetPrototype()->ToObject(env()->isolate());
    Local<Object> sandbox_obj = sandbox();

    Local<Function> clone_property_method;

    Local<Array> names = global->GetOwnPropertyNames();
    int length = names->Length();
    for (int i = 0; i < length; i++) {
      Local<String> key = names->Get(i)->ToString(env()->isolate());
      auto maybe_has = sandbox_obj->HasOwnProperty(context, key);

      // Check for pending exceptions
      if (!maybe_has.IsJust())
        break;

      bool has = maybe_has.FromJust();

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

          Local<Script> script =
              Script::Compile(context, code).ToLocalChecked();
          clone_property_method = Local<Function>::Cast(script->Run());
          CHECK(clone_property_method->IsFunction());
        }
        Local<Value> args[] = { global, key, sandbox_obj };
        clone_property_method->Call(global, arraysize(args), args);
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
        env->script_data_constructor_function()
            ->NewInstance(env->context()).FromMaybe(Local<Object>());
    if (wrapper.IsEmpty())
      return scope.Escape(Local<Value>::New(env->isolate(), Local<Value>()));

    Wrap(wrapper, this);
    return scope.Escape(wrapper);
  }


  Local<Context> CreateV8Context(Environment* env, Local<Object> sandbox_obj) {
    EscapableHandleScope scope(env->isolate());
    Local<FunctionTemplate> function_template =
        FunctionTemplate::New(env->isolate());
    function_template->SetHiddenPrototype(true);

    function_template->SetClassName(sandbox_obj->GetConstructorName());

    Local<ObjectTemplate> object_template =
        function_template->InstanceTemplate();

    NamedPropertyHandlerConfiguration config(GlobalPropertyGetterCallback,
                                             GlobalPropertySetterCallback,
                                             GlobalPropertyQueryCallback,
                                             GlobalPropertyDeleterCallback,
                                             GlobalPropertyEnumeratorCallback,
                                             CreateDataWrapper(env));
    object_template->SetHandler(config);

    Local<Context> ctx = Context::New(env->isolate(), nullptr, object_template);

    if (ctx.IsEmpty()) {
      env->ThrowError("\x43\x6f\x75\x6c\x64\x20\x6e\x6f\x74\x20\x69\x6e\x73\x74\x61\x6e\x74\x69\x61\x74\x65\x20\x63\x6f\x6e\x74\x65\x78\x74");
      return Local<Context>();
    }

    ctx->SetSecurityToken(env->context()->GetSecurityToken());

    // We need to tie the lifetime of the sandbox object with the lifetime of
    // newly created context. We do this by making them hold references to each
    // other. The context can directly hold a reference to the sandbox as an
    // embedder data field. However, we cannot hold a reference to a v8::Context
    // directly in an Object, we instead hold onto the new context's global
    // object instead (which then has a reference to the context).
    ctx->SetEmbedderData(kSandboxObjectIndex, sandbox_obj);
    sandbox_obj->SetPrivate(env->context(),
                            env->contextify_global_private_symbol(),
                            ctx->Global());

    env->AssignToContext(ctx);

    return scope.Escape(ctx);
  }


  static void Init(Environment* env, Local<Object> target) {
    Local<FunctionTemplate> function_template =
        FunctionTemplate::New(env->isolate());
    function_template->InstanceTemplate()->SetInternalFieldCount(1);
    env->set_script_data_constructor_function(function_template->GetFunction());

    env->SetMethod(target, "\x72\x75\x6e\x49\x6e\x44\x65\x62\x75\x67\x43\x6f\x6e\x74\x65\x78\x74", RunInDebugContext);
    env->SetMethod(target, "\x6d\x61\x6b\x65\x43\x6f\x6e\x74\x65\x78\x74", MakeContext);
    env->SetMethod(target, "\x69\x73\x43\x6f\x6e\x74\x65\x78\x74", IsContext);
  }


  static void RunInDebugContext(const FunctionCallbackInfo<Value>& args) {
    Local<String> script_source(args[0]->ToString(args.GetIsolate()));
    if (script_source.IsEmpty())
      return;  // Exception pending.
    Local<Context> debug_context = Debug::GetDebugContext(args.GetIsolate());
    Environment* env = Environment::GetCurrent(args);
    if (debug_context.IsEmpty()) {
      // Force-load the debug context.
      auto dummy_event_listener = [] (const Debug::EventDetails&) {};
      Debug::SetDebugEventListener(args.GetIsolate(), dummy_event_listener);
      debug_context = Debug::GetDebugContext(args.GetIsolate());
      CHECK(!debug_context.IsEmpty());
      // Ensure that the debug context has an Environment assigned in case
      // a fatal error is raised.  The fatal exception handler in node.cc
      // is not equipped to deal with contexts that don't have one and
      // can't easily be taught that due to a deficiency in the V8 API:
      // there is no way for the embedder to tell if the data index is
      // in use.
      const int index = Environment::kContextEmbedderDataIndex;
      debug_context->SetAlignedPointerInEmbedderData(index, env);
    }

    Context::Scope context_scope(debug_context);
    MaybeLocal<Script> script = Script::Compile(debug_context, script_source);
    if (script.IsEmpty())
      return;  // Exception pending.
    args.GetReturnValue().Set(script.ToLocalChecked()->Run());
  }


  static void MakeContext(const FunctionCallbackInfo<Value>& args) {
    Environment* env = Environment::GetCurrent(args);

    if (!args[0]->IsObject()) {
      return env->ThrowTypeError("\x73\x61\x6e\x64\x62\x6f\x78\x20\x61\x72\x67\x75\x6d\x65\x6e\x74\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x6e\x20\x6f\x62\x6a\x65\x63\x74\x2e");
    }
    Local<Object> sandbox = args[0].As<Object>();

    // Don't allow contextifying a sandbox multiple times.
    CHECK(
        !sandbox->HasPrivate(
            env->context(),
            env->contextify_context_private_symbol()).FromJust());

    TryCatch try_catch(env->isolate());
    ContextifyContext* context = new ContextifyContext(env, sandbox);

    if (try_catch.HasCaught()) {
      try_catch.ReThrow();
      return;
    }

    if (context->context().IsEmpty())
      return;

    sandbox->SetPrivate(
        env->context(),
        env->contextify_context_private_symbol(),
        External::New(env->isolate(), context));
  }


  static void IsContext(const FunctionCallbackInfo<Value>& args) {
    Environment* env = Environment::GetCurrent(args);

    if (!args[0]->IsObject()) {
      env->ThrowTypeError("\x73\x61\x6e\x64\x62\x6f\x78\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x6e\x20\x6f\x62\x6a\x65\x63\x74");
      return;
    }
    Local<Object> sandbox = args[0].As<Object>();

    auto result =
        sandbox->HasPrivate(env->context(),
                            env->contextify_context_private_symbol());
    args.GetReturnValue().Set(result.FromJust());
  }


  static void WeakCallback(const WeakCallbackInfo<ContextifyContext>& data) {
    ContextifyContext* context = data.GetParameter();
    delete context;
  }


  static ContextifyContext* ContextFromContextifiedSandbox(
      Environment* env,
      const Local<Object>& sandbox) {
    auto maybe_value =
        sandbox->GetPrivate(env->context(),
                            env->contextify_context_private_symbol());
    Local<Value> context_external_v;
    if (maybe_value.ToLocal(&context_external_v) &&
        context_external_v->IsExternal()) {
      Local<External> context_external = context_external_v.As<External>();
      return static_cast<ContextifyContext*>(context_external->Value());
    }
    return nullptr;
  }


  static void GlobalPropertyGetterCallback(
      Local<Name> property,
      const PropertyCallbackInfo<Value>& args) {
    ContextifyContext* ctx;
    ASSIGN_OR_RETURN_UNWRAP(&ctx, args.Data().As<Object>());

    // Still initializing
    if (ctx->context_.IsEmpty())
      return;

    Local<Context> context = ctx->context();
    Local<Object> sandbox = ctx->sandbox();
    MaybeLocal<Value> maybe_rv =
        sandbox->GetRealNamedProperty(context, property);
    if (maybe_rv.IsEmpty()) {
      maybe_rv =
          ctx->global_proxy()->GetRealNamedProperty(context, property);
    }

    Local<Value> rv;
    if (maybe_rv.ToLocal(&rv)) {
      if (rv == sandbox)
        rv = ctx->global_proxy();

      args.GetReturnValue().Set(rv);
    }
  }


  static void GlobalPropertySetterCallback(
      Local<Name> property,
      Local<Value> value,
      const PropertyCallbackInfo<Value>& args) {
    ContextifyContext* ctx;
    ASSIGN_OR_RETURN_UNWRAP(&ctx, args.Data().As<Object>());

    // Still initializing
    if (ctx->context_.IsEmpty())
      return;

    bool is_declared =
        ctx->global_proxy()->HasRealNamedProperty(ctx->context(),
                                                  property).FromJust();
    bool is_contextual_store = ctx->global_proxy() != args.This();

    bool set_property_will_throw =
        args.ShouldThrowOnError() &&
        !is_declared &&
        is_contextual_store;

    if (!set_property_will_throw) {
      ctx->sandbox()->Set(property, value);
    }
  }


  static void GlobalPropertyQueryCallback(
      Local<Name> property,
      const PropertyCallbackInfo<Integer>& args) {
    ContextifyContext* ctx;
    ASSIGN_OR_RETURN_UNWRAP(&ctx, args.Data().As<Object>());

    // Still initializing
    if (ctx->context_.IsEmpty())
      return;

    Local<Context> context = ctx->context();
    Maybe<PropertyAttribute> maybe_prop_attr =
        ctx->sandbox()->GetRealNamedPropertyAttributes(context, property);

    if (maybe_prop_attr.IsNothing()) {
      maybe_prop_attr =
          ctx->global_proxy()->GetRealNamedPropertyAttributes(context,
                                                              property);
    }

    if (maybe_prop_attr.IsJust()) {
      PropertyAttribute prop_attr = maybe_prop_attr.FromJust();
      args.GetReturnValue().Set(prop_attr);
    }
  }


  static void GlobalPropertyDeleterCallback(
      Local<Name> property,
      const PropertyCallbackInfo<Boolean>& args) {
    ContextifyContext* ctx;
    ASSIGN_OR_RETURN_UNWRAP(&ctx, args.Data().As<Object>());

    // Still initializing
    if (ctx->context_.IsEmpty())
      return;

    Maybe<bool> success = ctx->sandbox()->Delete(ctx->context(), property);

    if (success.IsJust())
      args.GetReturnValue().Set(success.FromJust());
  }


  static void GlobalPropertyEnumeratorCallback(
      const PropertyCallbackInfo<Array>& args) {
    ContextifyContext* ctx;
    ASSIGN_OR_RETURN_UNWRAP(&ctx, args.Data().As<Object>());

    // Still initializing
    if (ctx->context_.IsEmpty())
      return;

    args.GetReturnValue().Set(ctx->sandbox()->GetPropertyNames());
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

    Local<FunctionTemplate> script_tmpl = env->NewFunctionTemplate(New);
    script_tmpl->InstanceTemplate()->SetInternalFieldCount(1);
    script_tmpl->SetClassName(class_name);
    env->SetProtoMethod(script_tmpl, "\x72\x75\x6e\x49\x6e\x43\x6f\x6e\x74\x65\x78\x74", RunInContext);
    env->SetProtoMethod(script_tmpl, "\x72\x75\x6e\x49\x6e\x54\x68\x69\x73\x43\x6f\x6e\x74\x65\x78\x74", RunInThisContext);

    target->Set(class_name, script_tmpl->GetFunction());
    env->set_script_context_constructor_template(script_tmpl);
  }


  // args: code, [options]
  static void New(const FunctionCallbackInfo<Value>& args) {
    Environment* env = Environment::GetCurrent(args);

    if (!args.IsConstructCall()) {
      return env->ThrowError("\x4d\x75\x73\x74\x20\x63\x61\x6c\x6c\x20\x76\x6d\x2e\x53\x63\x72\x69\x70\x74\x20\x61\x73\x20\x61\x20\x63\x6f\x6e\x73\x74\x72\x75\x63\x74\x6f\x72\x2e");
    }

    ContextifyScript* contextify_script =
        new ContextifyScript(env, args.This());

    TryCatch try_catch(env->isolate());
    Local<String> code = args[0]->ToString(env->isolate());

    Local<Value> options = args[1];
    MaybeLocal<String> filename = GetFilenameArg(env, options);
    MaybeLocal<Integer> lineOffset = GetLineOffsetArg(env, options);
    MaybeLocal<Integer> columnOffset = GetColumnOffsetArg(env, options);
    Maybe<bool> maybe_display_errors = GetDisplayErrorsArg(env, options);
    MaybeLocal<Uint8Array> cached_data_buf = GetCachedData(env, options);
    Maybe<bool> maybe_produce_cached_data = GetProduceCachedData(env, options);
    if (try_catch.HasCaught()) {
      try_catch.ReThrow();
      return;
    }

    bool display_errors = maybe_display_errors.FromJust();
    bool produce_cached_data = maybe_produce_cached_data.FromJust();

    ScriptCompiler::CachedData* cached_data = nullptr;
    if (!cached_data_buf.IsEmpty()) {
      Local<Uint8Array> ui8 = cached_data_buf.ToLocalChecked();
      ArrayBuffer::Contents contents = ui8->Buffer()->GetContents();
      cached_data = new ScriptCompiler::CachedData(
          static_cast<uint8_t*>(contents.Data()) + ui8->ByteOffset(),
          ui8->ByteLength());
    }

    ScriptOrigin origin(filename.ToLocalChecked(), lineOffset.ToLocalChecked(),
                        columnOffset.ToLocalChecked());
    ScriptCompiler::Source source(code, origin, cached_data);
    ScriptCompiler::CompileOptions compile_options =
        ScriptCompiler::kNoCompileOptions;

    if (source.GetCachedData() != nullptr)
      compile_options = ScriptCompiler::kConsumeCodeCache;
    else if (produce_cached_data)
      compile_options = ScriptCompiler::kProduceCodeCache;

    MaybeLocal<UnboundScript> v8_script = ScriptCompiler::CompileUnboundScript(
        env->isolate(),
        &source,
        compile_options);

    if (v8_script.IsEmpty()) {
      if (display_errors) {
        DecorateErrorStack(env, try_catch);
      }
      try_catch.ReThrow();
      return;
    }
    contextify_script->script_.Reset(env->isolate(),
                                     v8_script.ToLocalChecked());

    if (compile_options == ScriptCompiler::kConsumeCodeCache) {
      args.This()->Set(
          env->cached_data_rejected_string(),
          Boolean::New(env->isolate(), source.GetCachedData()->rejected));
    } else if (compile_options == ScriptCompiler::kProduceCodeCache) {
      const ScriptCompiler::CachedData* cached_data = source.GetCachedData();
      bool cached_data_produced = cached_data != nullptr;
      if (cached_data_produced) {
        MaybeLocal<Object> buf = Buffer::Copy(
            env,
            reinterpret_cast<const char*>(cached_data->data),
            cached_data->length);
        args.This()->Set(env->cached_data_string(), buf.ToLocalChecked());
      }
      args.This()->Set(
          env->cached_data_produced_string(),
          Boolean::New(env->isolate(), cached_data_produced));
    }
  }


  static bool InstanceOf(Environment* env, const Local<Value>& value) {
    return !value.IsEmpty() &&
           env->script_context_constructor_template()->HasInstance(value);
  }


  // args: [options]
  static void RunInThisContext(const FunctionCallbackInfo<Value>& args) {
    Environment* env = Environment::GetCurrent(args);

    // Assemble arguments
    TryCatch try_catch(args.GetIsolate());
    Maybe<int64_t> maybe_timeout = GetTimeoutArg(env, args[0]);
    Maybe<bool> maybe_display_errors = GetDisplayErrorsArg(env, args[0]);
    Maybe<bool> maybe_break_on_sigint = GetBreakOnSigintArg(env, args[0]);
    if (try_catch.HasCaught()) {
      try_catch.ReThrow();
      return;
    }

    int64_t timeout = maybe_timeout.FromJust();
    bool display_errors = maybe_display_errors.FromJust();
    bool break_on_sigint = maybe_break_on_sigint.FromJust();

    // Do the eval within this context
    EvalMachine(env, timeout, display_errors, break_on_sigint, args,
                &try_catch);
  }

  // args: sandbox, [options]
  static void RunInContext(const FunctionCallbackInfo<Value>& args) {
    Environment* env = Environment::GetCurrent(args);

    int64_t timeout;
    bool display_errors;
    bool break_on_sigint;

    // Assemble arguments
    if (!args[0]->IsObject()) {
      return env->ThrowTypeError(
          "\x63\x6f\x6e\x74\x65\x78\x74\x69\x66\x69\x65\x64\x53\x61\x6e\x64\x62\x6f\x78\x20\x61\x72\x67\x75\x6d\x65\x6e\x74\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x6e\x20\x6f\x62\x6a\x65\x63\x74\x2e");
    }

    Local<Object> sandbox = args[0].As<Object>();
    {
      TryCatch try_catch(env->isolate());
      Maybe<int64_t> maybe_timeout = GetTimeoutArg(env, args[1]);
      Maybe<bool> maybe_display_errors = GetDisplayErrorsArg(env, args[1]);
      Maybe<bool> maybe_break_on_sigint = GetBreakOnSigintArg(env, args[1]);
      if (try_catch.HasCaught()) {
        try_catch.ReThrow();
        return;
      }

      timeout = maybe_timeout.FromJust();
      display_errors = maybe_display_errors.FromJust();
      break_on_sigint = maybe_break_on_sigint.FromJust();
    }

    // Get the context from the sandbox
    ContextifyContext* contextify_context =
        ContextifyContext::ContextFromContextifiedSandbox(env, sandbox);
    if (contextify_context == nullptr) {
      return env->ThrowTypeError(
          "\x73\x61\x6e\x64\x62\x6f\x78\x20\x61\x72\x67\x75\x6d\x65\x6e\x74\x20\x6d\x75\x73\x74\x20\x68\x61\x76\x65\x20\x62\x65\x65\x6e\x20\x63\x6f\x6e\x76\x65\x72\x74\x65\x64\x20\x74\x6f\x20\x61\x20\x63\x6f\x6e\x74\x65\x78\x74\x2e");
    }

    if (contextify_context->context().IsEmpty())
      return;

    {
      TryCatch try_catch(env->isolate());
      // Do the eval within the context
      Context::Scope context_scope(contextify_context->context());
      if (EvalMachine(contextify_context->env(),
                      timeout,
                      display_errors,
                      break_on_sigint,
                      args,
                      &try_catch)) {
        contextify_context->CopyProperties();
      }

      if (try_catch.HasCaught()) {
        try_catch.ReThrow();
        return;
      }
    }
  }

  static void DecorateErrorStack(Environment* env, const TryCatch& try_catch) {
    Local<Value> exception = try_catch.Exception();

    if (!exception->IsObject())
      return;

    Local<Object> err_obj = exception.As<Object>();

    if (IsExceptionDecorated(env, err_obj))
      return;

    AppendExceptionLine(env, exception, try_catch.Message(), CONTEXTIFY_ERROR);
    Local<Value> stack = err_obj->Get(env->stack_string());
    auto maybe_value =
        err_obj->GetPrivate(
            env->context(),
            env->arrow_message_private_symbol());

    Local<Value> arrow;
    if (!(maybe_value.ToLocal(&arrow) && arrow->IsString())) {
      return;
    }

    if (stack.IsEmpty() || !stack->IsString()) {
      return;
    }

    Local<String> decorated_stack = String::Concat(
        String::Concat(arrow.As<String>(),
          FIXED_ONE_BYTE_STRING(env->isolate(), u8"\n")),
        stack.As<String>());
    err_obj->Set(env->stack_string(), decorated_stack);
    err_obj->SetPrivate(
        env->context(),
        env->decorated_private_symbol(),
        True(env->isolate()));
  }

  static Maybe<bool> GetBreakOnSigintArg(Environment* env,
                                         Local<Value> options) {
    if (options->IsUndefined() || options->IsString()) {
      return Just(false);
    }
    if (!options->IsObject()) {
      env->ThrowTypeError("\x6f\x70\x74\x69\x6f\x6e\x73\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x6e\x20\x6f\x62\x6a\x65\x63\x74");
      return Nothing<bool>();
    }

    Local<String> key = FIXED_ONE_BYTE_STRING(env->isolate(), "\x62\x72\x65\x61\x6b\x4f\x6e\x53\x69\x67\x69\x6e\x74");
    MaybeLocal<Value> maybe_value =
        options.As<Object>()->Get(env->context(), key);
    if (maybe_value.IsEmpty())
      return Nothing<bool>();

    Local<Value> value = maybe_value.ToLocalChecked();
    return Just(value->IsTrue());
  }

  static Maybe<int64_t> GetTimeoutArg(Environment* env, Local<Value> options) {
    if (options->IsUndefined() || options->IsString()) {
      return Just<int64_t>(-1);
    }
    if (!options->IsObject()) {
      env->ThrowTypeError("\x6f\x70\x74\x69\x6f\x6e\x73\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x6e\x20\x6f\x62\x6a\x65\x63\x74");
      return Nothing<int64_t>();
    }

    MaybeLocal<Value> maybe_value =
        options.As<Object>()->Get(env->context(), env->timeout_string());
    if (maybe_value.IsEmpty())
      return Nothing<int64_t>();

    Local<Value> value = maybe_value.ToLocalChecked();
    if (value->IsUndefined()) {
      return Just<int64_t>(-1);
    }

    Maybe<int64_t> timeout = value->IntegerValue(env->context());

    if (timeout.IsJust() && timeout.FromJust() <= 0) {
      env->ThrowRangeError("\x74\x69\x6d\x65\x6f\x75\x74\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x20\x70\x6f\x73\x69\x74\x69\x76\x65\x20\x6e\x75\x6d\x62\x65\x72");
      return Nothing<int64_t>();
    }

    return timeout;
  }


  static Maybe<bool> GetDisplayErrorsArg(Environment* env,
                                         Local<Value> options) {
    if (options->IsUndefined() || options->IsString()) {
      return Just(true);
    }
    if (!options->IsObject()) {
      env->ThrowTypeError("\x6f\x70\x74\x69\x6f\x6e\x73\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x6e\x20\x6f\x62\x6a\x65\x63\x74");
      return Nothing<bool>();
    }

    Local<String> key = FIXED_ONE_BYTE_STRING(env->isolate(), "\x64\x69\x73\x70\x6c\x61\x79\x45\x72\x72\x6f\x72\x73");
    MaybeLocal<Value> maybe_value =
        options.As<Object>()->Get(env->context(), key);
    if (maybe_value.IsEmpty())
      return Nothing<bool>();

    Local<Value> value = maybe_value.ToLocalChecked();
    if (value->IsUndefined())
      return Just(true);

    return value->BooleanValue(env->context());
  }


  static MaybeLocal<String> GetFilenameArg(Environment* env,
                                           Local<Value> options) {
    Local<String> defaultFilename =
        FIXED_ONE_BYTE_STRING(env->isolate(), "\x65\x76\x61\x6c\x6d\x61\x63\x68\x69\x6e\x65\x2e\x3c\x61\x6e\x6f\x6e\x79\x6d\x6f\x75\x73\x3e");

    if (options->IsUndefined()) {
      return defaultFilename;
    }
    if (options->IsString()) {
      return options.As<String>();
    }
    if (!options->IsObject()) {
      env->ThrowTypeError("\x6f\x70\x74\x69\x6f\x6e\x73\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x6e\x20\x6f\x62\x6a\x65\x63\x74");
      return Local<String>();
    }

    Local<String> key = FIXED_ONE_BYTE_STRING(env->isolate(), "\x66\x69\x6c\x65\x6e\x61\x6d\x65");
    MaybeLocal<Value> maybe_value =
        options.As<Object>()->Get(env->context(), key);
    if (maybe_value.IsEmpty())
      return MaybeLocal<String>();

    Local<Value> value = maybe_value.ToLocalChecked();
    if (value->IsUndefined())
      return defaultFilename;
    return value->ToString(env->context());
  }


  static MaybeLocal<Uint8Array> GetCachedData(Environment* env,
                                              Local<Value> options) {
    if (!options->IsObject()) {
      return MaybeLocal<Uint8Array>();
    }

    MaybeLocal<Value> maybe_value =
        options.As<Object>()->Get(env->context(), env->cached_data_string());
    if (maybe_value.IsEmpty())
      return MaybeLocal<Uint8Array>();

    Local<Value> value = maybe_value.ToLocalChecked();
    if (value->IsUndefined()) {
      return MaybeLocal<Uint8Array>();
    }

    if (!value->IsUint8Array()) {
      env->ThrowTypeError("\x6f\x70\x74\x69\x6f\x6e\x73\x2e\x63\x61\x63\x68\x65\x64\x44\x61\x74\x61\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x20\x42\x75\x66\x66\x65\x72\x20\x69\x6e\x73\x74\x61\x6e\x63\x65");
      return MaybeLocal<Uint8Array>();
    }

    return value.As<Uint8Array>();
  }


  static Maybe<bool> GetProduceCachedData(Environment* env,
                                          Local<Value> options) {
    if (!options->IsObject()) {
      return Just(false);
    }

    MaybeLocal<Value> maybe_value =
        options.As<Object>()->Get(env->context(),
                                  env->produce_cached_data_string());
    if (maybe_value.IsEmpty())
      return Nothing<bool>();

    Local<Value> value = maybe_value.ToLocalChecked();
    return Just(value->IsTrue());
  }


  static MaybeLocal<Integer> GetLineOffsetArg(Environment* env,
                                              Local<Value> options) {
    Local<Integer> defaultLineOffset = Integer::New(env->isolate(), 0);

    if (!options->IsObject()) {
      return defaultLineOffset;
    }

    Local<String> key = FIXED_ONE_BYTE_STRING(env->isolate(), "\x6c\x69\x6e\x65\x4f\x66\x66\x73\x65\x74");
    MaybeLocal<Value> maybe_value =
        options.As<Object>()->Get(env->context(), key);
    if (maybe_value.IsEmpty())
      return MaybeLocal<Integer>();

    Local<Value> value = maybe_value.ToLocalChecked();
    if (value->IsUndefined())
      return defaultLineOffset;

    return value->ToInteger(env->context());
  }


  static MaybeLocal<Integer> GetColumnOffsetArg(Environment* env,
                                                Local<Value> options) {
    Local<Integer> defaultColumnOffset = Integer::New(env->isolate(), 0);

    if (!options->IsObject()) {
      return defaultColumnOffset;
    }

    Local<String> key = FIXED_ONE_BYTE_STRING(env->isolate(), "\x63\x6f\x6c\x75\x6d\x6e\x4f\x66\x66\x73\x65\x74");
    MaybeLocal<Value> maybe_value =
      options.As<Object>()->Get(env->context(), key);
    if (maybe_value.IsEmpty())
      return MaybeLocal<Integer>();

    Local<Value> value = maybe_value.ToLocalChecked();
    if (value->IsUndefined())
      return defaultColumnOffset;

    return value->ToInteger(env->context());
  }


  static bool EvalMachine(Environment* env,
                          const int64_t timeout,
                          const bool display_errors,
                          const bool break_on_sigint,
                          const FunctionCallbackInfo<Value>& args,
                          TryCatch* try_catch) {
    if (!ContextifyScript::InstanceOf(env, args.Holder())) {
      env->ThrowTypeError(
          "\x53\x63\x72\x69\x70\x74\x20\x6d\x65\x74\x68\x6f\x64\x73\x20\x63\x61\x6e\x20\x6f\x6e\x6c\x79\x20\x62\x65\x20\x63\x61\x6c\x6c\x65\x64\x20\x6f\x6e\x20\x73\x63\x72\x69\x70\x74\x20\x69\x6e\x73\x74\x61\x6e\x63\x65\x73\x2e");
      return false;
    }

    ContextifyScript* wrapped_script;
    ASSIGN_OR_RETURN_UNWRAP(&wrapped_script, args.Holder(), false);
    Local<UnboundScript> unbound_script =
        PersistentToLocal(env->isolate(), wrapped_script->script_);
    Local<Script> script = unbound_script->BindToCurrentContext();

    Local<Value> result;
    bool timed_out = false;
    bool received_signal = false;
    if (break_on_sigint && timeout != -1) {
      Watchdog wd(env->isolate(), timeout, &timed_out);
      SigintWatchdog swd(env->isolate(), &received_signal);
      result = script->Run();
    } else if (break_on_sigint) {
      SigintWatchdog swd(env->isolate(), &received_signal);
      result = script->Run();
    } else if (timeout != -1) {
      Watchdog wd(env->isolate(), timeout, &timed_out);
      result = script->Run();
    } else {
      result = script->Run();
    }

    if (timed_out || received_signal) {
      // It is possible that execution was terminated by another timeout in
      // which this timeout is nested, so check whether one of the watchdogs
      // from this invocation is responsible for termination.
      if (timed_out) {
        env->ThrowError("\x53\x63\x72\x69\x70\x74\x20\x65\x78\x65\x63\x75\x74\x69\x6f\x6e\x20\x74\x69\x6d\x65\x64\x20\x6f\x75\x74\x2e");
      } else if (received_signal) {
        env->ThrowError("\x53\x63\x72\x69\x70\x74\x20\x65\x78\x65\x63\x75\x74\x69\x6f\x6e\x20\x69\x6e\x74\x65\x72\x72\x75\x70\x74\x65\x64\x2e");
      }
      env->isolate()->CancelTerminateExecution();
    }

    if (try_catch->HasCaught()) {
      if (!timed_out && !received_signal && display_errors) {
        // We should decorate non-termination exceptions
        DecorateErrorStack(env, *try_catch);
      }

      // If there was an exception thrown during script execution, re-throw it.
      // If one of the above checks threw, re-throw the exception instead of
      // letting try_catch catch it.
      // If execution has been terminated, but not by one of the watchdogs from
      // this invocation, this will re-throw a `null` value.
      try_catch->ReThrow();

      return false;
    }

    args.GetReturnValue().Set(result);
    return true;
  }


  ContextifyScript(Environment* env, Local<Object> object)
      : BaseObject(env, object) {
    MakeWeak<ContextifyScript>(this);
  }


  ~ContextifyScript() override {
    script_.Reset();
  }
};


void InitContextify(Local<Object> target,
                    Local<Value> unused,
                    Local<Context> context) {
  Environment* env = Environment::GetCurrent(context);
  ContextifyContext::Init(env, target);
  ContextifyScript::Init(env, target);
}

}  // namespace node

NODE_MODULE_CONTEXT_AWARE_BUILTIN(contextify, node::InitContextify)
