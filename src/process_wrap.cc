#include "env-inl.h"
#include "handle_wrap.h"
#include "node_wrap.h"
#include "util-inl.h"

#include <string.h>
#include <stdlib.h>
#include <regex>
#ifdef __MVS__
#include <unistd.h> // e2a
#endif

namespace node {

using v8::Array;
using v8::Context;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::HandleScope;
using v8::Integer;
using v8::Local;
using v8::Number;
using v8::Object;
using v8::String;
using v8::Value;

class ProcessWrap : public HandleWrap {
 public:
  static void Initialize(Local<Object> target,
                         Local<Value> unused,
                         Local<Context> context) {
    Environment* env = Environment::GetCurrent(context);
    Local<FunctionTemplate> constructor = env->NewFunctionTemplate(New);
    constructor->InstanceTemplate()->SetInternalFieldCount(1);
    constructor->SetClassName(FIXED_ONE_BYTE_STRING(env->isolate(), "\x50\x72\x6f\x63\x65\x73\x73"));

    env->SetProtoMethod(constructor, "\x63\x6c\x6f\x73\x65", HandleWrap::Close);

    env->SetProtoMethod(constructor, "\x73\x70\x61\x77\x6e", Spawn);
    env->SetProtoMethod(constructor, "\x6b\x69\x6c\x6c", Kill);

    env->SetProtoMethod(constructor, "\x72\x65\x66", HandleWrap::Ref);
    env->SetProtoMethod(constructor, "\x75\x6e\x72\x65\x66", HandleWrap::Unref);
    env->SetProtoMethod(constructor, "\x68\x61\x73\x52\x65\x66", HandleWrap::HasRef);

    target->Set(FIXED_ONE_BYTE_STRING(env->isolate(), "\x50\x72\x6f\x63\x65\x73\x73"),
                constructor->GetFunction());
  }

  size_t self_size() const override { return sizeof(*this); }

 private:
  static void New(const FunctionCallbackInfo<Value>& args) {
    // This constructor should not be exposed to public javascript.
    // Therefore we assert that we are not trying to call this as a
    // normal function.
    CHECK(args.IsConstructCall());
    Environment* env = Environment::GetCurrent(args);
    new ProcessWrap(env, args.This());
  }

  ProcessWrap(Environment* env, Local<Object> object)
      : HandleWrap(env,
                   object,
                   reinterpret_cast<uv_handle_t*>(&process_),
                   AsyncWrap::PROVIDER_PROCESSWRAP) {
  }
  
  static bool isAsciiPgm(const char *pgm) {
    const char * pgmName = pgm;
    const char * AsciiPgms[] = { "git", "python2", "python", "make"};
    std::cmatch cm;
    std::regex absolutePath("^.*\/([^/]*)$");
    if (std::regex_match(pgmName,cm,absolutePath)) {
        pgmName = cm[1].str().c_str();
        if (cm.size() > 2) {
            return false;
            }
    } 

    for (int pgId = 0 ; pgId < sizeof(AsciiPgms) / sizeof(const char*); pgId++) {
       if (strcmp(pgmName,AsciiPgms[pgId]) == 0) {  
           return true;
       } 
    }
    return false;
  }

  static void ParseStdioOptions(Environment* env,
                                Local<Object> js_options,
                                uv_process_options_t* options) {
    Local<String> stdio_key = env->stdio_string();
    Local<Array> stdios = js_options->Get(stdio_key).As<Array>();

    uint32_t len = stdios->Length();
    options->stdio = new uv_stdio_container_t[len];
    options->stdio_count = len;
    bool ascii_output = isAsciiPgm(options->file);
    for (uint32_t i = 0; i < len; i++) {
      Local<Object> stdio = stdios->Get(i).As<Object>();
      Local<Value> type = stdio->Get(env->type_string());

      if (type->Equals(env->ignore_string())) {
        options->stdio[i].flags = UV_IGNORE;
      } else if (type->Equals(env->pipe_string())) {
        options->stdio[i].flags = static_cast<uv_stdio_flags>(
            UV_CREATE_PIPE | UV_READABLE_PIPE | UV_WRITABLE_PIPE);
        Local<String> handle_key = env->handle_string();
        Local<Object> handle = stdio->Get(handle_key).As<Object>();
        CHECK(!handle.IsEmpty());
        options->stdio[i].data.stream =
            reinterpret_cast<uv_stream_t*>(
                Unwrap<PipeWrap>(handle)->UVHandle());
        if (ascii_output && i > 0) {
          options->stdio[i].data.stream->ascii = true;
        }else{
          options->stdio[i].data.stream->ascii = false;
        }
      } else if (type->Equals(env->wrap_string())) {
        Local<String> handle_key = env->handle_string();
        Local<Object> handle = stdio->Get(handle_key).As<Object>();
        uv_stream_t* stream = HandleToStream(env, handle);
        CHECK_NE(stream, nullptr);

        options->stdio[i].flags = UV_INHERIT_STREAM;
        options->stdio[i].data.stream = stream;
        options->stdio[i].data.stream->ascii = false;
      } else {
        Local<String> fd_key = env->fd_string();
        int fd = static_cast<int>(stdio->Get(fd_key)->IntegerValue());
        options->stdio[i].flags = UV_INHERIT_FD;
        options->stdio[i].data.fd = fd;
      }
    }
  }

  static void Spawn(const FunctionCallbackInfo<Value>& args) {
    Environment* env = Environment::GetCurrent(args);

    ProcessWrap* wrap;
    ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());

    Local<Object> js_options = args[0]->ToObject(env->isolate());

    uv_process_options_t options;
    memset(&options, 0, sizeof(uv_process_options_t));

    options.exit_cb = OnExit;

    // options.uid
    Local<Value> uid_v = js_options->Get(env->uid_string());
    if (uid_v->IsInt32()) {
      const int32_t uid = uid_v->Int32Value(env->context()).FromJust();
      options.flags |= UV_PROCESS_SETUID;
      options.uid = static_cast<uv_uid_t>(uid);
    } else if (!uid_v->IsUndefined() && !uid_v->IsNull()) {
      return env->ThrowTypeError("\x6f\x70\x74\x69\x6f\x6e\x73\x2e\x75\x69\x64\x20\x73\x68\x6f\x75\x6c\x64\x20\x62\x65\x20\x61\x20\x6e\x75\x6d\x62\x65\x72");
    }

    // options.gid
    Local<Value> gid_v = js_options->Get(env->gid_string());
    if (gid_v->IsInt32()) {
      const int32_t gid = gid_v->Int32Value(env->context()).FromJust();
      options.flags |= UV_PROCESS_SETGID;
      options.gid = static_cast<uv_gid_t>(gid);
    } else if (!gid_v->IsUndefined() && !gid_v->IsNull()) {
      return env->ThrowTypeError("\x6f\x70\x74\x69\x6f\x6e\x73\x2e\x67\x69\x64\x20\x73\x68\x6f\x75\x6c\x64\x20\x62\x65\x20\x61\x20\x6e\x75\x6d\x62\x65\x72");
    }

    // TODO(bnoordhuis) is this possible to do without mallocing ?

    // options.file
    Local<Value> file_v = js_options->Get(env->file_string());
    node::BufferValue file(env->isolate(),
                         file_v->IsString() ? file_v : Local<Value>());
    if (file.length() > 0) {
      options.file = *file;
    } else {
      return env->ThrowTypeError("\x42\x61\x64\x20\x61\x72\x67\x75\x6d\x65\x6e\x74");
    }

    // options.args
    Local<Value> argv_v = js_options->Get(env->args_string());
    if (!argv_v.IsEmpty() && argv_v->IsArray()) {
      Local<Array> js_argv = Local<Array>::Cast(argv_v);
      int argc = js_argv->Length();
      CHECK_GT(argc + 1, 0);  // Check for overflow.

      // Heap allocate to detect errors. +1 is for nullptr.
      options.args = new char*[argc + 1];
      for (int i = 0; i < argc; i++) {
        node::Utf8Value arg(env->isolate(), js_argv->Get(i));
        options.args[i] = strdup(*arg);
        CHECK_NE(options.args[i], nullptr);
        __a2e_s(options.args[i]);
      }
      options.args[argc] = nullptr;
    }

    // options.cwd
    Local<Value> cwd_v = js_options->Get(env->cwd_string());
    node::BufferValue cwd(env->isolate(),
                        cwd_v->IsString() ? cwd_v : Local<Value>());
    if (cwd.length() > 0) {
      options.cwd = *cwd;
    }

    // options.env
    Local<Value> env_v = js_options->Get(env->env_pairs_string());
    if (!env_v.IsEmpty() && env_v->IsArray()) {
      Local<Array> env_opt = Local<Array>::Cast(env_v);
      int envc = env_opt->Length();
      CHECK_GT(envc + 1, 0);  // Check for overflow.
      options.env = new char*[envc + 1];  // Heap allocated to detect errors.
      for (int i = 0; i < envc; i++) {
        node::Utf8Value pair(env->isolate(), env_opt->Get(i));
        options.env[i] = strdup(*pair);
        CHECK_NE(options.env[i], nullptr);
        __a2e_s(options.env[i]);
      }
      options.env[envc] = nullptr;
    }

    // options.stdio
    ParseStdioOptions(env, js_options, &options);

    // options.windows_verbatim_arguments
    Local<String> windows_verbatim_arguments_key =
        env->windows_verbatim_arguments_string();
    if (js_options->Get(windows_verbatim_arguments_key)->IsTrue()) {
      options.flags |= UV_PROCESS_WINDOWS_VERBATIM_ARGUMENTS;
    }

    // options.detached
    Local<String> detached_key = env->detached_string();
    if (js_options->Get(detached_key)->IsTrue()) {
      options.flags |= UV_PROCESS_DETACHED;
    }

    int err = uv_spawn(env->event_loop(), &wrap->process_, &options);

    if (err == 0) {
      CHECK_EQ(wrap->process_.data, wrap);
      wrap->object()->Set(env->pid_string(),
                          Integer::New(env->isolate(), wrap->process_.pid));
    }

    if (options.args) {
      for (int i = 0; options.args[i]; i++) free(options.args[i]);
      delete [] options.args;
    }

    if (options.env) {
      for (int i = 0; options.env[i]; i++) free(options.env[i]);
      delete [] options.env;
    }

    delete[] options.stdio;

    args.GetReturnValue().Set(err);
  }

  static void Kill(const FunctionCallbackInfo<Value>& args) {
    ProcessWrap* wrap;
    ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());
    int signal = args[0]->Int32Value();
    int err = uv_process_kill(&wrap->process_, signal);
    args.GetReturnValue().Set(err);
  }

  static void OnExit(uv_process_t* handle,
                     int64_t exit_status,
                     int term_signal) {
    ProcessWrap* wrap = static_cast<ProcessWrap*>(handle->data);
    CHECK_NE(wrap, nullptr);
    CHECK_EQ(&wrap->process_, handle);

    Environment* env = wrap->env();
    HandleScope handle_scope(env->isolate());
    Context::Scope context_scope(env->context());

    Local<Value> argv[] = {
      Number::New(env->isolate(), static_cast<double>(exit_status)),
      OneByteString(env->isolate(), signo_string(term_signal))
    };

    wrap->MakeCallback(env->onexit_string(), arraysize(argv), argv);
  }

  uv_process_t process_;
};


}  // namespace node

NODE_MODULE_CONTEXT_AWARE_BUILTIN(process_wrap, node::ProcessWrap::Initialize)
