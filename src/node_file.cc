#include "node.h"
#include "node_file.h"
#include "node_buffer.h"
#include "node_internals.h"
#include "node_stat_watcher.h"

#include "env-inl.h"
#include "req-wrap-inl.h"
#include "string_bytes.h"
#include "util.h"

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#if defined(__MINGW32__) || defined(_MSC_VER)
# include <io.h>
#elif defined(__MVS__)
# include <unistd.h>
#endif

#include <vector>

namespace node {

using v8::Array;
using v8::ArrayBuffer;
using v8::Context;
using v8::EscapableHandleScope;
using v8::Float64Array;
using v8::Function;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::HandleScope;
using v8::Integer;
using v8::Local;
using v8::Number;
using v8::Object;
using v8::String;
using v8::Value;

#ifndef MIN
# define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#define TYPE_ERROR(msg) env->ThrowTypeError(msg)

#define GET_OFFSET(a) ((a)->IsNumber() ? (a)->IntegerValue() : -1)

class FSReqWrap: public ReqWrap<uv_fs_t> {
 public:
  enum Ownership { COPY, MOVE };

  inline static FSReqWrap* New(Environment* env,
                               Local<Object> req,
                               const char* syscall,
                               const char* data = nullptr,
                               enum encoding encoding = UTF8,
                               Ownership ownership = COPY);

  inline void Dispose();

  void ReleaseEarly() {
    if (data_ != inline_data()) {
      delete[] data_;
      data_ = nullptr;
    }
  }

  const char* syscall() const { return syscall_; }
  const char* data() const { return data_; }
  const enum encoding encoding_;

  size_t self_size() const override { return sizeof(*this); }

 private:
  FSReqWrap(Environment* env,
            Local<Object> req,
            const char* syscall,
            const char* data,
            enum encoding encoding)
      : ReqWrap(env, req, AsyncWrap::PROVIDER_FSREQWRAP),
        encoding_(encoding),
        syscall_(syscall),
        data_(data) {
    Wrap(object(), this);
  }

  ~FSReqWrap() { ReleaseEarly(); }

  void* operator new(size_t size) = delete;
  void* operator new(size_t size, char* storage) { return storage; }
  char* inline_data() { return reinterpret_cast<char*>(this + 1); }

  const char* syscall_;
  const char* data_;

  DISALLOW_COPY_AND_ASSIGN(FSReqWrap);
};

#define ASSERT_PATH(path)                                                   \
  if (*path == nullptr)                                                     \
    return TYPE_ERROR(  USTR(#path) "\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x20\x73\x74\x72\x69\x6e\x67\x20\x6f\x72\x20\x42\x75\x66\x66\x65\x72");

FSReqWrap* FSReqWrap::New(Environment* env,
                          Local<Object> req,
                          const char* syscall,
                          const char* data,
                          enum encoding encoding,
                          Ownership ownership) {
  const bool copy = (data != nullptr && ownership == COPY);
  const size_t size = copy ? 1 + strlen(data) : 0;
  FSReqWrap* that;
  char* const storage = new char[sizeof(*that) + size];
  that = new(storage) FSReqWrap(env, req, syscall, data, encoding);
  if (copy)
    that->data_ = static_cast<char*>(memcpy(that->inline_data(), data, size));
  return that;
}


void FSReqWrap::Dispose() {
  this->~FSReqWrap();
  delete[] reinterpret_cast<char*>(this);
}


static void NewFSReqWrap(const FunctionCallbackInfo<Value>& args) {
  CHECK(args.IsConstructCall());
}


static inline bool IsInt64(double x) {
  return x == static_cast<double>(static_cast<int64_t>(x));
}

static void After(uv_fs_t *req) {
  FSReqWrap* req_wrap = static_cast<FSReqWrap*>(req->data);
  CHECK_EQ(req_wrap->req(), req);
  req_wrap->ReleaseEarly();  // Free memory that's no longer used now.

  Environment* env = req_wrap->env();
  HandleScope handle_scope(env->isolate());
  Context::Scope context_scope(env->context());

  // there is always at least one argument. "error"
  int argc = 1;

  // Allocate space for two args. We may only use one depending on the case.
  // (Feel free to increase this if you need more)
  Local<Value> argv[2];
  Local<Value> link;

  if (req->result < 0) {
    // An error happened.
    argv[0] = UVException(env->isolate(),
                          req->result,
                          req_wrap->syscall(),
                          nullptr,
                          req->path,
                          req_wrap->data());
  } else {
    // error value is empty or null for non-error.
    argv[0] = Null(env->isolate());

    // All have at least two args now.
    argc = 2;

    switch (req->fs_type) {
      // These all have no data to pass.
      case UV_FS_ACCESS:
      case UV_FS_CLOSE:
      case UV_FS_RENAME:
      case UV_FS_UNLINK:
      case UV_FS_RMDIR:
      case UV_FS_MKDIR:
      case UV_FS_FTRUNCATE:
      case UV_FS_FSYNC:
      case UV_FS_FDATASYNC:
      case UV_FS_LINK:
      case UV_FS_SYMLINK:
      case UV_FS_CHMOD:
      case UV_FS_FCHMOD:
      case UV_FS_CHOWN:
      case UV_FS_FCHOWN:
        // These, however, don't.
        argc = 1;
        break;

      case UV_FS_UTIME:
      case UV_FS_FUTIME:
        argc = 0;
        break;

      case UV_FS_OPEN:
        argv[1] = Integer::New(env->isolate(), req->result);
        break;

      case UV_FS_WRITE:
        argv[1] = Integer::New(env->isolate(), req->result);
        break;

      case UV_FS_STAT:
      case UV_FS_LSTAT:
      case UV_FS_FSTAT:
        argv[1] = BuildStatsObject(env,
                                   static_cast<const uv_stat_t*>(req->ptr));
        break;

      case UV_FS_MKDTEMP:
        link = StringBytes::Encode(env->isolate(),
                                   static_cast<const char*>(req->path),
                                   req_wrap->encoding_);
        if (link.IsEmpty()) {
          argv[0] = UVException(env->isolate(),
                                UV_EINVAL,
                                req_wrap->syscall(),
                                "\x49\x6e\x76\x61\x6c\x69\x64\x20\x63\x68\x61\x72\x61\x63\x74\x65\x72\x20\x65\x6e\x63\x6f\x64\x69\x6e\x67\x20\x66\x6f\x72\x20\x66\x69\x6c\x65\x6e\x61\x6d\x65",
                                req->path,
                                req_wrap->data());
        } else {
          argv[1] = link;
        }
        break;

      case UV_FS_READLINK:

        link = StringBytes::Encode(env->isolate(),
                                   static_cast<const char*>(req->ptr),
                                   req_wrap->encoding_);
        if (link.IsEmpty()) {
          argv[0] = UVException(env->isolate(),
                                UV_EINVAL,
                                req_wrap->syscall(),
                                "\x49\x6e\x76\x61\x6c\x69\x64\x20\x63\x68\x61\x72\x61\x63\x74\x65\x72\x20\x65\x6e\x63\x6f\x64\x69\x6e\x67\x20\x66\x6f\x72\x20\x6c\x69\x6e\x6b",
                                req->path,
                                req_wrap->data());
        } else {
          argv[1] = link;
        }
        break;

      case UV_FS_REALPATH:
        link = StringBytes::Encode(env->isolate(),
                                   static_cast<const char*>(req->ptr),
                                   req_wrap->encoding_);
        if (link.IsEmpty()) {
          argv[0] = UVException(env->isolate(),
                                UV_EINVAL,
                                req_wrap->syscall(),
                                "\x49\x6e\x76\x61\x6c\x69\x64\x20\x63\x68\x61\x72\x61\x63\x74\x65\x72\x20\x65\x6e\x63\x6f\x64\x69\x6e\x67\x20\x66\x6f\x72\x20\x6c\x69\x6e\x6b",
                                req->path,
                                req_wrap->data());
        } else {
          argv[1] = link;
        }
        break;

      case UV_FS_READ:
        // Buffer interface
        argv[1] = Integer::New(env->isolate(), req->result);
        break;

      case UV_FS_SCANDIR:
        {
          int r;
          Local<Array> names = Array::New(env->isolate(), 0);
          Local<Function> fn = env->push_values_to_array_function();
          Local<Value> name_argv[NODE_PUSH_VAL_TO_ARRAY_MAX];
          size_t name_idx = 0;

          for (int i = 0; ; i++) {
            uv_dirent_t ent;

            r = uv_fs_scandir_next(req, &ent);
            if (r == UV_EOF)
              break;
            if (r != 0) {
              argv[0] = UVException(r,
                                    nullptr,
                                    req_wrap->syscall(),
                                    static_cast<const char*>(req->path));
              break;
            }

            Local<Value> filename = StringBytes::Encode(env->isolate(),
#ifdef __MVS__
                                                        *E2A(ent.name),
#else
                                                        ent.name,
#endif
                                                        req_wrap->encoding_);
            if (filename.IsEmpty()) {
              argv[0] = UVException(env->isolate(),
                                    UV_EINVAL,
                                    req_wrap->syscall(),
                                    "\x49\x6e\x76\x61\x6c\x69\x64\x20\x63\x68\x61\x72\x61\x63\x74\x65\x72\x20\x65\x6e\x63\x6f\x64\x69\x6e\x67\x20\x66\x6f\x72\x20\x66\x69\x6c\x65\x6e\x61\x6d\x65",
                                    req->path,
                                    req_wrap->data());
              break;
            }
            name_argv[name_idx++] = filename;

            if (name_idx >= arraysize(name_argv)) {
              fn->Call(env->context(), names, name_idx, name_argv)
                  .ToLocalChecked();
              name_idx = 0;
            }
          }

          if (name_idx > 0) {
            fn->Call(env->context(), names, name_idx, name_argv)
                .ToLocalChecked();
          }

          argv[1] = names;
        }
        break;

      default:
        CHECK(0 && "\x55\x6e\x68\x61\x6e\x64\x6c\x65\x64\x20\x65\x69\x6f\x20\x72\x65\x73\x70\x6f\x6e\x73\x65");
    }
  }

  req_wrap->MakeCallback(env->oncomplete_string(), argc, argv);

  uv_fs_req_cleanup(req_wrap->req());
  req_wrap->Dispose();
}

// This struct is only used on sync fs calls.
// For async calls FSReqWrap is used.
class fs_req_wrap {
 public:
  fs_req_wrap() {}
  ~fs_req_wrap() { uv_fs_req_cleanup(&req); }
  uv_fs_t req;

 private:
  DISALLOW_COPY_AND_ASSIGN(fs_req_wrap);
};


#define ASYNC_DEST_CALL(func, request, dest, encoding, ...)                   \
  Environment* env = Environment::GetCurrent(args);                           \
  CHECK(request->IsObject());                                                 \
  FSReqWrap* req_wrap = FSReqWrap::New(env, request.As<Object>(),             \
                                       USTR(#func), dest, encoding);                \
  int err = uv_fs_ ## func(env->event_loop(),                                 \
                           req_wrap->req(),                                   \
                           __VA_ARGS__,                                       \
                           After);                                            \
  req_wrap->Dispatched();                                                     \
  if (err < 0) {                                                              \
    uv_fs_t* uv_req = req_wrap->req();                                        \
    uv_req->result = err;                                                     \
    uv_req->path = nullptr;                                                   \
    After(uv_req);                                                            \
    req_wrap = nullptr;                                                       \
  } else {                                                                    \
    args.GetReturnValue().Set(req_wrap->persistent());                        \
  }

#define ASYNC_CALL(func, req, encoding, ...)                                  \
  ASYNC_DEST_CALL(func, req, nullptr, encoding, __VA_ARGS__)                  \

#define SYNC_DEST_CALL(func, path, dest, ...)                                 \
  fs_req_wrap req_wrap;                                                       \
  env->PrintSyncTrace();                                                      \
  int err = uv_fs_ ## func(env->event_loop(),                                 \
                         &req_wrap.req,                                       \
                         __VA_ARGS__,                                         \
                         nullptr);                                            \
  if (err < 0) {                                                              \
    return env->ThrowUVException(err, USTR(#func), nullptr, path, dest);      \
  }                                                                           \

#define SYNC_CALL(func, path, ...)                                            \
  SYNC_DEST_CALL(func, path, nullptr, __VA_ARGS__)                            \

#define SYNC_REQ req_wrap.req

#define SYNC_RESULT err

static void Access(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args.GetIsolate());
  HandleScope scope(env->isolate());

  if (args.Length() < 2)
    return TYPE_ERROR("\x70\x61\x74\x68\x20\x61\x6e\x64\x20\x6d\x6f\x64\x65\x20\x61\x72\x65\x20\x72\x65\x71\x75\x69\x72\x65\x64");
  if (!args[1]->IsInt32())
    return TYPE_ERROR("\x6d\x6f\x64\x65\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x6e\x20\x69\x6e\x74\x65\x67\x65\x72");

  BufferValue path(env->isolate(), args[0]);
  ASSERT_PATH(path)

  int mode = static_cast<int>(args[1]->Int32Value());

  if (args[2]->IsObject()) {
    ASYNC_CALL(access, args[2], EBCDIC, *path, mode);
  } else {
    SYNC_CALL(access, *path, *path, mode);
  }
}


static void Close(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  if (args.Length() < 1)
    return TYPE_ERROR("\x66\x64\x20\x69\x73\x20\x72\x65\x71\x75\x69\x72\x65\x64");
  if (!args[0]->IsInt32())
    return TYPE_ERROR("\x66\x64\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x20\x66\x69\x6c\x65\x20\x64\x65\x73\x63\x72\x69\x70\x74\x6f\x72");

  int fd = args[0]->Int32Value();

  if (args[1]->IsObject()) {
    ASYNC_CALL(close, args[1], EBCDIC, fd)
  } else {
    SYNC_CALL(close, 0, fd)
  }
}


Local<Value> BuildStatsObject(Environment* env, const uv_stat_t* s) {
  EscapableHandleScope handle_scope(env->isolate());

  // If you hit this assertion, you forgot to enter the v8::Context first.
  CHECK_EQ(env->context(), env->isolate()->GetCurrentContext());

  // The code below is very nasty-looking but it prevents a segmentation fault
  // when people run JS code like the snippet below. It's apparently more
  // common than you would expect, several people have reported this crash...
  //
  //   function crash() {
  //     fs.statSync('.');
  //     crash();
  //   }
  //
  // We need to check the return value of Number::New() and Date::New()
  // and make sure that we bail out when V8 returns an empty handle.

  // Numbers.
#define X(name)                                                               \
  Local<Value> name = Number::New(env->isolate(),                             \
                                  static_cast<double>(s->st_##name));         \
  if (name.IsEmpty())                                                         \
    return Local<Object>();                                                   \

  X(uid)
  X(gid)
  X(ino)
  X(size)
  X(dev)
  X(mode)
  X(nlink)
  X(rdev)
# if defined(__POSIX__)
  X(blksize)
  X(blocks)
# else
  Local<Value> blksize = Undefined(env->isolate());
  Local<Value> blocks = Undefined(env->isolate());
# endif
#undef X

  // Dates.
#define X(name)                                                               \
  Local<Value> name##_msec =                                                  \
    Number::New(env->isolate(),                                               \
        (static_cast<double>(s->st_##name.tv_sec) * 1000) +                   \
        (static_cast<double>(s->st_##name.tv_nsec / 1000000)));               \
                                                                              \
  if (name##_msec.IsEmpty())                                                  \
    return Local<Object>();                                                   \

  X(atim)
  X(mtim)
  X(ctim)
  X(birthtim)
#undef X

  // Pass stats as the first argument, this is the object we are modifying.
  Local<Value> argv[] = {
    dev,
    mode,
    nlink,
    uid,
    gid,
    rdev,
    blksize,
    ino,
    size,
    blocks,
    atim_msec,
    mtim_msec,
    ctim_msec,
    birthtim_msec
  };

  // Call out to JavaScript to create the stats object.
  Local<Value> stats =
      env->fs_stats_constructor_function()->NewInstance(
          env->context(),
          arraysize(argv),
          argv).FromMaybe(Local<Value>());

  if (stats.IsEmpty())
    return handle_scope.Escape(Local<Object>());

  return handle_scope.Escape(stats);
}

void FillStatsArray(double* fields, const uv_stat_t* s) {
  fields[0] = s->st_dev;
  fields[1] = s->st_mode;
  fields[2] = s->st_nlink;
  fields[3] = s->st_uid;
  fields[4] = s->st_gid;
  fields[5] = s->st_rdev;
#if defined(__POSIX__)
  fields[6] = s->st_blksize;
#else
  fields[6] = -1;
#endif
  fields[7] = s->st_ino;
  fields[8] = s->st_size;
#if defined(__POSIX__)
  fields[9] = s->st_blocks;
#else
  fields[9] = -1;
#endif
  // Dates.
#define X(idx, name)                                                          \
  fields[idx] = (static_cast<double>(s->st_##name.tv_sec) * 1000) +           \
                (static_cast<double>(s->st_##name.tv_nsec / 1000000));        \

  X(10, atim)
  X(11, mtim)
  X(12, ctim)
  X(13, birthtim)
#undef X
}

// Used to speed up module loading.  Returns the contents of the file as
// a string or undefined when the file cannot be opened.  The speedup
// comes from not creating Error objects on failure.
static void InternalModuleReadFile(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  uv_loop_t* loop = env->event_loop();

  CHECK(args[0]->IsString());
  node::BufferValue path(env->isolate(), args[0]);

  if (strlen(*path) != path.length())
    return;  // Contains a nul byte.

  uv_fs_t open_req;
  const int fd = uv_fs_open(loop, &open_req, *path, O_RDONLY, 0, nullptr);
  uv_fs_req_cleanup(&open_req);

  if (fd < 0) {
    return;
  }

  std::vector<char> chars;
  int64_t offset = 0;
  for (;;) {
    const size_t kBlockSize = 32 << 10;
    const size_t start = chars.size();
    chars.resize(start + kBlockSize);

    uv_buf_t buf;
    buf.base = &chars[start];
    buf.len = kBlockSize;

    uv_fs_t read_req;
    const ssize_t numchars =
        uv_fs_read(loop, &read_req, fd, &buf, 1, offset, nullptr);
    uv_fs_req_cleanup(&read_req);

    CHECK_GE(numchars, 0);
    if (static_cast<size_t>(numchars) < kBlockSize) {
      chars.resize(start + numchars);
    }
    if (numchars == 0) {
      break;
    }
    offset += numchars;
  }

  uv_fs_t close_req;
  CHECK_EQ(0, uv_fs_close(loop, &close_req, fd, nullptr));
  uv_fs_req_cleanup(&close_req);

  size_t start = 0;
  if (chars.size() >= 3 && 0 == memcmp(&chars[0], "\xEF\xBB\xBF", 3)) {
    start = 3;  // Skip UTF-8 BOM.
  }

  Local<String> chars_string =
      String::NewFromUtf8(env->isolate(),
                          &chars[start],
                          String::kNormalString,
                          chars.size() - start);
  args.GetReturnValue().Set(chars_string);
}

// Used to speed up module loading.  Returns 0 if the path refers to
// a file, 1 when it's a directory or < 0 on error (usually -ENOENT.)
// The speedup comes from not creating thousands of Stat and Error objects.
static void InternalModuleStat(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  CHECK(args[0]->IsString());
  BufferValue path(env->isolate(), args[0]);

  uv_fs_t req;
  int rc = uv_fs_stat(env->event_loop(), &req, *path, nullptr);
  if (rc == 0) {
    const uv_stat_t* const s = static_cast<const uv_stat_t*>(req.ptr);
#ifdef __MVS__
    rc = !!(S_ISDIR(s->st_mode));
#else
    rc = !!(s->st_mode & S_IFDIR);
#endif
  }
  uv_fs_req_cleanup(&req);

  args.GetReturnValue().Set(rc);
}

static void Stat(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  if (args.Length() < 1)
    return TYPE_ERROR("\x70\x61\x74\x68\x20\x72\x65\x71\x75\x69\x72\x65\x64");

  BufferValue path(env->isolate(), args[0]);
  ASSERT_PATH(path)

  if (args[1]->IsFloat64Array()) {
    Local<Float64Array> array = args[1].As<Float64Array>();
    CHECK_EQ(array->Length(), 14);
    Local<ArrayBuffer> ab = array->Buffer();
    double* fields = static_cast<double*>(ab->GetContents().Data());
    SYNC_CALL(stat, *path, *path)
    FillStatsArray(fields, static_cast<const uv_stat_t*>(SYNC_REQ.ptr));
  } else if (args[1]->IsObject()) {
#ifdef __MVS__
    ASYNC_CALL(stat, args[1], EBCDIC, *path)
#else
    ASYNC_CALL(stat, args[1], UTF8, *path)
#endif
  }
}

static void LStat(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  if (args.Length() < 1)
    return TYPE_ERROR("\x70\x61\x74\x68\x20\x72\x65\x71\x75\x69\x72\x65\x64");

  BufferValue path(env->isolate(), args[0]);
  ASSERT_PATH(path)

  if (args[1]->IsFloat64Array()) {
    Local<Float64Array> array = args[1].As<Float64Array>();
    CHECK_EQ(array->Length(), 14);
    Local<ArrayBuffer> ab = array->Buffer();
    double* fields = static_cast<double*>(ab->GetContents().Data());
    SYNC_CALL(lstat, *path, *path)
    FillStatsArray(fields, static_cast<const uv_stat_t*>(SYNC_REQ.ptr));
  } else if (args[1]->IsObject()) {
#ifdef __MVS__
    ASYNC_CALL(lstat, args[1], EBCDIC, *path)
#else
    ASYNC_CALL(lstat, args[1], UTF8, *path)
#endif
  }
}

static void FStat(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  if (args.Length() < 1)
    return TYPE_ERROR("\x66\x64\x20\x69\x73\x20\x72\x65\x71\x75\x69\x72\x65\x64");
  if (!args[0]->IsInt32())
    return TYPE_ERROR("\x66\x64\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x20\x66\x69\x6c\x65\x20\x64\x65\x73\x63\x72\x69\x70\x74\x6f\x72");

  int fd = args[0]->Int32Value();

  if (args[1]->IsFloat64Array()) {
    Local<Float64Array> array = args[1].As<Float64Array>();
    CHECK_EQ(array->Length(), 14);
    Local<ArrayBuffer> ab = array->Buffer();
    double* fields = static_cast<double*>(ab->GetContents().Data());
    SYNC_CALL(fstat, 0, fd)
    FillStatsArray(fields, static_cast<const uv_stat_t*>(SYNC_REQ.ptr));
  } else if (args[1]->IsObject()) {
#ifdef __MVS__
    ASYNC_CALL(fstat, args[1], EBCDIC, fd)
#else
    ASYNC_CALL(fstat, args[1], UTF8, fd)
#endif
  }
}

static void Symlink(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  int len = args.Length();
  if (len < 1)
    return TYPE_ERROR("\x74\x61\x72\x67\x65\x74\x20\x70\x61\x74\x68\x20\x72\x65\x71\x75\x69\x72\x65\x64");
  if (len < 2)
    return TYPE_ERROR("\x73\x72\x63\x20\x70\x61\x74\x68\x20\x72\x65\x71\x75\x69\x72\x65\x64");

  BufferValue target(env->isolate(), args[0]);
  ASSERT_PATH(target)
  BufferValue path(env->isolate(), args[1]);
  ASSERT_PATH(path)

  int flags = 0;

  if (args[2]->IsString()) {
    node::Utf8Value mode(env->isolate(), args[2]);
    if (strcmp(*mode, "\x64\x69\x72") == 0) {
      flags |= UV_FS_SYMLINK_DIR;
    } else if (strcmp(*mode, "\x6a\x75\x6e\x63\x74\x69\x6f\x6e") == 0) {
      flags |= UV_FS_SYMLINK_JUNCTION;
    } else if (strcmp(*mode, "\x66\x69\x6c\x65") != 0) {
      return env->ThrowError("\x55\x6e\x6b\x6e\x6f\x77\x6e\x20\x73\x79\x6d\x6c\x69\x6e\x6b\x20\x74\x79\x70\x65");
    }
  }

  if (args[3]->IsObject()) {
    ASYNC_DEST_CALL(symlink, args[3], *path, EBCDIC, *target, *path, flags)
  } else {
    SYNC_DEST_CALL(symlink, *target, *path, *target, *path, flags)
  }
}

static void Link(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  int len = args.Length();
  if (len < 1)
    return TYPE_ERROR("\x73\x72\x63\x20\x70\x61\x74\x68\x20\x72\x65\x71\x75\x69\x72\x65\x64");
  if (len < 2)
    return TYPE_ERROR("\x64\x65\x73\x74\x20\x70\x61\x74\x68\x20\x72\x65\x71\x75\x69\x72\x65\x64");

  BufferValue src(env->isolate(), args[0]);
  ASSERT_PATH(src)

  BufferValue dest(env->isolate(), args[1]);
  ASSERT_PATH(dest)

  if (args[2]->IsObject()) {
    ASYNC_DEST_CALL(link, args[2], *dest, EBCDIC, *src, *dest)
  } else {
    SYNC_DEST_CALL(link, *src, *dest, *src, *dest)
  }
}

static void ReadLink(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  const int argc = args.Length();

  if (argc < 1)
    return TYPE_ERROR("\x70\x61\x74\x68\x20\x72\x65\x71\x75\x69\x72\x65\x64");

  BufferValue path(env->isolate(), args[0]);
  ASSERT_PATH(path)

  const enum encoding encoding = ParseEncoding(env->isolate(), args[1], EBCDIC);

  Local<Value> callback = Null(env->isolate());
  if (argc == 3)
    callback = args[2];

  if (callback->IsObject()) {
    ASYNC_CALL(readlink, callback, encoding, *path)
  } else {
    SYNC_CALL(readlink, *path, *path)
    const char* link_path = static_cast<const char*>(SYNC_REQ.ptr);
    Local<Value> rc = StringBytes::Encode(env->isolate(),
                                          link_path,
                                          encoding);
    if (rc.IsEmpty()) {
      return env->ThrowUVException(UV_EINVAL,
                                   "\x72\x65\x61\x64\x6c\x69\x6e\x6b",
                                   "\x49\x6e\x76\x61\x6c\x69\x64\x20\x63\x68\x61\x72\x61\x63\x74\x65\x72\x20\x65\x6e\x63\x6f\x64\x69\x6e\x67\x20\x66\x6f\x72\x20\x6c\x69\x6e\x6b",
                                   *path);
    }
    args.GetReturnValue().Set(rc);
  }
}

static void Rename(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  int len = args.Length();
  if (len < 1)
    return TYPE_ERROR("\x6f\x6c\x64\x20\x70\x61\x74\x68\x20\x72\x65\x71\x75\x69\x72\x65\x64");
  if (len < 2)
    return TYPE_ERROR("\x6e\x65\x77\x20\x70\x61\x74\x68\x20\x72\x65\x71\x75\x69\x72\x65\x64");

  BufferValue old_path(env->isolate(), args[0]);
  ASSERT_PATH(old_path)
  BufferValue new_path(env->isolate(), args[1]);
  ASSERT_PATH(new_path)

  if (args[2]->IsObject()) {
    ASYNC_DEST_CALL(rename, args[2], *new_path, EBCDIC, *old_path, *new_path)
  } else {
    SYNC_DEST_CALL(rename, *old_path, *new_path, *old_path, *new_path)
  }
}

static void FTruncate(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  if (args.Length() < 2)
    return TYPE_ERROR("\x66\x64\x20\x61\x6e\x64\x20\x6c\x65\x6e\x67\x74\x68\x20\x61\x72\x65\x20\x72\x65\x71\x75\x69\x72\x65\x64");
  if (!args[0]->IsInt32())
    return TYPE_ERROR("\x66\x64\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x20\x66\x69\x6c\x65\x20\x64\x65\x73\x63\x72\x69\x70\x74\x6f\x72");

  int fd = args[0]->Int32Value();

  // FIXME(bnoordhuis) It's questionable to reject non-ints here but still
  // allow implicit coercion from null or undefined to zero.  Probably best
  // handled in lib/fs.js.
  Local<Value> len_v(args[1]);
  if (!len_v->IsUndefined() &&
      !len_v->IsNull() &&
      !IsInt64(len_v->NumberValue())) {
    return env->ThrowTypeError("\x4e\x6f\x74\x20\x61\x6e\x20\x69\x6e\x74\x65\x67\x65\x72");
  }

  const int64_t len = len_v->IntegerValue();

  if (args[2]->IsObject()) {
    ASYNC_CALL(ftruncate, args[2], EBCDIC, fd, len)
  } else {
    SYNC_CALL(ftruncate, 0, fd, len)
  }
}

static void Fdatasync(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  if (args.Length() < 1)
    return TYPE_ERROR("\x66\x64\x20\x69\x73\x20\x72\x65\x71\x75\x69\x72\x65\x64");
  if (!args[0]->IsInt32())
    return TYPE_ERROR("\x66\x64\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x20\x66\x69\x6c\x65\x20\x64\x65\x73\x63\x72\x69\x70\x74\x6f\x72");

  int fd = args[0]->Int32Value();

  if (args[1]->IsObject()) {
    ASYNC_CALL(fdatasync, args[1], EBCDIC, fd)
  } else {
    SYNC_CALL(fdatasync, 0, fd)
  }
}

static void Fsync(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  if (args.Length() < 1)
    return TYPE_ERROR("\x66\x64\x20\x69\x73\x20\x72\x65\x71\x75\x69\x72\x65\x64");
  if (!args[0]->IsInt32())
    return TYPE_ERROR("\x66\x64\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x20\x66\x69\x6c\x65\x20\x64\x65\x73\x63\x72\x69\x70\x74\x6f\x72");

  int fd = args[0]->Int32Value();

  if (args[1]->IsObject()) {
    ASYNC_CALL(fsync, args[1], EBCDIC, fd)
  } else {
    SYNC_CALL(fsync, 0, fd)
  }
}

static void Unlink(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  if (args.Length() < 1)
    return TYPE_ERROR("\x70\x61\x74\x68\x20\x72\x65\x71\x75\x69\x72\x65\x64");

  BufferValue path(env->isolate(), args[0]);
  ASSERT_PATH(path)

  if (args[1]->IsObject()) {
    ASYNC_CALL(unlink, args[1], EBCDIC, *path)
  } else {
    SYNC_CALL(unlink, *path, *path)
  }
}

static void RMDir(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  if (args.Length() < 1)
    return TYPE_ERROR("\x70\x61\x74\x68\x20\x72\x65\x71\x75\x69\x72\x65\x64");

  BufferValue path(env->isolate(), args[0]);
  ASSERT_PATH(path)

  if (args[1]->IsObject()) {
    ASYNC_CALL(rmdir, args[1], EBCDIC, *path)
  } else {
    SYNC_CALL(rmdir, *path, *path)
  }
}

static void MKDir(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  if (args.Length() < 2)
    return TYPE_ERROR("\x70\x61\x74\x68\x20\x61\x6e\x64\x20\x6d\x6f\x64\x65\x20\x61\x72\x65\x20\x72\x65\x71\x75\x69\x72\x65\x64");
  if (!args[1]->IsInt32())
    return TYPE_ERROR("\x6d\x6f\x64\x65\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x6e\x20\x69\x6e\x74\x65\x67\x65\x72");

  BufferValue path(env->isolate(), args[0]);
  ASSERT_PATH(path)

  int mode = static_cast<int>(args[1]->Int32Value());

  if (args[2]->IsObject()) {
    ASYNC_CALL(mkdir, args[2], EBCDIC, *path, mode)
  } else {
    SYNC_CALL(mkdir, *path, *path, mode)
  }
}

static void RealPath(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  const int argc = args.Length();

  if (argc < 1)
    return TYPE_ERROR("\x70\x61\x74\x68\x20\x72\x65\x71\x75\x69\x72\x65\x64");

  BufferValue path(env->isolate(), args[0]);
  ASSERT_PATH(path)

  const enum encoding encoding = ParseEncoding(env->isolate(), args[1], EBCDIC);

  Local<Value> callback = Null(env->isolate());
  if (argc == 3)
    callback = args[2];

  if (callback->IsObject()) {
    ASYNC_CALL(realpath, callback, encoding, *path);
  } else {
    SYNC_CALL(realpath, *path, *path);
    const char* link_path = static_cast<const char*>(SYNC_REQ.ptr);
    Local<Value> rc = StringBytes::Encode(env->isolate(),
                                          link_path,
                                          encoding);
    if (rc.IsEmpty()) {
      return env->ThrowUVException(UV_EINVAL,
                                   "\x72\x65\x61\x6c\x70\x61\x74\x68",
                                   "\x49\x6e\x76\x61\x6c\x69\x64\x20\x63\x68\x61\x72\x61\x63\x74\x65\x72\x20\x65\x6e\x63\x6f\x64\x69\x6e\x67\x20\x66\x6f\x72\x20\x70\x61\x74\x68",
                                   *path);
    }
    args.GetReturnValue().Set(rc);
  }
}

static void ReadDir(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  const int argc = args.Length();

  if (argc < 1)
    return TYPE_ERROR("\x70\x61\x74\x68\x20\x72\x65\x71\x75\x69\x72\x65\x64");

  BufferValue path(env->isolate(), args[0]);
  ASSERT_PATH(path)

  const enum encoding encoding = ParseEncoding(env->isolate(), args[1], UTF8);

  Local<Value> callback = Null(env->isolate());
  if (argc == 3)
    callback = args[2];

  if (callback->IsObject()) {
    ASYNC_CALL(scandir, callback, encoding, *path, 0 /*flags*/)
  } else {
    SYNC_CALL(scandir, *path, *path, 0 /*flags*/)

    CHECK_GE(SYNC_REQ.result, 0);
    int r;
    Local<Array> names = Array::New(env->isolate(), 0);
    Local<Function> fn = env->push_values_to_array_function();
    Local<Value> name_v[NODE_PUSH_VAL_TO_ARRAY_MAX];
    size_t name_idx = 0;

    for (int i = 0; ; i++) {
      uv_dirent_t ent;

      r = uv_fs_scandir_next(&SYNC_REQ, &ent);
      if (r == UV_EOF)
        break;
      if (r != 0)
        return env->ThrowUVException(r, "\x72\x65\x61\x64\x64\x69\x72\x75\x38", "", *path);

      Local<Value> filename = StringBytes::Encode(env->isolate(),
#ifdef __MVS__
                                                  *E2A(ent.name),
#else
                                                  ent.name,
#endif
                                                  encoding);
      if (filename.IsEmpty()) {
        return env->ThrowUVException(UV_EINVAL,
                                     "\x72\x65\x61\x64\x64\x69\x72",
                                     "\x49\x6e\x76\x61\x6c\x69\x64\x20\x63\x68\x61\x72\x61\x63\x74\x65\x72\x20\x65\x6e\x63\x6f\x64\x69\x6e\x67\x20\x66\x6f\x72\x20\x66\x69\x6c\x65\x6e\x61\x6d\x65",
                                     *path);
      }

      name_v[name_idx++] = filename;

      if (name_idx >= arraysize(name_v)) {
        fn->Call(env->context(), names, name_idx, name_v)
            .ToLocalChecked();
        name_idx = 0;
      }
    }

    if (name_idx > 0) {
      fn->Call(env->context(), names, name_idx, name_v).ToLocalChecked();
    }

    args.GetReturnValue().Set(names);
  }
}

static void Open(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  int len = args.Length();
  if (len < 1)
    return TYPE_ERROR("\x70\x61\x74\x68\x20\x72\x65\x71\x75\x69\x72\x65\x64");
  if (len < 2)
    return TYPE_ERROR("\x66\x6c\x61\x67\x73\x20\x72\x65\x71\x75\x69\x72\x65\x64");
  if (len < 3)
    return TYPE_ERROR("\x6d\x6f\x64\x65\x20\x72\x65\x71\x75\x69\x72\x65\x64");
  if (!args[1]->IsInt32())
    return TYPE_ERROR("\x66\x6c\x61\x67\x73\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x6e\x20\x69\x6e\x74");
  if (!args[2]->IsInt32())
    return TYPE_ERROR("\x6d\x6f\x64\x65\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x6e\x20\x69\x6e\x74");

  BufferValue path(env->isolate(), args[0]);
  ASSERT_PATH(path)

  int flags = args[1]->Int32Value();
  int mode = static_cast<int>(args[2]->Int32Value());

  if (args[3]->IsObject()) {
    ASYNC_CALL(open, args[3], EBCDIC, *path, flags, mode)
  } else {
    SYNC_CALL(open, *path, *path, flags, mode)
    args.GetReturnValue().Set(SYNC_RESULT);
  }
}


// Wrapper for write(2).
//
// bytesWritten = write(fd, buffer, offset, length, position, callback)
// 0 fd        integer. file descriptor
// 1 buffer    the data to write
// 2 offset    where in the buffer to start from
// 3 length    how much to write
// 4 position  if integer, position to write at in the file.
//             if null, write from the current position
static void WriteBuffer(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  if (!args[0]->IsInt32())
    return env->ThrowTypeError("\x46\x69\x72\x73\x74\x20\x61\x72\x67\x75\x6d\x65\x6e\x74\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x66\x69\x6c\x65\x20\x64\x65\x73\x63\x72\x69\x70\x74\x6f\x72");

  CHECK(Buffer::HasInstance(args[1]));

  int fd = args[0]->Int32Value();
  Local<Object> obj = args[1].As<Object>();
  const char* buf = Buffer::Data(obj);
  size_t buffer_length = Buffer::Length(obj);
  size_t off = args[2]->Uint32Value();
  size_t len = args[3]->Uint32Value();
  int64_t pos = GET_OFFSET(args[4]);
  Local<Value> req = args[5];

  if (off > buffer_length)
    return env->ThrowRangeError("\x6f\x66\x66\x73\x65\x74\x20\x6f\x75\x74\x20\x6f\x66\x20\x62\x6f\x75\x6e\x64\x73");
  if (len > buffer_length)
    return env->ThrowRangeError("\x6c\x65\x6e\x67\x74\x68\x20\x6f\x75\x74\x20\x6f\x66\x20\x62\x6f\x75\x6e\x64\x73");
  if (off + len < off)
    return env->ThrowRangeError("\x6f\x66\x66\x20\x2b\x20\x6c\x65\x6e\x20\x6f\x76\x65\x72\x66\x6c\x6f\x77");
  if (!Buffer::IsWithinBounds(off, len, buffer_length))
    return env->ThrowRangeError("\x6f\x66\x66\x20\x2b\x20\x6c\x65\x6e\x20\x3e\x20\x62\x75\x66\x66\x65\x72\x2e\x6c\x65\x6e\x67\x74\x68");

  buf += off;

  uv_buf_t uvbuf = uv_buf_init(const_cast<char*>(buf), len);

  if (req->IsObject()) {
    ASYNC_CALL(write, req, EBCDIC, fd, &uvbuf, 1, pos)
    return;
  }

  SYNC_CALL(write, nullptr, fd, &uvbuf, 1, pos)
  args.GetReturnValue().Set(SYNC_RESULT);
}


// Wrapper for writev(2).
//
// bytesWritten = writev(fd, chunks, position, callback)
// 0 fd        integer. file descriptor
// 1 chunks    array of buffers to write
// 2 position  if integer, position to write at in the file.
//             if null, write from the current position
static void WriteBuffers(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  CHECK(args[0]->IsInt32());
  CHECK(args[1]->IsArray());

  int fd = args[0]->Int32Value();
  Local<Array> chunks = args[1].As<Array>();
  int64_t pos = GET_OFFSET(args[2]);
  Local<Value> req = args[3];

  MaybeStackBuffer<uv_buf_t> iovs(chunks->Length());

  for (uint32_t i = 0; i < iovs.length(); i++) {
    Local<Value> chunk = chunks->Get(i);

    if (!Buffer::HasInstance(chunk))
      return env->ThrowTypeError("\x41\x72\x72\x61\x79\x20\x65\x6c\x65\x6d\x65\x6e\x74\x73\x20\x61\x6c\x6c\x20\x6e\x65\x65\x64\x20\x74\x6f\x20\x62\x65\x20\x62\x75\x66\x66\x65\x72\x73");

    iovs[i] = uv_buf_init(Buffer::Data(chunk), Buffer::Length(chunk));
  }

  if (req->IsObject()) {
    ASYNC_CALL(write, req, EBCDIC, fd, *iovs, iovs.length(), pos)
    return;
  }

  SYNC_CALL(write, nullptr, fd, *iovs, iovs.length(), pos)
  args.GetReturnValue().Set(SYNC_RESULT);
}


// Wrapper for write(2).
//
// bytesWritten = write(fd, string, position, enc, callback)
// 0 fd        integer. file descriptor
// 1 string    non-buffer values are converted to strings
// 2 position  if integer, position to write at in the file.
//             if null, write from the current position
// 3 enc       encoding of string
static void WriteString(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  if (!args[0]->IsInt32())
    return env->ThrowTypeError("\x46\x69\x72\x73\x74\x20\x61\x72\x67\x75\x6d\x65\x6e\x74\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x66\x69\x6c\x65\x20\x64\x65\x73\x63\x72\x69\x70\x74\x6f\x72");

  Local<Value> req;
  Local<Value> string = args[1];
  int fd = args[0]->Int32Value();
  char* buf = nullptr;
  int64_t pos;
  size_t len;
  FSReqWrap::Ownership ownership = FSReqWrap::COPY;

  // will assign buf and len if string was external
  if (!StringBytes::GetExternalParts(env->isolate(),
                                     string,
                                     const_cast<const char**>(&buf),
                                     &len)) {
    enum encoding enc = ParseEncoding(env->isolate(), args[3], UTF8);
    len = StringBytes::StorageSize(env->isolate(), string, enc);
    buf = new char[len];
    // StorageSize may return too large a char, so correct the actual length
    // by the write size
    len = StringBytes::Write(env->isolate(), buf, len, args[1], enc);
    ownership = FSReqWrap::MOVE;
  }
  pos = GET_OFFSET(args[2]);
  req = args[4];

  uv_buf_t uvbuf = uv_buf_init(const_cast<char*>(buf), len);

  if (!req->IsObject()) {
    // SYNC_CALL returns on error.  Make sure to always free the memory.
    struct Delete {
      inline explicit Delete(char* pointer) : pointer_(pointer) {}
      inline ~Delete() { delete[] pointer_; }
      char* const pointer_;
    };
    Delete delete_on_return(ownership == FSReqWrap::MOVE ? buf : nullptr);
    SYNC_CALL(write, nullptr, fd, &uvbuf, 1, pos)
    return args.GetReturnValue().Set(SYNC_RESULT);
  }

  FSReqWrap* req_wrap =
      FSReqWrap::New(env, req.As<Object>(), "\x77\x72\x69\x74\x65", buf, UTF8, ownership);
  int err = uv_fs_write(env->event_loop(),
                        req_wrap->req(),
                        fd,
                        &uvbuf,
                        1,
                        pos,
                        After);
  req_wrap->Dispatched();
  if (err < 0) {
    uv_fs_t* uv_req = req_wrap->req();
    uv_req->result = err;
    uv_req->path = nullptr;
    After(uv_req);
    return;
  }

  return args.GetReturnValue().Set(req_wrap->persistent());
}


/*
 * Wrapper for read(2).
 *
 * bytesRead = fs.read(fd, buffer, offset, length, position)
 *
 * 0 fd        integer. file descriptor
 * 1 buffer    instance of Buffer
 * 2 offset    integer. offset to start reading into inside buffer
 * 3 length    integer. length to read
 * 4 position  file position - null for current position
 *
 */
static void Read(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  if (args.Length() < 2)
    return TYPE_ERROR("\x66\x64\x20\x61\x6e\x64\x20\x62\x75\x66\x66\x65\x72\x20\x61\x72\x65\x20\x72\x65\x71\x75\x69\x72\x65\x64");
  if (!args[0]->IsInt32())
    return TYPE_ERROR("\x66\x64\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x20\x66\x69\x6c\x65\x20\x64\x65\x73\x63\x72\x69\x70\x74\x6f\x72");
  if (!Buffer::HasInstance(args[1]))
    return TYPE_ERROR("\x53\x65\x63\x6f\x6e\x64\x20\x61\x72\x67\x75\x6d\x65\x6e\x74\x20\x6e\x65\x65\x64\x73\x20\x74\x6f\x20\x62\x65\x20\x61\x20\x62\x75\x66\x66\x65\x72");

  int fd = args[0]->Int32Value();

  Local<Value> req;

  size_t len;
  int64_t pos;

  char * buf = nullptr;

  Local<Object> buffer_obj = args[1]->ToObject(env->isolate());
  char *buffer_data = Buffer::Data(buffer_obj);
  size_t buffer_length = Buffer::Length(buffer_obj);

  size_t off = args[2]->Int32Value();
  if (off >= buffer_length) {
    return env->ThrowError("\x4f\x66\x66\x73\x65\x74\x20\x69\x73\x20\x6f\x75\x74\x20\x6f\x66\x20\x62\x6f\x75\x6e\x64\x73");
  }

  len = args[3]->Int32Value();
  if (!Buffer::IsWithinBounds(off, len, buffer_length))
    return env->ThrowRangeError("\x4c\x65\x6e\x67\x74\x68\x20\x65\x78\x74\x65\x6e\x64\x73\x20\x62\x65\x79\x6f\x6e\x64\x20\x62\x75\x66\x66\x65\x72");

  pos = GET_OFFSET(args[4]);

  buf = buffer_data + off;

  uv_buf_t uvbuf = uv_buf_init(const_cast<char*>(buf), len);

  req = args[5];

  if (req->IsObject()) {
    ASYNC_CALL(read, req, UTF8, fd, &uvbuf, 1, pos);
  } else {
    SYNC_CALL(read, 0, fd, &uvbuf, 1, pos)
    args.GetReturnValue().Set(SYNC_RESULT);
  }
}


/* fs.chmod(path, mode);
 * Wrapper for chmod(1) / EIO_CHMOD
 */
static void Chmod(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  if (args.Length() < 2)
    return TYPE_ERROR("\x70\x61\x74\x68\x20\x61\x6e\x64\x20\x6d\x6f\x64\x65\x20\x61\x72\x65\x20\x72\x65\x71\x75\x69\x72\x65\x64");
  if (!args[1]->IsInt32())
    return TYPE_ERROR("\x6d\x6f\x64\x65\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x6e\x20\x69\x6e\x74\x65\x67\x65\x72");

  BufferValue path(env->isolate(), args[0]);
  ASSERT_PATH(path)

  int mode = static_cast<int>(args[1]->Int32Value());

  if (args[2]->IsObject()) {
    ASYNC_CALL(chmod, args[2], EBCDIC, *path, mode);
  } else {
    SYNC_CALL(chmod, *path, *path, mode);
  }
}


/* fs.fchmod(fd, mode);
 * Wrapper for fchmod(1) / EIO_FCHMOD
 */
static void FChmod(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  if (args.Length() < 2)
    return TYPE_ERROR("\x66\x64\x20\x61\x6e\x64\x20\x6d\x6f\x64\x65\x20\x61\x72\x65\x20\x72\x65\x71\x75\x69\x72\x65\x64");
  if (!args[0]->IsInt32())
    return TYPE_ERROR("\x66\x64\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x20\x66\x69\x6c\x65\x20\x64\x65\x73\x63\x72\x69\x70\x74\x6f\x72");
  if (!args[1]->IsInt32())
    return TYPE_ERROR("\x6d\x6f\x64\x65\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x6e\x20\x69\x6e\x74\x65\x67\x65\x72");

  int fd = args[0]->Int32Value();
  int mode = static_cast<int>(args[1]->Int32Value());

  if (args[2]->IsObject()) {
    ASYNC_CALL(fchmod, args[2], EBCDIC, fd, mode);
  } else {
    SYNC_CALL(fchmod, 0, fd, mode);
  }
}


/* fs.chown(path, uid, gid);
 * Wrapper for chown(1) / EIO_CHOWN
 */
static void Chown(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  int len = args.Length();
  if (len < 1)
    return TYPE_ERROR("\x70\x61\x74\x68\x20\x72\x65\x71\x75\x69\x72\x65\x64");
  if (len < 2)
    return TYPE_ERROR("\x75\x69\x64\x20\x72\x65\x71\x75\x69\x72\x65\x64");
  if (len < 3)
    return TYPE_ERROR("\x67\x69\x64\x20\x72\x65\x71\x75\x69\x72\x65\x64");
  if (!args[1]->IsUint32())
    return TYPE_ERROR("\x75\x69\x64\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x6e\x20\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\x74");
  if (!args[2]->IsUint32())
    return TYPE_ERROR("\x67\x69\x64\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x6e\x20\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\x74");

  BufferValue path(env->isolate(), args[0]);
  ASSERT_PATH(path)

  uv_uid_t uid = static_cast<uv_uid_t>(args[1]->Uint32Value());
  uv_gid_t gid = static_cast<uv_gid_t>(args[2]->Uint32Value());

  if (args[3]->IsObject()) {
    ASYNC_CALL(chown, args[3], EBCDIC, *path, uid, gid);
  } else {
    SYNC_CALL(chown, *path, *path, uid, gid);
  }
}


/* fs.fchown(fd, uid, gid);
 * Wrapper for fchown(1) / EIO_FCHOWN
 */
static void FChown(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  int len = args.Length();
  if (len < 1)
    return TYPE_ERROR("\x66\x64\x20\x72\x65\x71\x75\x69\x72\x65\x64");
  if (len < 2)
    return TYPE_ERROR("\x75\x69\x64\x20\x72\x65\x71\x75\x69\x72\x65\x64");
  if (len < 3)
    return TYPE_ERROR("\x67\x69\x64\x20\x72\x65\x71\x75\x69\x72\x65\x64");
  if (!args[0]->IsInt32())
    return TYPE_ERROR("\x66\x64\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x6e\x20\x69\x6e\x74");
  if (!args[1]->IsUint32())
    return TYPE_ERROR("\x75\x69\x64\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x6e\x20\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\x74");
  if (!args[2]->IsUint32())
    return TYPE_ERROR("\x67\x69\x64\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x6e\x20\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\x74");

  int fd = args[0]->Int32Value();
  uv_uid_t uid = static_cast<uv_uid_t>(args[1]->Uint32Value());
  uv_gid_t gid = static_cast<uv_gid_t>(args[2]->Uint32Value());

  if (args[3]->IsObject()) {
    ASYNC_CALL(fchown, args[3], EBCDIC, fd, uid, gid);
  } else {
    SYNC_CALL(fchown, 0, fd, uid, gid);
  }
}


static void UTimes(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  int len = args.Length();
  if (len < 1)
    return TYPE_ERROR("\x70\x61\x74\x68\x20\x72\x65\x71\x75\x69\x72\x65\x64");
  if (len < 2)
    return TYPE_ERROR("\x61\x74\x69\x6d\x65\x20\x72\x65\x71\x75\x69\x72\x65\x64");
  if (len < 3)
    return TYPE_ERROR("\x6d\x74\x69\x6d\x65\x20\x72\x65\x71\x75\x69\x72\x65\x64");
  if (!args[1]->IsNumber())
    return TYPE_ERROR("\x61\x74\x69\x6d\x65\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x20\x6e\x75\x6d\x62\x65\x72");
  if (!args[2]->IsNumber())
    return TYPE_ERROR("\x6d\x74\x69\x6d\x65\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x20\x6e\x75\x6d\x62\x65\x72");

  BufferValue path(env->isolate(), args[0]);
  ASSERT_PATH(path)

  const double atime = static_cast<double>(args[1]->NumberValue());
  const double mtime = static_cast<double>(args[2]->NumberValue());

  if (args[3]->IsObject()) {
    ASYNC_CALL(utime, args[3], EBCDIC, *path, atime, mtime);
  } else {
    SYNC_CALL(utime, *path, *path, atime, mtime);
  }
}

static void FUTimes(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  int len = args.Length();
  if (len < 1)
    return TYPE_ERROR("\x66\x64\x20\x72\x65\x71\x75\x69\x72\x65\x64");
  if (len < 2)
    return TYPE_ERROR("\x61\x74\x69\x6d\x65\x20\x72\x65\x71\x75\x69\x72\x65\x64");
  if (len < 3)
    return TYPE_ERROR("\x6d\x74\x69\x6d\x65\x20\x72\x65\x71\x75\x69\x72\x65\x64");
  if (!args[0]->IsInt32())
    return TYPE_ERROR("\x66\x64\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x6e\x20\x69\x6e\x74");
  if (!args[1]->IsNumber())
    return TYPE_ERROR("\x61\x74\x69\x6d\x65\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x20\x6e\x75\x6d\x62\x65\x72");
  if (!args[2]->IsNumber())
    return TYPE_ERROR("\x6d\x74\x69\x6d\x65\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x20\x6e\x75\x6d\x62\x65\x72");

  const int fd = args[0]->Int32Value();
  const double atime = static_cast<double>(args[1]->NumberValue());
  const double mtime = static_cast<double>(args[2]->NumberValue());

  if (args[3]->IsObject()) {
    ASYNC_CALL(futime, args[3], EBCDIC, fd, atime, mtime);
  } else {
    SYNC_CALL(futime, 0, fd, atime, mtime);
  }
}

static void Mkdtemp(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  CHECK_GE(args.Length(), 2);

  BufferValue tmpl(env->isolate(), args[0]);
  if (*tmpl == nullptr)
    return TYPE_ERROR("\x74\x65\x6d\x70\x6c\x61\x74\x65\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x61\x20\x73\x74\x72\x69\x6e\x67\x20\x6f\x72\x20\x42\x75\x66\x66\x65\x72");

  const enum encoding encoding = ParseEncoding(env->isolate(), args[1], EBCDIC);

  if (args[2]->IsObject()) {
    ASYNC_CALL(mkdtemp, args[2], encoding, *tmpl);
  } else {
    SYNC_CALL(mkdtemp, *tmpl, *tmpl);
    const char* path = static_cast<const char*>(SYNC_REQ.path);
    Local<Value> rc = StringBytes::Encode(env->isolate(), path, encoding);
    if (rc.IsEmpty()) {
      return env->ThrowUVException(UV_EINVAL,
                                   "\x6d\x6b\x64\x74\x65\x6d\x70",
                                   "\x49\x6e\x76\x61\x6c\x69\x64\x20\x63\x68\x61\x72\x61\x63\x74\x65\x72\x20\x65\x6e\x63\x6f\x64\x69\x6e\x67\x20\x66\x6f\x72\x20\x66\x69\x6c\x65\x6e\x61\x6d\x65",
                                   *tmpl);
    }
    args.GetReturnValue().Set(rc);
  }
}

void FSInitialize(const FunctionCallbackInfo<Value>& args) {
  Local<Function> stats_constructor = args[0].As<Function>();
  CHECK(stats_constructor->IsFunction());

  Environment* env = Environment::GetCurrent(args);
  env->set_fs_stats_constructor_function(stats_constructor);
}

void InitFs(Local<Object> target,
            Local<Value> unused,
            Local<Context> context,
            void* priv) {
  Environment* env = Environment::GetCurrent(context);

  // Function which creates a new Stats object.
  target->Set(FIXED_ONE_BYTE_STRING(env->isolate(), "\x46\x53\x49\x6e\x69\x74\x69\x61\x6c\x69\x7a\x65"),
              env->NewFunctionTemplate(FSInitialize)->GetFunction());

  env->SetMethod(target, "\x61\x63\x63\x65\x73\x73", Access);
  env->SetMethod(target, "\x63\x6c\x6f\x73\x65", Close);
  env->SetMethod(target, "\x6f\x70\x65\x6e", Open);
  env->SetMethod(target, "\x72\x65\x61\x64", Read);
  env->SetMethod(target, "\x66\x64\x61\x74\x61\x73\x79\x6e\x63", Fdatasync);
  env->SetMethod(target, "\x66\x73\x79\x6e\x63", Fsync);
  env->SetMethod(target, "\x72\x65\x6e\x61\x6d\x65", Rename);
  env->SetMethod(target, "\x66\x74\x72\x75\x6e\x63\x61\x74\x65", FTruncate);
  env->SetMethod(target, "\x72\x6d\x64\x69\x72", RMDir);
  env->SetMethod(target, "\x6d\x6b\x64\x69\x72", MKDir);
  env->SetMethod(target, "\x72\x65\x61\x64\x64\x69\x72", ReadDir);
  env->SetMethod(target, "\x69\x6e\x74\x65\x72\x6e\x61\x6c\x4d\x6f\x64\x75\x6c\x65\x52\x65\x61\x64\x46\x69\x6c\x65", InternalModuleReadFile);
  env->SetMethod(target, "\x69\x6e\x74\x65\x72\x6e\x61\x6c\x4d\x6f\x64\x75\x6c\x65\x53\x74\x61\x74", InternalModuleStat);
  env->SetMethod(target, "\x73\x74\x61\x74", Stat);
  env->SetMethod(target, "\x6c\x73\x74\x61\x74", LStat);
  env->SetMethod(target, "\x66\x73\x74\x61\x74", FStat);
  env->SetMethod(target, "\x6c\x69\x6e\x6b", Link);
  env->SetMethod(target, "\x73\x79\x6d\x6c\x69\x6e\x6b", Symlink);
  env->SetMethod(target, "\x72\x65\x61\x64\x6c\x69\x6e\x6b", ReadLink);
  env->SetMethod(target, "\x75\x6e\x6c\x69\x6e\x6b", Unlink);
  env->SetMethod(target, "\x77\x72\x69\x74\x65\x42\x75\x66\x66\x65\x72", WriteBuffer);
  env->SetMethod(target, "\x77\x72\x69\x74\x65\x42\x75\x66\x66\x65\x72\x73", WriteBuffers);
  env->SetMethod(target, "\x77\x72\x69\x74\x65\x53\x74\x72\x69\x6e\x67", WriteString);
  env->SetMethod(target, "\x72\x65\x61\x6c\x70\x61\x74\x68", RealPath);

  env->SetMethod(target, "\x63\x68\x6d\x6f\x64", Chmod);
  env->SetMethod(target, "\x66\x63\x68\x6d\x6f\x64", FChmod);
  // env->SetMethod(target, "lchmod", LChmod);

  env->SetMethod(target, "\x63\x68\x6f\x77\x6e", Chown);
  env->SetMethod(target, "\x66\x63\x68\x6f\x77\x6e", FChown);
  // env->SetMethod(target, "lchown", LChown);

  env->SetMethod(target, "\x75\x74\x69\x6d\x65\x73", UTimes);
  env->SetMethod(target, "\x66\x75\x74\x69\x6d\x65\x73", FUTimes);

  env->SetMethod(target, "\x6d\x6b\x64\x74\x65\x6d\x70", Mkdtemp);

  StatWatcher::Initialize(env, target);

  // Create FunctionTemplate for FSReqWrap
  Local<FunctionTemplate> fst =
      FunctionTemplate::New(env->isolate(), NewFSReqWrap);
  fst->InstanceTemplate()->SetInternalFieldCount(1);
  fst->SetClassName(FIXED_ONE_BYTE_STRING(env->isolate(), "\x46\x53\x52\x65\x71\x57\x72\x61\x70"));
  target->Set(FIXED_ONE_BYTE_STRING(env->isolate(), "\x46\x53\x52\x65\x71\x57\x72\x61\x70"),
              fst->GetFunction());
}

}  // end namespace node

NODE_MODULE_CONTEXT_AWARE_BUILTIN(fs, node::InitFs)
