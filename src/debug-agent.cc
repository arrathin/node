// Copyright Fedor Indutny and other Node contributors.
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

#include "debug-agent.h"

#include "node.h"
#include "node_internals.h"  // arraysize
#include "env-inl.h"
#include "v8.h"
#include "v8-debug.h"
#include "util-inl.h"

#include <string.h>
#include <algorithm>

namespace node {
namespace debugger {

using v8::Context;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::HandleScope;
using v8::Integer;
using v8::Isolate;
using v8::Local;
using v8::Locker;
using v8::NewStringType;
using v8::Object;
using v8::String;
using v8::Value;

std::vector<uv_sem_t> Agent::system_ipc;

Agent::Agent(Environment* env) : state_(kNone),
                                 port_(5858),
                                 wait_(false),
                                 parent_env_(env),
                                 child_env_(nullptr),
                                 dispatch_handler_(nullptr) {
  CHECK_EQ(0, uv_sem_init(&start_sem_, 0));

#ifdef __MVS__
  system_ipc.push_back(start_sem_);
#endif

}


Agent::~Agent() {
  Stop();

  system_ipc.erase(std::remove(system_ipc.begin(), system_ipc.end(), start_sem_),
            system_ipc.end());
  uv_sem_destroy(&start_sem_);

  while (AgentMessage* msg = messages_.PopFront())
    delete msg;
}


bool Agent::Start(const std::string& host, int port, bool wait) {
  int err;

  if (state_ == kRunning)
    return false;

  err = uv_loop_init(&child_loop_);
  if (err != 0)
    goto loop_init_failed;

  // Interruption signal handler
  err = uv_async_init(&child_loop_, &child_signal_, ChildSignalCb);
  if (err != 0)
    goto async_init_failed;
  uv_unref(reinterpret_cast<uv_handle_t*>(&child_signal_));

  host_ = host;
  port_ = port;
  wait_ = wait;

  err = uv_thread_create(&thread_,
                         reinterpret_cast<uv_thread_cb>(ThreadCb),
                         this);
  if (err != 0)
    goto thread_create_failed;

  uv_sem_wait(&start_sem_);

  state_ = kRunning;

  return true;

 thread_create_failed:
  uv_close(reinterpret_cast<uv_handle_t*>(&child_signal_), nullptr);

 async_init_failed:
  err = uv_loop_close(&child_loop_);
  CHECK_EQ(err, 0);

 loop_init_failed:
  return false;
}


void Agent::Enable() {
  v8::Debug::SetMessageHandler(parent_env()->isolate(), MessageHandler);

  // Assign environment to the debugger's context
  // NOTE: The debugger context is created after `SetMessageHandler()` call
  auto debug_context = v8::Debug::GetDebugContext(parent_env()->isolate());
  parent_env()->AssignToContext(debug_context);
}


void Agent::Stop() {
  int err;

  if (state_ != kRunning) {
    return;
  }

  v8::Debug::SetMessageHandler(parent_env()->isolate(), nullptr);

  // Send empty message to terminate things
  EnqueueMessage(new AgentMessage(nullptr, 0));

  // Signal worker thread to make it stop
  err = uv_async_send(&child_signal_);
  CHECK_EQ(err, 0);

  err = uv_thread_join(&thread_);
  CHECK_EQ(err, 0);

  uv_close(reinterpret_cast<uv_handle_t*>(&child_signal_), nullptr);
  uv_run(&child_loop_, UV_RUN_NOWAIT);

  err = uv_loop_close(&child_loop_);
  CHECK_EQ(err, 0);

  state_ = kNone;
}


void Agent::WorkerRun() {
  static const char* argv[] = { "\x6e\x6f\x64\x65\x75\x38", "\x2d\x2d\x64\x65\x62\x75\x67\x2d\x61\x67\x65\x6e\x74" };
  Isolate::CreateParams params;
  ArrayBufferAllocator array_buffer_allocator;
  params.array_buffer_allocator = &array_buffer_allocator;
  Isolate* isolate = Isolate::New(params);
  {
    Locker locker(isolate);
    Isolate::Scope isolate_scope(isolate);

    HandleScope handle_scope(isolate);
    Local<Context> context = Context::New(isolate);

    Context::Scope context_scope(context);
    Environment* env = CreateEnvironment(
        isolate,
        &child_loop_,
        context,
        arraysize(argv),
        argv,
        arraysize(argv),
        argv);

    child_env_ = env;

    // Expose API
    InitAdaptor(env);
    LoadEnvironment(env);

    CHECK_EQ(&child_loop_, env->event_loop());
    uv_run(&child_loop_, UV_RUN_DEFAULT);

    // Clean-up peristent
    api_.Reset();

    // Clean-up all running handles
    env->CleanupHandles();

    env->Dispose();
    env = nullptr;
  }
  isolate->Dispose();
}


void Agent::InitAdaptor(Environment* env) {
  Isolate* isolate = env->isolate();
  HandleScope scope(isolate);

  // Create API adaptor
  Local<FunctionTemplate> t = FunctionTemplate::New(isolate);
  t->InstanceTemplate()->SetInternalFieldCount(1);
  t->SetClassName(String::NewFromUtf8(isolate, "\x44\x65\x62\x75\x67\x41\x50\x49"));

  NODE_SET_PROTOTYPE_METHOD(t, "\x6e\x6f\x74\x69\x66\x79\x4c\x69\x73\x74\x65\x6e", NotifyListen);
  NODE_SET_PROTOTYPE_METHOD(t, "\x6e\x6f\x74\x69\x66\x79\x57\x61\x69\x74", NotifyWait);
  NODE_SET_PROTOTYPE_METHOD(t, "\x73\x65\x6e\x64\x43\x6f\x6d\x6d\x61\x6e\x64", SendCommand);

  Local<Object> api =
      t->GetFunction()->NewInstance(env->context()).ToLocalChecked();
  api->SetAlignedPointerInInternalField(0, this);

  api->Set(String::NewFromUtf8(isolate, "\x68\x6f\x73\x74",
                               NewStringType::kNormal).ToLocalChecked(),
           String::NewFromUtf8(isolate, host_.data(), NewStringType::kNormal,
                               host_.size()).ToLocalChecked());
  api->Set(String::NewFromUtf8(isolate, "\x70\x6f\x72\x74"), Integer::New(isolate, port_));

  env->process_object()->Set(String::NewFromUtf8(isolate, "\x5f\x64\x65\x62\x75\x67\x41\x50\x49"), api);
  api_.Reset(env->isolate(), api);
}


Agent* Agent::Unwrap(const v8::FunctionCallbackInfo<v8::Value>& args) {
  void* ptr = args.Holder()->GetAlignedPointerFromInternalField(0);
  return reinterpret_cast<Agent*>(ptr);
}


void Agent::NotifyListen(const FunctionCallbackInfo<Value>& args) {
  Agent* a = Unwrap(args);

  // Notify other thread that we are ready to process events
  uv_sem_post(&a->start_sem_);
}


void Agent::NotifyWait(const FunctionCallbackInfo<Value>& args) {
  Agent* a = Unwrap(args);

  a->wait_ = false;

  int err = uv_async_send(&a->child_signal_);
  CHECK_EQ(err, 0);
}


void Agent::SendCommand(const FunctionCallbackInfo<Value>& args) {
  Agent* a = Unwrap(args);
  Environment* env = a->child_env();
  HandleScope scope(env->isolate());

  String::Value v(args[0]);

  v8::Debug::SendCommand(a->parent_env()->isolate(), *v, v.length());
  if (a->dispatch_handler_ != nullptr)
    a->dispatch_handler_(a->parent_env());
}


void Agent::ThreadCb(Agent* agent) {
  agent->WorkerRun();
}


void Agent::ChildSignalCb(uv_async_t* signal) {
  Agent* a = ContainerOf(&Agent::child_signal_, signal);
  Isolate* isolate = a->child_env()->isolate();

  HandleScope scope(isolate);
  Local<Object> api = PersistentToLocal(isolate, a->api_);

  Mutex::ScopedLock scoped_lock(a->message_mutex_);
  while (AgentMessage* msg = a->messages_.PopFront()) {
    // Time to close everything
    if (msg->data() == nullptr) {
      delete msg;

      MakeCallback(isolate, api, "\x6f\x6e\x63\x6c\x6f\x73\x65", 0, nullptr);
      break;
    }

    // Waiting for client, do not send anything just yet
    if (a->wait_) {
      a->messages_.PushFront(msg);  // Push message back into the ready queue.
      break;
    }

    Local<Value> argv[] = {
      String::NewFromTwoByte(isolate,
                             msg->data(),
                             String::kNormalString,
                             msg->length())
    };

    // Emit message
    MakeCallback(isolate,
                 api,
                 "\x6f\x6e\x6d\x65\x73\x73\x61\x67\x65",
                 arraysize(argv),
                 argv);
    delete msg;
  }
}


void Agent::EnqueueMessage(AgentMessage* message) {
  Mutex::ScopedLock scoped_lock(message_mutex_);
  messages_.PushBack(message);
  uv_async_send(&child_signal_);
}


void Agent::MessageHandler(const v8::Debug::Message& message) {
  Isolate* isolate = message.GetIsolate();
  Environment* env = Environment::GetCurrent(isolate);
  if (env == nullptr)
    return;  // Called from a non-node context.
  Agent* a = env->debugger_agent();
  CHECK_NE(a, nullptr);
  CHECK_EQ(isolate, a->parent_env()->isolate());

  HandleScope scope(isolate);
  Local<String> json = message.GetJSON();
  String::Value v(json);

  AgentMessage* msg = new AgentMessage(*v, v.length());
  a->EnqueueMessage(msg);
}


}  // namespace debugger
}  // namespace node
