#ifndef SRC_INSPECTOR_AGENT_H_
#define SRC_INSPECTOR_AGENT_H_

#if !HAVE_INSPECTOR
#error("\x54\x68\x69\x73\x20\x68\x65\x61\x64\x65\x72\x20\x63\x61\x6e\x20\x6f\x6e\x6c\x79\x20\x62\x65\x20\x75\x73\x65\x64\x20\x77\x68\x65\x6e\x20\x69\x6e\x73\x70\x65\x63\x74\x6f\x72\x20\x69\x73\x20\x65\x6e\x61\x62\x6c\x65\x64")
#endif

// Forward declaration to break recursive dependency chain with src/env.h.
namespace node {
class Environment;
}  // namespace node

namespace v8 {
class Platform;
template<typename T>
class Local;
class Value;
class Message;
}  // namespace v8

namespace node {
namespace inspector {

class AgentImpl;

class Agent {
 public:
  explicit Agent(node::Environment* env);
  ~Agent();

  // Start the inspector agent thread
  bool Start(v8::Platform* platform, const char* path,
             const char* address, int port, bool wait);
  // Stop the inspector agent
  void Stop();

  bool IsStarted();
  bool IsConnected();
  void WaitForDisconnect();

  void FatalException(v8::Local<v8::Value> error,
                      v8::Local<v8::Message> message);
 private:
  AgentImpl* impl;
};

}  // namespace inspector
}  // namespace node

#endif  // SRC_INSPECTOR_AGENT_H_
