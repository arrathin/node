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

#include "node_dtrace.h"
#include "node_win32_etw_provider.h"
#include "node_etw_provider.h"
#include "node_win32_etw_provider-inl.h"

namespace node {

using v8::JitCodeEvent;
using v8::V8;

HMODULE advapi;
REGHANDLE node_provider;
EventRegisterFunc event_register;
EventUnregisterFunc event_unregister;
EventWriteFunc event_write;
int events_enabled;
static uv_async_t dispatch_etw_events_change_async;

struct v8tags {
  char prefix[32 - sizeof(size_t)];
  size_t prelen;
};

// The v8 CODE_ADDED event name has a prefix indicating the type of event.
// Many of these are internal to v8.
// The trace_codes array specifies which types are written.
struct v8tags trace_codes[] = {
#define MAKE_V8TAG(s) { s, sizeof(s) - 1 }
  MAKE_V8TAG("\x4c\x61\x7a\x79\x43\x6f\x6d\x70\x69\x6c\x65\x3a"),
  MAKE_V8TAG("\x53\x63\x72\x69\x70\x74\x3a"),
  MAKE_V8TAG("\x46\x75\x6e\x63\x74\x69\x6f\x6e\x3a"),
  MAKE_V8TAG("\x52\x65\x67\x45\x78\x70\x3a"),
  MAKE_V8TAG("\x45\x76\x61\x6c\x3a")
#undef MAKE_V8TAG
};

/* Below are some code prefixes which are not being written.
 *    "Builtin:"
 *    "Stub:"
 *    "CallIC:"
 *    "LoadIC:"
 *    "KeyedLoadIC:"
 *    "StoreIC:"
 *    "KeyedStoreIC:"
 *    "CallPreMonomorphic:"
 *    "CallInitialize:"
 *    "CallMiss:"
 *    "CallMegamorphic:"
 */

// v8 sometimes puts a '*' or '~' in front of the name.
#define V8_MARKER1 '\x2a'
#define V8_MARKER2 '\x7e'


// If prefix is not in filtered list return -1,
// else return length of prefix and marker.
int FilterCodeEvents(const char* name, size_t len) {
  for (int i = 0; i < ARRAY_SIZE(trace_codes); i++) {
    size_t prelen = trace_codes[i].prelen;
    if (prelen < len) {
      if (strncmp(name, trace_codes[i].prefix, prelen) == 0) {
        if (name[prelen] == V8_MARKER1 || name[prelen] == V8_MARKER2)
          prelen++;
        return prelen;
      }
    }
  }
  return -1;
}


// callback from V8 module passes symbol and address info for stack walk
void CodeAddressNotification(const JitCodeEvent* jevent) {
  int pre_offset = 0;
  if (NODE_V8SYMBOL_ENABLED()) {
    switch (jevent->type) {
    case JitCodeEvent::CODE_ADDED:
      pre_offset = FilterCodeEvents(jevent->name.str, jevent->name.len);
      if (pre_offset >= 0) {
        // skip over prefix and marker
        NODE_V8SYMBOL_ADD(jevent->name.str + pre_offset,
                          jevent->name.len - pre_offset,
                          jevent->code_start,
                          jevent->code_len);
      }
      break;
    case JitCodeEvent::CODE_REMOVED:
      NODE_V8SYMBOL_REMOVE(jevent->code_start, 0);
      break;
    case JitCodeEvent::CODE_MOVED:
      NODE_V8SYMBOL_MOVE(jevent->code_start, jevent->new_code_start);
      break;
    default:
      break;
    }
  }
}


// Call v8 to enable or disable code event callbacks.
// Must be on default thread to do this.
// Note: It is possible to call v8 from ETW thread, but then
//       event callbacks are received in the same thread. Attempts
//       to write ETW events in this thread will fail.
void etw_events_change_async(uv_async_t* handle) {
  if (events_enabled > 0) {
    NODE_V8SYMBOL_RESET();
    V8::SetJitCodeEventHandler(v8::kJitCodeEventEnumExisting,
                               CodeAddressNotification);
  } else {
    V8::SetJitCodeEventHandler(v8::kJitCodeEventDefault, NULL);
  }
}


// This callback is called by ETW when consumers of our provider
// are enabled or disabled.
// The callback is dispatched on ETW thread.
// Before calling into V8 to enable code events, switch to default thread.
void NTAPI etw_events_enable_callback(
  LPCGUID SourceId,
  ULONG IsEnabled,
  UCHAR Level,
  ULONGLONG MatchAnyKeyword,
  ULONGLONG MatchAllKeywords,
  PEVENT_FILTER_DESCRIPTOR FilterData,
  PVOID CallbackContext) {
  if (IsEnabled) {
    events_enabled++;
    if (events_enabled == 1) {
      uv_async_send(&dispatch_etw_events_change_async);
    }
  } else {
    events_enabled--;
    if (events_enabled == 0) {
      uv_async_send(&dispatch_etw_events_change_async);
    }
  }
}


void init_etw() {
  events_enabled = 0;

  advapi = LoadLibrary("\x61\x64\x76\x61\x70\x69\x33\x32\x2e\x64\x6c\x6c");
  if (advapi) {
    event_register = (EventRegisterFunc)
      GetProcAddress(advapi, "\x45\x76\x65\x6e\x74\x52\x65\x67\x69\x73\x74\x65\x72");
    event_unregister = (EventUnregisterFunc)
      GetProcAddress(advapi, "\x45\x76\x65\x6e\x74\x55\x6e\x72\x65\x67\x69\x73\x74\x65\x72");
    event_write = (EventWriteFunc)GetProcAddress(advapi, "\x45\x76\x65\x6e\x74\x57\x72\x69\x74\x65");

    // create async object used to invoke main thread from callback
    uv_async_init(uv_default_loop(),
                  &dispatch_etw_events_change_async,
                  etw_events_change_async);
    uv_unref(reinterpret_cast<uv_handle_t*>(&dispatch_etw_events_change_async));

    if (event_register) {
      DWORD status = event_register(&NODE_ETW_PROVIDER,
                                    etw_events_enable_callback,
                                    NULL,
                                    &node_provider);
      assert(status == ERROR_SUCCESS);
    }
  }
}


void shutdown_etw() {
  if (advapi && event_unregister && node_provider) {
    event_unregister(node_provider);
    node_provider = 0;
  }

  events_enabled = 0;
  V8::SetJitCodeEventHandler(v8::kJitCodeEventDefault, NULL);

  if (advapi) {
    FreeLibrary(advapi);
    advapi = NULL;
  }
}
}
