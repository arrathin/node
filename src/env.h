#ifndef SRC_ENV_H_
#define SRC_ENV_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "ares.h"
#include "debug-agent.h"
#if HAVE_INSPECTOR
#include "inspector_agent.h"
#endif
#include "handle_wrap.h"
#include "req-wrap.h"
#include "tree.h"
#include "util.h"
#include "uv.h"
#include "v8.h"

#include <stdint.h>
#include <vector>

// Caveat emptor: we're going slightly crazy with macros here but the end
// hopefully justifies the means. We have a lot of per-context properties
// and adding and maintaining their getters and setters by hand would be
// a nightmare so let's make the preprocessor generate them for us.
//
// Make sure that any macros defined here are undefined again at the bottom
// of context-inl.h. The exceptions are NODE_CONTEXT_EMBEDDER_DATA_INDEX
// and NODE_ISOLATE_SLOT, they may have been defined externally.
namespace node {

// Pick an index that's hopefully out of the way when we're embedded inside
// another application. Performance-wise or memory-wise it doesn't matter:
// Context::SetAlignedPointerInEmbedderData() is backed by a FixedArray,
// worst case we pay a one-time penalty for resizing the array.
#ifndef NODE_CONTEXT_EMBEDDER_DATA_INDEX
#define NODE_CONTEXT_EMBEDDER_DATA_INDEX 32
#endif

// The slot 0 and 1 had already been taken by "gin" and "blink" in Chrome,
// and the size of isolate's slots is 4 by default, so using 3 should
// hopefully make node work independently when embedded into other
// application.
#ifndef NODE_ISOLATE_SLOT
#define NODE_ISOLATE_SLOT 3
#endif

// The number of items passed to push_values_to_array_function has diminishing
// returns around 8. This should be used at all call sites using said function.
#ifndef NODE_PUSH_VAL_TO_ARRAY_MAX
#define NODE_PUSH_VAL_TO_ARRAY_MAX 8
#endif

// Private symbols are per-isolate primitives but Environment proxies them
// for the sake of convenience.  Strings should be ASCII-only and have a
// "node:" prefix to avoid name clashes with third-party code.
#define PER_ISOLATE_PRIVATE_SYMBOL_PROPERTIES(V)                              \
  V(alpn_buffer_private_symbol, "\x6e\x6f\x64\x65\x3a\x61\x6c\x70\x6e\x42\x75\x66\x66\x65\x72")                            \
  V(arrow_message_private_symbol, "\x6e\x6f\x64\x65\x3a\x61\x72\x72\x6f\x77\x4d\x65\x73\x73\x61\x67\x65")                        \
  V(contextify_context_private_symbol, "\x6e\x6f\x64\x65\x3a\x63\x6f\x6e\x74\x65\x78\x74\x69\x66\x79\x3a\x63\x6f\x6e\x74\x65\x78\x74")             \
  V(contextify_global_private_symbol, "\x6e\x6f\x64\x65\x3a\x63\x6f\x6e\x74\x65\x78\x74\x69\x66\x79\x3a\x67\x6c\x6f\x62\x61\x6c")               \
  V(decorated_private_symbol, "\x6e\x6f\x64\x65\x3a\x64\x65\x63\x6f\x72\x61\x74\x65\x64")                               \
  V(npn_buffer_private_symbol, "\x6e\x6f\x64\x65\x3a\x6e\x70\x6e\x42\x75\x66\x66\x65\x72")                              \
  V(processed_private_symbol, "\x6e\x6f\x64\x65\x3a\x70\x72\x6f\x63\x65\x73\x73\x65\x64")                               \
  V(selected_npn_buffer_private_symbol, "\x6e\x6f\x64\x65\x3a\x73\x65\x6c\x65\x63\x74\x65\x64\x4e\x70\x6e\x42\x75\x66\x66\x65\x72")             \
  V(napi_env, "\x6e\x6f\x64\x65\x3a\x6e\x61\x70\x69\x3a\x65\x6e\x76")                                                \
  V(napi_wrapper, "\x6e\x6f\x64\x65\x3a\x6e\x61\x70\x69\x3a\x77\x72\x61\x70\x70\x65\x72")                                        \

// Strings are per-isolate primitives but Environment proxies them
// for the sake of convenience.  Strings should be ASCII-only.
#define PER_ISOLATE_STRING_PROPERTIES(V)                                      \
  V(address_string, "\x61\x64\x64\x72\x65\x73\x73")                                                \
  V(args_string, "\x61\x72\x67\x73")                                                      \
  V(async, "\x61\x73\x79\x6e\x63")                                                           \
  V(async_queue_string, "\x5f\x61\x73\x79\x6e\x63\x51\x75\x65\x75\x65")                                        \
  V(buffer_string, "\x62\x75\x66\x66\x65\x72")                                                  \
  V(bytes_string, "\x62\x79\x74\x65\x73")                                                    \
  V(bytes_parsed_string, "\x62\x79\x74\x65\x73\x50\x61\x72\x73\x65\x64")                                       \
  V(bytes_read_string, "\x62\x79\x74\x65\x73\x52\x65\x61\x64")                                           \
  V(cached_data_string, "\x63\x61\x63\x68\x65\x64\x44\x61\x74\x61")                                         \
  V(cached_data_produced_string, "\x63\x61\x63\x68\x65\x64\x44\x61\x74\x61\x50\x72\x6f\x64\x75\x63\x65\x64")                        \
  V(cached_data_rejected_string, "\x63\x61\x63\x68\x65\x64\x44\x61\x74\x61\x52\x65\x6a\x65\x63\x74\x65\x64")                        \
  V(callback_string, "\x63\x61\x6c\x6c\x62\x61\x63\x6b")                                              \
  V(change_string, "\x63\x68\x61\x6e\x67\x65")                                                  \
  V(oncertcb_string, "\x6f\x6e\x63\x65\x72\x74\x63\x62")                                              \
  V(onclose_string, "\x5f\x6f\x6e\x63\x6c\x6f\x73\x65")                                               \
  V(code_string, "\x63\x6f\x64\x65")                                                      \
  V(cwd_string, "\x63\x77\x64")                                                        \
  V(dest_string, "\x64\x65\x73\x74")                                                      \
  V(detached_string, "\x64\x65\x74\x61\x63\x68\x65\x64")                                              \
  V(disposed_string, "\x5f\x64\x69\x73\x70\x6f\x73\x65\x64")                                             \
  V(domain_string, "\x64\x6f\x6d\x61\x69\x6e")                                                  \
  V(emitting_top_level_domain_error_string, "\x5f\x65\x6d\x69\x74\x74\x69\x6e\x67\x54\x6f\x70\x4c\x65\x76\x65\x6c\x44\x6f\x6d\x61\x69\x6e\x45\x72\x72\x6f\x72")   \
  V(exchange_string, "\x65\x78\x63\x68\x61\x6e\x67\x65")                                              \
  V(idle_string, "\x69\x64\x6c\x65")                                                      \
  V(irq_string, "\x69\x72\x71")                                                        \
  V(encoding_string, "\x65\x6e\x63\x6f\x64\x69\x6e\x67")                                              \
  V(enter_string, "\x65\x6e\x74\x65\x72")                                                    \
  V(env_pairs_string, "\x65\x6e\x76\x50\x61\x69\x72\x73")                                             \
  V(errno_string, "\x65\x72\x72\x6e\x6f")                                                    \
  V(error_string, "\x65\x72\x72\x6f\x72")                                                    \
  V(events_string, "\x5f\x65\x76\x65\x6e\x74\x73")                                                 \
  V(exiting_string, "\x5f\x65\x78\x69\x74\x69\x6e\x67")                                               \
  V(exit_code_string, "\x65\x78\x69\x74\x43\x6f\x64\x65")                                             \
  V(exit_string, "\x65\x78\x69\x74")                                                      \
  V(expire_string, "\x65\x78\x70\x69\x72\x65")                                                  \
  V(exponent_string, "\x65\x78\x70\x6f\x6e\x65\x6e\x74")                                              \
  V(exports_string, "\x65\x78\x70\x6f\x72\x74\x73")                                                \
  V(ext_key_usage_string, "\x65\x78\x74\x5f\x6b\x65\x79\x5f\x75\x73\x61\x67\x65")                                    \
  V(external_stream_string, "\x5f\x65\x78\x74\x65\x72\x6e\x61\x6c\x53\x74\x72\x65\x61\x6d")                                \
  V(family_string, "\x66\x61\x6d\x69\x6c\x79")                                                  \
  V(fatal_exception_string, "\x5f\x66\x61\x74\x61\x6c\x45\x78\x63\x65\x70\x74\x69\x6f\x6e")                                \
  V(fd_string, "\x66\x64")                                                          \
  V(file_string, "\x66\x69\x6c\x65")                                                      \
  V(fingerprint_string, "\x66\x69\x6e\x67\x65\x72\x70\x72\x69\x6e\x74")                                        \
  V(flags_string, "\x66\x6c\x61\x67\x73")                                                    \
  V(gid_string, "\x67\x69\x64")                                                        \
  V(handle_string, "\x68\x61\x6e\x64\x6c\x65")                                                  \
  V(homedir_string, "\x68\x6f\x6d\x65\x64\x69\x72")                                                \
  V(hostmaster_string, "\x68\x6f\x73\x74\x6d\x61\x73\x74\x65\x72")                                          \
  V(ignore_string, "\x69\x67\x6e\x6f\x72\x65")                                                  \
  V(immediate_callback_string, "\x5f\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x43\x61\x6c\x6c\x62\x61\x63\x6b")                          \
  V(infoaccess_string, "\x69\x6e\x66\x6f\x41\x63\x63\x65\x73\x73")                                          \
  V(inherit_string, "\x69\x6e\x68\x65\x72\x69\x74")                                                \
  V(input_string, "\x69\x6e\x70\x75\x74")                                                    \
  V(internal_string, "\x69\x6e\x74\x65\x72\x6e\x61\x6c")                                              \
  V(ipv4_string, "\x49\x50\x76\x34")                                                      \
  V(ipv6_string, "\x49\x50\x76\x36")                                                      \
  V(isalive_string, "\x69\x73\x41\x6c\x69\x76\x65")                                                \
  V(isclosing_string, "\x69\x73\x43\x6c\x6f\x73\x69\x6e\x67")                                            \
  V(issuer_string, "\x69\x73\x73\x75\x65\x72")                                                  \
  V(issuercert_string, "\x69\x73\x73\x75\x65\x72\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65")                                   \
  V(kill_signal_string, "\x6b\x69\x6c\x6c\x53\x69\x67\x6e\x61\x6c")                                         \
  V(mac_string, "\x6d\x61\x63")                                                        \
  V(max_buffer_string, "\x6d\x61\x78\x42\x75\x66\x66\x65\x72")                                           \
  V(message_string, "\x6d\x65\x73\x73\x61\x67\x65")                                                \
  V(minttl_string, "\x6d\x69\x6e\x74\x74\x6c")                                                  \
  V(model_string, "\x6d\x6f\x64\x65\x6c")                                                    \
  V(modulus_string, "\x6d\x6f\x64\x75\x6c\x75\x73")                                                \
  V(name_string, "\x6e\x61\x6d\x65")                                                      \
  V(netmask_string, "\x6e\x65\x74\x6d\x61\x73\x6b")                                                \
  V(nice_string, "\x6e\x69\x63\x65")                                                      \
  V(nsname_string, "\x6e\x73\x6e\x61\x6d\x65")                                                  \
  V(ocsp_request_string, "\x4f\x43\x53\x50\x52\x65\x71\x75\x65\x73\x74")                                       \
  V(onchange_string, "\x6f\x6e\x63\x68\x61\x6e\x67\x65")                                              \
  V(onclienthello_string, "\x6f\x6e\x63\x6c\x69\x65\x6e\x74\x68\x65\x6c\x6c\x6f")                                    \
  V(oncomplete_string, "\x6f\x6e\x63\x6f\x6d\x70\x6c\x65\x74\x65")                                          \
  V(onconnection_string, "\x6f\x6e\x63\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e")                                      \
  V(ondone_string, "\x6f\x6e\x64\x6f\x6e\x65")                                                  \
  V(onerror_string, "\x6f\x6e\x65\x72\x72\x6f\x72")                                                \
  V(onexit_string, "\x6f\x6e\x65\x78\x69\x74")                                                  \
  V(onhandshakedone_string, "\x6f\x6e\x68\x61\x6e\x64\x73\x68\x61\x6b\x65\x64\x6f\x6e\x65")                                \
  V(onhandshakestart_string, "\x6f\x6e\x68\x61\x6e\x64\x73\x68\x61\x6b\x65\x73\x74\x61\x72\x74")                              \
  V(onmessage_string, "\x6f\x6e\x6d\x65\x73\x73\x61\x67\x65")                                            \
  V(onnewsession_string, "\x6f\x6e\x6e\x65\x77\x73\x65\x73\x73\x69\x6f\x6e")                                      \
  V(onnewsessiondone_string, "\x6f\x6e\x6e\x65\x77\x73\x65\x73\x73\x69\x6f\x6e\x64\x6f\x6e\x65")                              \
  V(onocspresponse_string, "\x6f\x6e\x6f\x63\x73\x70\x72\x65\x73\x70\x6f\x6e\x73\x65")                                  \
  V(onread_string, "\x6f\x6e\x72\x65\x61\x64")                                                  \
  V(onreadstart_string, "\x6f\x6e\x72\x65\x61\x64\x73\x74\x61\x72\x74")                                        \
  V(onreadstop_string, "\x6f\x6e\x72\x65\x61\x64\x73\x74\x6f\x70")                                          \
  V(onselect_string, "\x6f\x6e\x73\x65\x6c\x65\x63\x74")                                              \
  V(onshutdown_string, "\x6f\x6e\x73\x68\x75\x74\x64\x6f\x77\x6e")                                          \
  V(onsignal_string, "\x6f\x6e\x73\x69\x67\x6e\x61\x6c")                                              \
  V(onstop_string, "\x6f\x6e\x73\x74\x6f\x70")                                                  \
  V(onwrite_string, "\x6f\x6e\x77\x72\x69\x74\x65")                                                \
  V(output_string, "\x6f\x75\x74\x70\x75\x74")                                                  \
  V(order_string, "\x6f\x72\x64\x65\x72")                                                    \
  V(owner_string, "\x6f\x77\x6e\x65\x72")                                                    \
  V(parse_error_string, "\x50\x61\x72\x73\x65\x20\x45\x72\x72\x6f\x72")                                        \
  V(path_string, "\x70\x61\x74\x68")                                                      \
  V(pbkdf2_error_string, "\x50\x42\x4b\x44\x46\x32\x20\x45\x72\x72\x6f\x72")                                      \
  V(pid_string, "\x70\x69\x64")                                                        \
  V(pipe_string, "\x70\x69\x70\x65")                                                      \
  V(port_string, "\x70\x6f\x72\x74")                                                      \
  V(preference_string, "\x70\x72\x65\x66\x65\x72\x65\x6e\x63\x65")                                          \
  V(priority_string, "\x70\x72\x69\x6f\x72\x69\x74\x79")                                              \
  V(produce_cached_data_string, "\x70\x72\x6f\x64\x75\x63\x65\x43\x61\x63\x68\x65\x64\x44\x61\x74\x61")                          \
  V(raw_string, "\x72\x61\x77")                                                        \
  V(readable_string, "\x72\x65\x61\x64\x61\x62\x6c\x65")                                              \
  V(received_shutdown_string, "\x72\x65\x63\x65\x69\x76\x65\x64\x53\x68\x75\x74\x64\x6f\x77\x6e")                             \
  V(refresh_string, "\x72\x65\x66\x72\x65\x73\x68")                                                \
  V(regexp_string, "\x72\x65\x67\x65\x78\x70")                                                  \
  V(rename_string, "\x72\x65\x6e\x61\x6d\x65")                                                  \
  V(replacement_string, "\x72\x65\x70\x6c\x61\x63\x65\x6d\x65\x6e\x74")                                        \
  V(retry_string, "\x72\x65\x74\x72\x79")                                                    \
  V(serial_string, "\x73\x65\x72\x69\x61\x6c")                                                  \
  V(scopeid_string, "\x73\x63\x6f\x70\x65\x69\x64")                                                \
  V(sent_shutdown_string, "\x73\x65\x6e\x74\x53\x68\x75\x74\x64\x6f\x77\x6e")                                     \
  V(serial_number_string, "\x73\x65\x72\x69\x61\x6c\x4e\x75\x6d\x62\x65\x72")                                     \
  V(service_string, "\x73\x65\x72\x76\x69\x63\x65")                                                \
  V(servername_string, "\x73\x65\x72\x76\x65\x72\x6e\x61\x6d\x65")                                          \
  V(session_id_string, "\x73\x65\x73\x73\x69\x6f\x6e\x49\x64")                                           \
  V(shell_string, "\x73\x68\x65\x6c\x6c")                                                    \
  V(signal_string, "\x73\x69\x67\x6e\x61\x6c")                                                  \
  V(size_string, "\x73\x69\x7a\x65")                                                      \
  V(sni_context_err_string, "\x49\x6e\x76\x61\x6c\x69\x64\x20\x53\x4e\x49\x20\x63\x6f\x6e\x74\x65\x78\x74")                            \
  V(sni_context_string, "\x73\x6e\x69\x5f\x63\x6f\x6e\x74\x65\x78\x74")                                        \
  V(speed_string, "\x73\x70\x65\x65\x64")                                                    \
  V(stack_string, "\x73\x74\x61\x63\x6b")                                                    \
  V(status_string, "\x73\x74\x61\x74\x75\x73")                                                  \
  V(stdio_string, "\x73\x74\x64\x69\x6f")                                                    \
  V(subject_string, "\x73\x75\x62\x6a\x65\x63\x74")                                                \
  V(subjectaltname_string, "\x73\x75\x62\x6a\x65\x63\x74\x61\x6c\x74\x6e\x61\x6d\x65")                                  \
  V(sys_string, "\x73\x79\x73")                                                        \
  V(syscall_string, "\x73\x79\x73\x63\x61\x6c\x6c")                                                \
  V(tick_callback_string, "\x5f\x74\x69\x63\x6b\x43\x61\x6c\x6c\x62\x61\x63\x6b")                                    \
  V(tick_domain_cb_string, "\x5f\x74\x69\x63\x6b\x44\x6f\x6d\x61\x69\x6e\x43\x61\x6c\x6c\x62\x61\x63\x6b")                             \
  V(ticketkeycallback_string, "\x6f\x6e\x74\x69\x63\x6b\x65\x74\x6b\x65\x79\x63\x61\x6c\x6c\x62\x61\x63\x6b")                          \
  V(timeout_string, "\x74\x69\x6d\x65\x6f\x75\x74")                                                \
  V(times_string, "\x74\x69\x6d\x65\x73")                                                    \
  V(tls_ticket_string, "\x74\x6c\x73\x54\x69\x63\x6b\x65\x74")                                           \
  V(type_string, "\x74\x79\x70\x65")                                                      \
  V(uid_string, "\x75\x69\x64")                                                        \
  V(unknown_string, "\x3c\x75\x6e\x6b\x6e\x6f\x77\x6e\x3e")                                              \
  V(user_string, "\x75\x73\x65\x72")                                                      \
  V(username_string, "\x75\x73\x65\x72\x6e\x61\x6d\x65")                                              \
  V(valid_from_string, "\x76\x61\x6c\x69\x64\x5f\x66\x72\x6f\x6d")                                          \
  V(valid_to_string, "\x76\x61\x6c\x69\x64\x5f\x74\x6f")                                              \
  V(verify_error_string, "\x76\x65\x72\x69\x66\x79\x45\x72\x72\x6f\x72")                                       \
  V(version_string, "\x76\x65\x72\x73\x69\x6f\x6e")                                                \
  V(weight_string, "\x77\x65\x69\x67\x68\x74")                                                  \
  V(windows_verbatim_arguments_string, "\x77\x69\x6e\x64\x6f\x77\x73\x56\x65\x72\x62\x61\x74\x69\x6d\x41\x72\x67\x75\x6d\x65\x6e\x74\x73")            \
  V(wrap_string, "\x77\x72\x61\x70")                                                      \
  V(writable_string, "\x77\x72\x69\x74\x61\x62\x6c\x65")                                              \
  V(write_queue_size_string, "\x77\x72\x69\x74\x65\x51\x75\x65\x75\x65\x53\x69\x7a\x65")                                \
  V(x_forwarded_string, "\x78\x2d\x66\x6f\x72\x77\x61\x72\x64\x65\x64\x2d\x66\x6f\x72")                                    \
  V(zero_return_string, "\x5a\x45\x52\x4f\x5f\x52\x45\x54\x55\x52\x4e")                                        \

#define ENVIRONMENT_STRONG_PERSISTENT_PROPERTIES(V)                           \
  V(as_external, v8::External)                                                \
  V(async_hooks_destroy_function, v8::Function)                               \
  V(async_hooks_init_function, v8::Function)                                  \
  V(async_hooks_post_function, v8::Function)                                  \
  V(async_hooks_pre_function, v8::Function)                                   \
  V(binding_cache_object, v8::Object)                                         \
  V(buffer_constructor_function, v8::Function)                                \
  V(buffer_prototype_object, v8::Object)                                      \
  V(context, v8::Context)                                                     \
  V(domain_array, v8::Array)                                                  \
  V(domains_stack_array, v8::Array)                                           \
  V(fs_stats_constructor_function, v8::Function)                              \
  V(generic_internal_field_template, v8::ObjectTemplate)                      \
  V(jsstream_constructor_template, v8::FunctionTemplate)                      \
  V(module_load_list_array, v8::Array)                                        \
  V(pipe_constructor_template, v8::FunctionTemplate)                          \
  V(process_object, v8::Object)                                               \
  V(promise_reject_function, v8::Function)                                    \
  V(push_values_to_array_function, v8::Function)                              \
  V(script_context_constructor_template, v8::FunctionTemplate)                \
  V(script_data_constructor_function, v8::Function)                           \
  V(secure_context_constructor_template, v8::FunctionTemplate)                \
  V(tcp_constructor_template, v8::FunctionTemplate)                           \
  V(tick_callback_function, v8::Function)                                     \
  V(tls_wrap_constructor_function, v8::Function)                              \
  V(tls_wrap_constructor_template, v8::FunctionTemplate)                      \
  V(tty_constructor_template, v8::FunctionTemplate)                           \
  V(udp_constructor_function, v8::Function)                                   \
  V(url_constructor_function, v8::Function)                                   \
  V(write_wrap_constructor_function, v8::Function)                            \

class Environment;

struct node_ares_task {
  Environment* env;
  ares_socket_t sock;
  uv_poll_t poll_watcher;
  RB_ENTRY(node_ares_task) node;
};

RB_HEAD(node_ares_task_list, node_ares_task);

class Environment {
 public:
  class AsyncHooks {
   public:
    inline uint32_t* fields();
    inline int fields_count() const;
    inline bool callbacks_enabled();
    inline void set_enable_callbacks(uint32_t flag);

   private:
    friend class Environment;  // So we can call the constructor.
    inline AsyncHooks();

    enum Fields {
      // Set this to not zero if the init hook should be called.
      kEnableCallbacks,
      kFieldsCount
    };

    uint32_t fields_[kFieldsCount];

    DISALLOW_COPY_AND_ASSIGN(AsyncHooks);
  };

  class AsyncCallbackScope {
   public:
    explicit AsyncCallbackScope(Environment* env);
    ~AsyncCallbackScope();

    inline bool in_makecallback() const;

   private:
    Environment* env_;

    DISALLOW_COPY_AND_ASSIGN(AsyncCallbackScope);
  };

  class DomainFlag {
   public:
    inline uint32_t* fields();
    inline int fields_count() const;
    inline uint32_t count() const;

   private:
    friend class Environment;  // So we can call the constructor.
    inline DomainFlag();

    enum Fields {
      kCount,
      kFieldsCount
    };

    uint32_t fields_[kFieldsCount];

    DISALLOW_COPY_AND_ASSIGN(DomainFlag);
  };

  class TickInfo {
   public:
    inline uint32_t* fields();
    inline int fields_count() const;
    inline uint32_t index() const;
    inline uint32_t length() const;
    inline void set_index(uint32_t value);

   private:
    friend class Environment;  // So we can call the constructor.
    inline TickInfo();

    enum Fields {
      kIndex,
      kLength,
      kFieldsCount
    };

    uint32_t fields_[kFieldsCount];

    DISALLOW_COPY_AND_ASSIGN(TickInfo);
  };

  class ArrayBufferAllocatorInfo {
   public:
    inline uint32_t* fields();
    inline int fields_count() const;
    inline bool no_zero_fill() const;
    inline void reset_fill_flag();

   private:
    friend class Environment;  // So we can call the constructor.
    inline ArrayBufferAllocatorInfo();

    enum Fields {
      kNoZeroFill,
      kFieldsCount
    };

    uint32_t fields_[kFieldsCount];

    DISALLOW_COPY_AND_ASSIGN(ArrayBufferAllocatorInfo);
  };

  typedef void (*HandleCleanupCb)(Environment* env,
                                  uv_handle_t* handle,
                                  void* arg);

  class HandleCleanup {
   private:
    friend class Environment;

    HandleCleanup(uv_handle_t* handle, HandleCleanupCb cb, void* arg)
        : handle_(handle),
          cb_(cb),
          arg_(arg) {
    }

    uv_handle_t* handle_;
    HandleCleanupCb cb_;
    void* arg_;
    ListNode<HandleCleanup> handle_cleanup_queue_;
  };

  static inline Environment* GetCurrent(v8::Isolate* isolate);
  static inline Environment* GetCurrent(v8::Local<v8::Context> context);
  static inline Environment* GetCurrent(
      const v8::FunctionCallbackInfo<v8::Value>& info);

  template <typename T>
  static inline Environment* GetCurrent(
      const v8::PropertyCallbackInfo<T>& info);

  // See CreateEnvironment() in src/node.cc.
  static inline Environment* New(v8::Local<v8::Context> context,
                                 uv_loop_t* loop);
  inline void CleanupHandles();
  inline void Dispose();

  void AssignToContext(v8::Local<v8::Context> context);

  inline v8::Isolate* isolate() const;
  inline uv_loop_t* event_loop() const;
  inline bool async_wrap_callbacks_enabled() const;
  inline bool in_domain() const;
  inline uint32_t watched_providers() const;

  static inline Environment* from_immediate_check_handle(uv_check_t* handle);
  static inline Environment* from_destroy_ids_idle_handle(uv_idle_t* handle);
  inline uv_check_t* immediate_check_handle();
  inline uv_idle_t* immediate_idle_handle();
  inline uv_idle_t* destroy_ids_idle_handle();

  static inline Environment* from_idle_prepare_handle(uv_prepare_t* handle);
  inline uv_prepare_t* idle_prepare_handle();

  static inline Environment* from_idle_check_handle(uv_check_t* handle);
  inline uv_check_t* idle_check_handle();

  // Register clean-up cb to be called on env->Dispose()
  inline void RegisterHandleCleanup(uv_handle_t* handle,
                                    HandleCleanupCb cb,
                                    void *arg);
  inline void FinishHandleCleanup(uv_handle_t* handle);

  inline AsyncHooks* async_hooks();
  inline DomainFlag* domain_flag();
  inline TickInfo* tick_info();
  inline ArrayBufferAllocatorInfo* array_buffer_allocator_info();
  inline uint64_t timer_base() const;

  static inline Environment* from_cares_timer_handle(uv_timer_t* handle);
  inline uv_timer_t* cares_timer_handle();
  inline ares_channel cares_channel();
  inline ares_channel* cares_channel_ptr();
  inline bool cares_query_last_ok();
  inline void set_cares_query_last_ok(bool ok);
  inline bool cares_is_servers_default();
  inline void set_cares_is_servers_default(bool is_default);
  inline node_ares_task_list* cares_task_list();

  inline bool using_domains() const;
  inline void set_using_domains(bool value);

  inline bool printed_error() const;
  inline void set_printed_error(bool value);

  void PrintSyncTrace() const;
  inline void set_trace_sync_io(bool value);

  inline int64_t get_async_wrap_uid();

  // List of id's that have been destroyed and need the destroy() cb called.
  inline std::vector<int64_t>* destroy_ids_list();

  inline double* heap_statistics_buffer() const;
  inline void set_heap_statistics_buffer(double* pointer);

  inline double* heap_space_statistics_buffer() const;
  inline void set_heap_space_statistics_buffer(double* pointer);

  inline char* http_parser_buffer() const;
  inline void set_http_parser_buffer(char* buffer);

  inline void ThrowError(const char* errmsg);
  inline void ThrowTypeError(const char* errmsg);
  inline void ThrowRangeError(const char* errmsg);
  inline void ThrowErrnoException(int errorno,
                                  const char* syscall = nullptr,
                                  const char* message = nullptr,
                                  const char* path = nullptr);
  inline void ThrowUVException(int errorno,
                               const char* syscall = nullptr,
                               const char* message = nullptr,
                               const char* path = nullptr,
                               const char* dest = nullptr);

  inline v8::Local<v8::FunctionTemplate>
      NewFunctionTemplate(v8::FunctionCallback callback,
                          v8::Local<v8::Signature> signature =
                              v8::Local<v8::Signature>());

  // Convenience methods for NewFunctionTemplate().
  inline void SetMethod(v8::Local<v8::Object> that,
                        const char* name,
                        v8::FunctionCallback callback);
  inline void SetProtoMethod(v8::Local<v8::FunctionTemplate> that,
                             const char* name,
                             v8::FunctionCallback callback);
  inline void SetTemplateMethod(v8::Local<v8::FunctionTemplate> that,
                                const char* name,
                                v8::FunctionCallback callback);

  inline v8::Local<v8::Object> NewInternalFieldObject();

  // Strings and private symbols are shared across shared contexts
  // The getters simply proxy to the per-isolate primitive.
#define VP(PropertyName, StringValue) V(v8::Private, PropertyName, StringValue)
#define VS(PropertyName, StringValue) V(v8::String, PropertyName, StringValue)
#define V(TypeName, PropertyName, StringValue)                                \
  inline v8::Local<TypeName> PropertyName() const;
  PER_ISOLATE_PRIVATE_SYMBOL_PROPERTIES(VP)
  PER_ISOLATE_STRING_PROPERTIES(VS)
#undef V
#undef VS
#undef VP

#define V(PropertyName, TypeName)                                             \
  inline v8::Local<TypeName> PropertyName() const;                            \
  inline void set_ ## PropertyName(v8::Local<TypeName> value);
  ENVIRONMENT_STRONG_PERSISTENT_PROPERTIES(V)
#undef V

  inline debugger::Agent* debugger_agent() {
    return &debugger_agent_;
  }

#if HAVE_INSPECTOR
  inline inspector::Agent* inspector_agent() {
    return &inspector_agent_;
  }
#endif

  typedef ListHead<HandleWrap, &HandleWrap::handle_wrap_queue_> HandleWrapQueue;
  typedef ListHead<ReqWrap<uv_req_t>, &ReqWrap<uv_req_t>::req_wrap_queue_>
          ReqWrapQueue;

  inline HandleWrapQueue* handle_wrap_queue() { return &handle_wrap_queue_; }
  inline ReqWrapQueue* req_wrap_queue() { return &req_wrap_queue_; }

  static const int kContextEmbedderDataIndex = NODE_CONTEXT_EMBEDDER_DATA_INDEX;

 private:
  inline void ThrowError(v8::Local<v8::Value> (*fun)(v8::Local<v8::String>),
                         const char* errmsg);

  static const int kIsolateSlot = NODE_ISOLATE_SLOT;

  class IsolateData;
  inline Environment(v8::Local<v8::Context> context, uv_loop_t* loop);
  inline ~Environment();
  inline IsolateData* isolate_data() const;

  v8::Isolate* const isolate_;
  IsolateData* const isolate_data_;
  uv_check_t immediate_check_handle_;
  uv_idle_t immediate_idle_handle_;
  uv_idle_t destroy_ids_idle_handle_;
  uv_prepare_t idle_prepare_handle_;
  uv_check_t idle_check_handle_;
  AsyncHooks async_hooks_;
  DomainFlag domain_flag_;
  TickInfo tick_info_;
  ArrayBufferAllocatorInfo array_buffer_allocator_info_;
  const uint64_t timer_base_;
  uv_timer_t cares_timer_handle_;
  ares_channel cares_channel_;
  bool cares_query_last_ok_;
  bool cares_is_servers_default_;
  node_ares_task_list cares_task_list_;
  bool using_domains_;
  bool printed_error_;
  bool trace_sync_io_;
  size_t makecallback_cntr_;
  int64_t async_wrap_uid_;
  std::vector<int64_t> destroy_ids_list_;
  debugger::Agent debugger_agent_;
#if HAVE_INSPECTOR
  inspector::Agent inspector_agent_;
#endif

  HandleWrapQueue handle_wrap_queue_;
  ReqWrapQueue req_wrap_queue_;
  ListHead<HandleCleanup,
           &HandleCleanup::handle_cleanup_queue_> handle_cleanup_queue_;
  int handle_cleanup_waiting_;

  double* heap_statistics_buffer_ = nullptr;
  double* heap_space_statistics_buffer_ = nullptr;

  char* http_parser_buffer_;

#define V(PropertyName, TypeName)                                             \
  v8::Persistent<TypeName> PropertyName ## _;
  ENVIRONMENT_STRONG_PERSISTENT_PROPERTIES(V)
#undef V

  // Per-thread, reference-counted singleton.
  class IsolateData {
   public:
    static inline IsolateData* GetOrCreate(v8::Isolate* isolate,
                                           uv_loop_t* loop);
    inline void Put();
    inline uv_loop_t* event_loop() const;

#define VP(PropertyName, StringValue) V(v8::Private, PropertyName, StringValue)
#define VS(PropertyName, StringValue) V(v8::String, PropertyName, StringValue)
#define V(TypeName, PropertyName, StringValue)                                \
    inline v8::Local<TypeName> PropertyName() const;
    PER_ISOLATE_PRIVATE_SYMBOL_PROPERTIES(VP)
    PER_ISOLATE_STRING_PROPERTIES(VS)
#undef V
#undef VS
#undef VP

   private:
    inline static IsolateData* Get(v8::Isolate* isolate);
    inline explicit IsolateData(v8::Isolate* isolate, uv_loop_t* loop);
    inline v8::Isolate* isolate() const;

    uv_loop_t* const event_loop_;
    v8::Isolate* const isolate_;

#define VP(PropertyName, StringValue) V(v8::Private, PropertyName, StringValue)
#define VS(PropertyName, StringValue) V(v8::String, PropertyName, StringValue)
#define V(TypeName, PropertyName, StringValue)                                \
    v8::Eternal<TypeName> PropertyName ## _;
    PER_ISOLATE_PRIVATE_SYMBOL_PROPERTIES(VP)
    PER_ISOLATE_STRING_PROPERTIES(VS)
#undef V
#undef VS
#undef VP

    unsigned int ref_count_;

    DISALLOW_COPY_AND_ASSIGN(IsolateData);
  };

  DISALLOW_COPY_AND_ASSIGN(Environment);
};

}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#endif  // SRC_ENV_H_
