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

#ifndef SRC_ENV_H_
#define SRC_ENV_H_

#include "ares.h"
#include "tree.h"
#include "util.h"
#include "uv.h"
#include "v8.h"
#include "queue.h"
#include "debugger-agent.h"

#include <stdint.h>

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

// Strings are per-isolate primitives but Environment proxies them
// for the sake of convenience.
#define PER_ISOLATE_STRING_PROPERTIES(V)                                      \
  V(address_string, "\x61\x64\x64\x72\x65\x73\x73")                                                \
  V(args_string, "\x61\x72\x67\x73")                                                      \
  V(argv_string, "\x61\x72\x67\x76")                                                      \
  V(async, "\x61\x73\x79\x6e\x63")                                                           \
  V(async_queue_string, "\x5f\x61\x73\x79\x6e\x63\x51\x75\x65\x75\x65")                                        \
  V(atime_string, "\x61\x74\x69\x6d\x65")                                                    \
  V(birthtime_string, "\x62\x69\x72\x74\x68\x74\x69\x6d\x65")                                            \
  V(blksize_string, "\x62\x6c\x6b\x73\x69\x7a\x65")                                                \
  V(blocks_string, "\x62\x6c\x6f\x63\x6b\x73")                                                  \
  V(buffer_string, "\x62\x75\x66\x66\x65\x72")                                                  \
  V(bytes_string, "\x62\x79\x74\x65\x73")                                                    \
  V(bytes_parsed_string, "\x62\x79\x74\x65\x73\x50\x61\x72\x73\x65\x64")                                       \
  V(callback_string, "\x63\x61\x6c\x6c\x62\x61\x63\x6b")                                              \
  V(change_string, "\x63\x68\x61\x6e\x67\x65")                                                  \
  V(close_string, "\x63\x6c\x6f\x73\x65")                                                    \
  V(code_string, "\x63\x6f\x64\x65")                                                      \
  V(compare_string, "\x63\x6f\x6d\x70\x61\x72\x65")                                                \
  V(ctime_string, "\x63\x74\x69\x6d\x65")                                                    \
  V(cwd_string, "\x63\x77\x64")                                                        \
  V(debug_port_string, "\x64\x65\x62\x75\x67\x50\x6f\x72\x74")                                           \
  V(debug_string, "\x64\x65\x62\x75\x67")                                                    \
  V(detached_string, "\x64\x65\x74\x61\x63\x68\x65\x64")                                              \
  V(dev_string, "\x64\x65\x76")                                                        \
  V(disposed_string, "\x5f\x64\x69\x73\x70\x6f\x73\x65\x64")                                             \
  V(domain_string, "\x64\x6f\x6d\x61\x69\x6e")                                                  \
  V(emitting_top_level_domain_error_string, "\x5f\x65\x6d\x69\x74\x74\x69\x6e\x67\x54\x6f\x70\x4c\x65\x76\x65\x6c\x44\x6f\x6d\x61\x69\x6e\x45\x72\x72\x6f\x72")   \
  V(exchange_string, "\x65\x78\x63\x68\x61\x6e\x67\x65")                                              \
  V(idle_string, "\x69\x64\x6c\x65")                                                      \
  V(irq_string, "\x69\x72\x71")                                                        \
  V(enter_string, "\x65\x6e\x74\x65\x72")                                                    \
  V(env_pairs_string, "\x65\x6e\x76\x50\x61\x69\x72\x73")                     \
  V(env_string, "\x65\x6e\x76")                                                        \
  V(errno_string, "\x65\x72\x72\x6e\x6f")                                                    \
  V(error_string, "\x65\x72\x72\x6f\x72")                                                    \
  V(events_string, "\x5f\x65\x76\x65\x6e\x74\x73")                                                 \
  V(exec_argv_string, "\x65\x78\x65\x63\x41\x72\x67\x76")                                             \
  V(exec_path_string, "\x65\x78\x65\x63\x50\x61\x74\x68")                                             \
  V(exiting_string, "\x5f\x65\x78\x69\x74\x69\x6e\x67")                                               \
  V(exit_code_string, "\x65\x78\x69\x74\x43\x6f\x64\x65")                                             \
  V(exit_string, "\x65\x78\x69\x74")                                                      \
  V(expire_string, "\x65\x78\x70\x69\x72\x65")                                                  \
  V(exponent_string, "\x65\x78\x70\x6f\x6e\x65\x6e\x74")                                              \
  V(exports_string, "\x65\x78\x70\x6f\x72\x74\x73")                                                \
  V(ext_key_usage_string, "\x65\x78\x74\x5f\x6b\x65\x79\x5f\x75\x73\x61\x67\x65")                                    \
  V(family_string, "\x66\x61\x6d\x69\x6c\x79")                                                  \
  V(fatal_exception_string, "\x5f\x66\x61\x74\x61\x6c\x45\x78\x63\x65\x70\x74\x69\x6f\x6e")                                \
  V(fd_string, "\x66\x64")                                                          \
  V(file_string, "\x66\x69\x6c\x65")                                                      \
  V(fingerprint_string, "\x66\x69\x6e\x67\x65\x72\x70\x72\x69\x6e\x74")                                        \
  V(flags_string, "\x66\x6c\x61\x67\x73")                                                    \
  V(fsevent_string, "\x46\x53\x45\x76\x65\x6e\x74")                                                \
  V(gid_string, "\x67\x69\x64")                                                        \
  V(handle_string, "\x68\x61\x6e\x64\x6c\x65")                                                  \
  V(headers_string, "\x68\x65\x61\x64\x65\x72\x73")                                                \
  V(heap_size_limit_string, "\x68\x65\x61\x70\x5f\x73\x69\x7a\x65\x5f\x6c\x69\x6d\x69\x74")                                \
  V(heap_total_string, "\x68\x65\x61\x70\x54\x6f\x74\x61\x6c")                                           \
  V(heap_used_string, "\x68\x65\x61\x70\x55\x73\x65\x64")                                             \
  V(hostmaster_string, "\x68\x6f\x73\x74\x6d\x61\x73\x74\x65\x72")                                          \
  V(ignore_string, "\x69\x67\x6e\x6f\x72\x65")                                                  \
  V(immediate_callback_string, "\x5f\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x43\x61\x6c\x6c\x62\x61\x63\x6b")                          \
  V(infoaccess_string, "\x69\x6e\x66\x6f\x41\x63\x63\x65\x73\x73")                                          \
  V(inherit_string, "\x69\x6e\x68\x65\x72\x69\x74")                                                \
  V(ino_string, "\x69\x6e\x6f")                                                        \
  V(input_string, "\x69\x6e\x70\x75\x74")                                                    \
  V(internal_string, "\x69\x6e\x74\x65\x72\x6e\x61\x6c")                                              \
  V(ipv4_string, "\x49\x50\x76\x34")                                                      \
  V(ipv6_lc_string, "\x69\x70\x76\x36")                                                   \
  V(ipv6_string, "\x49\x50\x76\x36")                                                      \
  V(issuer_string, "\x69\x73\x73\x75\x65\x72")                                                  \
  V(issuercert_string, "\x69\x73\x73\x75\x65\x72\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65")                                   \
  V(kill_signal_string, "\x6b\x69\x6c\x6c\x53\x69\x67\x6e\x61\x6c")                                         \
  V(mac_string, "\x6d\x61\x63")                                                        \
  V(mark_sweep_compact_string, "\x6d\x61\x72\x6b\x2d\x73\x77\x65\x65\x70\x2d\x63\x6f\x6d\x70\x61\x63\x74")                          \
  V(max_buffer_string, "\x6d\x61\x78\x42\x75\x66\x66\x65\x72")                                           \
  V(message_string, "\x6d\x65\x73\x73\x61\x67\x65")                                                \
  V(method_string, "\x6d\x65\x74\x68\x6f\x64")                                                  \
  V(minttl_string, "\x6d\x69\x6e\x74\x74\x6c")                                                  \
  V(mode_string, "\x6d\x6f\x64\x65")                                                      \
  V(model_string, "\x6d\x6f\x64\x65\x6c")                                                    \
  V(modulus_string, "\x6d\x6f\x64\x75\x6c\x75\x73")                                                \
  V(mtime_string, "\x6d\x74\x69\x6d\x65")                                                    \
  V(name_string, "\x6e\x61\x6d\x65")                                                      \
  V(need_imm_cb_string, "\x5f\x6e\x65\x65\x64\x49\x6d\x6d\x65\x64\x69\x61\x74\x65\x43\x61\x6c\x6c\x62\x61\x63\x6b")                             \
  V(netmask_string, "\x6e\x65\x74\x6d\x61\x73\x6b")                                                \
  V(nice_string, "\x6e\x69\x63\x65")                                                      \
  V(nlink_string, "\x6e\x6c\x69\x6e\x6b")                                                    \
  V(nsname_string, "\x6e\x73\x6e\x61\x6d\x65")                                                  \
  V(ocsp_request_string, "\x4f\x43\x53\x50\x52\x65\x71\x75\x65\x73\x74")                                       \
  V(offset_string, "\x6f\x66\x66\x73\x65\x74")                                                  \
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
  V(onselect_string, "\x6f\x6e\x73\x65\x6c\x65\x63\x74")                                              \
  V(onsignal_string, "\x6f\x6e\x73\x69\x67\x6e\x61\x6c")                                              \
  V(onstop_string, "\x6f\x6e\x73\x74\x6f\x70")                                                  \
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
  V(processed_string, "\x70\x72\x6f\x63\x65\x73\x73\x65\x64")                                            \
  V(prototype_string, "\x70\x72\x6f\x74\x6f\x74\x79\x70\x65")                                            \
  V(raw_string, "\x72\x61\x77")                                                        \
  V(rdev_string, "\x72\x64\x65\x76")                                                      \
  V(readable_string, "\x72\x65\x61\x64\x61\x62\x6c\x65")                                              \
  V(received_shutdown_string, "\x72\x65\x63\x65\x69\x76\x65\x64\x53\x68\x75\x74\x64\x6f\x77\x6e")                             \
  V(refresh_string, "\x72\x65\x66\x72\x65\x73\x68")                                                \
  V(regexp_string, "\x72\x65\x67\x65\x78\x70")                                                  \
  V(rename_string, "\x72\x65\x6e\x61\x6d\x65")                                                  \
  V(replacement_string, "\x72\x65\x70\x6c\x61\x63\x65\x6d\x65\x6e\x74")                                        \
  V(retry_string, "\x72\x65\x74\x72\x79")                                                    \
  V(rss_string, "\x72\x73\x73")                                                        \
  V(serial_string, "\x73\x65\x72\x69\x61\x6c")                                                  \
  V(scavenge_string, "\x73\x63\x61\x76\x65\x6e\x67\x65")                                              \
  V(scopeid_string, "\x73\x63\x6f\x70\x65\x69\x64")                                                \
  V(sent_shutdown_string, "\x73\x65\x6e\x74\x53\x68\x75\x74\x64\x6f\x77\x6e")                                     \
  V(serial_number_string, "\x73\x65\x72\x69\x61\x6c\x4e\x75\x6d\x62\x65\x72")                                     \
  V(service_string, "\x73\x65\x72\x76\x69\x63\x65")                                                \
  V(servername_string, "\x73\x65\x72\x76\x65\x72\x6e\x61\x6d\x65")                                          \
  V(session_id_string, "\x73\x65\x73\x73\x69\x6f\x6e\x49\x64")                                           \
  V(should_keep_alive_string, "\x73\x68\x6f\x75\x6c\x64\x4b\x65\x65\x70\x41\x6c\x69\x76\x65")                              \
  V(signal_string, "\x73\x69\x67\x6e\x61\x6c")                                                  \
  V(size_string, "\x73\x69\x7a\x65")                                                      \
  V(smalloc_p_string, "\x5f\x73\x6d\x61\x6c\x6c\x6f\x63\x5f\x70")                                           \
  V(sni_context_err_string, "\x49\x6e\x76\x61\x6c\x69\x64\x20\x53\x4e\x49\x20\x63\x6f\x6e\x74\x65\x78\x74")                            \
  V(sni_context_string, "\x73\x6e\x69\x5f\x63\x6f\x6e\x74\x65\x78\x74")                                        \
  V(speed_string, "\x73\x70\x65\x65\x64")                                                    \
  V(stack_string, "\x73\x74\x61\x63\x6b")                                                    \
  V(status_code_string, "\x73\x74\x61\x74\x75\x73\x43\x6f\x64\x65")                                         \
  V(status_message_string, "\x73\x74\x61\x74\x75\x73\x4d\x65\x73\x73\x61\x67\x65")                                   \
  V(status_string, "\x73\x74\x61\x74\x75\x73")                                                  \
  V(stdio_string, "\x73\x74\x64\x69\x6f")                                                    \
  V(subject_string, "\x73\x75\x62\x6a\x65\x63\x74")                                                \
  V(subjectaltname_string, "\x73\x75\x62\x6a\x65\x63\x74\x61\x6c\x74\x6e\x61\x6d\x65")                                  \
  V(sys_string, "\x73\x79\x73")                                                        \
  V(syscall_string, "\x73\x79\x73\x63\x61\x6c\x6c")                                                \
  V(tick_callback_string, "\x5f\x74\x69\x63\x6b\x43\x61\x6c\x6c\x62\x61\x63\x6b")                                    \
  V(tick_domain_cb_string, "\x5f\x74\x69\x63\x6b\x44\x6f\x6d\x61\x69\x6e\x43\x61\x6c\x6c\x62\x61\x63\x6b")                             \
  V(timeout_string, "\x74\x69\x6d\x65\x6f\x75\x74")                                                \
  V(times_string, "\x74\x69\x6d\x65\x73")                                                    \
  V(timestamp_string, "\x74\x69\x6d\x65\x73\x74\x61\x6d\x70")                                            \
  V(title_string, "\x74\x69\x74\x6c\x65")                                                    \
  V(tls_npn_string, "\x74\x6c\x73\x5f\x6e\x70\x6e")                                                \
  V(tls_ocsp_string, "\x74\x6c\x73\x5f\x6f\x63\x73\x70")                                              \
  V(tls_sni_string, "\x74\x6c\x73\x5f\x73\x6e\x69")                                                \
  V(tls_string, "\x74\x6c\x73")                                                        \
  V(tls_ticket_string, "\x74\x6c\x73\x54\x69\x63\x6b\x65\x74")                                           \
  V(total_heap_size_executable_string, "\x74\x6f\x74\x61\x6c\x5f\x68\x65\x61\x70\x5f\x73\x69\x7a\x65\x5f\x65\x78\x65\x63\x75\x74\x61\x62\x6c\x65")          \
  V(total_heap_size_string, "\x74\x6f\x74\x61\x6c\x5f\x68\x65\x61\x70\x5f\x73\x69\x7a\x65")                                \
  V(total_physical_size_string, "\x74\x6f\x74\x61\x6c\x5f\x70\x68\x79\x73\x69\x63\x61\x6c\x5f\x73\x69\x7a\x65")                        \
  V(type_string, "\x74\x79\x70\x65")                                                      \
  V(uid_string, "\x75\x69\x64")                                                        \
  V(unknown_string, "\x3c\x75\x6e\x6b\x6e\x6f\x77\x6e\x3e")                                              \
  V(upgrade_string, "\x75\x70\x67\x72\x61\x64\x65")                                                \
  V(url_string, "\x75\x72\x6c")                                                        \
  V(used_heap_size_string, "\x75\x73\x65\x64\x5f\x68\x65\x61\x70\x5f\x73\x69\x7a\x65")                                  \
  V(user_string, "\x75\x73\x65\x72")                                                      \
  V(uv_string, "\x75\x76")                                                          \
  V(valid_from_string, "\x76\x61\x6c\x69\x64\x5f\x66\x72\x6f\x6d")                                          \
  V(valid_to_string, "\x76\x61\x6c\x69\x64\x5f\x74\x6f")                                              \
  V(verify_error_string, "\x76\x65\x72\x69\x66\x79\x45\x72\x72\x6f\x72")                                       \
  V(version_major_string, "\x76\x65\x72\x73\x69\x6f\x6e\x4d\x61\x6a\x6f\x72")                                     \
  V(version_minor_string, "\x76\x65\x72\x73\x69\x6f\x6e\x4d\x69\x6e\x6f\x72")                                     \
  V(version_string, "\x76\x65\x72\x73\x69\x6f\x6e")                                                \
  V(weight_string, "\x77\x65\x69\x67\x68\x74")                                                  \
  V(windows_verbatim_arguments_string, "\x77\x69\x6e\x64\x6f\x77\x73\x56\x65\x72\x62\x61\x74\x69\x6d\x41\x72\x67\x75\x6d\x65\x6e\x74\x73")            \
  V(wrap_string, "\x77\x72\x61\x70")                                                      \
  V(writable_string, "\x77\x72\x69\x74\x61\x62\x6c\x65")                                              \
  V(write_queue_size_string, "\x77\x72\x69\x74\x65\x51\x75\x65\x75\x65\x53\x69\x7a\x65")                                \
  V(x_forwarded_string, "\x78\x2d\x66\x6f\x72\x77\x61\x72\x64\x65\x64\x2d\x66\x6f\x72")                                    \
  V(zero_return_string, "\x5a\x45\x52\x4f\x5f\x52\x45\x54\x55\x52\x4e")                                        \

#define ENVIRONMENT_STRONG_PERSISTENT_PROPERTIES(V)                           \
  V(async_hooks_init_function, v8::Function)                                  \
  V(async_hooks_pre_function, v8::Function)                                   \
  V(async_hooks_post_function, v8::Function)                                  \
  V(binding_cache_object, v8::Object)                                         \
  V(buffer_constructor_function, v8::Function)                                \
  V(context, v8::Context)                                                     \
  V(domain_array, v8::Array)                                                  \
  V(domains_stack_array, v8::Array)                                           \
  V(fs_stats_constructor_function, v8::Function)                              \
  V(gc_info_callback_function, v8::Function)                                  \
  V(module_load_list_array, v8::Array)                                        \
  V(pipe_constructor_template, v8::FunctionTemplate)                          \
  V(process_object, v8::Object)                                               \
  V(script_context_constructor_template, v8::FunctionTemplate)                \
  V(script_data_constructor_function, v8::Function)                           \
  V(secure_context_constructor_template, v8::FunctionTemplate)                \
  V(tcp_constructor_template, v8::FunctionTemplate)                           \
  V(tick_callback_function, v8::Function)                                     \
  V(tls_wrap_constructor_function, v8::Function)                              \
  V(tty_constructor_template, v8::FunctionTemplate)                           \
  V(udp_constructor_function, v8::Function)                                   \

class Environment;

// TODO(bnoordhuis) Rename struct, the ares_ prefix implies it's part
// of the c-ares API while the _t suffix implies it's a typedef.
struct ares_task_t {
  Environment* env;
  ares_socket_t sock;
  uv_poll_t poll_watcher;
  RB_ENTRY(ares_task_t) node;
};

RB_HEAD(ares_task_list, ares_task_t);

class Environment {
 public:
  class AsyncHooks {
   public:
    inline uint32_t* fields();
    inline int fields_count() const;
    inline bool call_init_hook();

   private:
    friend class Environment;  // So we can call the constructor.
    inline AsyncHooks();

    enum Fields {
      // Set this to not zero if the init hook should be called.
      kCallInitHook,
      kFieldsCount
    };

    uint32_t fields_[kFieldsCount];

    DISALLOW_COPY_AND_ASSIGN(AsyncHooks);
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
    inline bool in_tick() const;
    inline bool last_threw() const;
    inline uint32_t index() const;
    inline uint32_t length() const;
    inline void set_in_tick(bool value);
    inline void set_index(uint32_t value);
    inline void set_last_threw(bool value);

   private:
    friend class Environment;  // So we can call the constructor.
    inline TickInfo();

    enum Fields {
      kIndex,
      kLength,
      kFieldsCount
    };

    uint32_t fields_[kFieldsCount];
    bool in_tick_;
    bool last_threw_;

    DISALLOW_COPY_AND_ASSIGN(TickInfo);
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
      QUEUE_INIT(&handle_cleanup_queue_);
    }

    uv_handle_t* handle_;
    HandleCleanupCb cb_;
    void* arg_;
    QUEUE handle_cleanup_queue_;
  };

  static inline Environment* GetCurrent(v8::Isolate* isolate);
  static inline Environment* GetCurrent(v8::Local<v8::Context> context);

  // See CreateEnvironment() in src/node.cc.
  static inline Environment* New(v8::Local<v8::Context> context,
                                 uv_loop_t* loop);
  inline void CleanupHandles();
  inline void Dispose();

  // Defined in src/node_profiler.cc.
  void StartGarbageCollectionTracking(v8::Local<v8::Function> callback);
  void StopGarbageCollectionTracking();

  void AssignToContext(v8::Local<v8::Context> context);

  inline v8::Isolate* isolate() const;
  inline uv_loop_t* event_loop() const;
  inline bool call_async_init_hook() const;
  inline bool in_domain() const;
  inline uint32_t watched_providers() const;

  static inline Environment* from_immediate_check_handle(uv_check_t* handle);
  inline uv_check_t* immediate_check_handle();
  inline uv_idle_t* immediate_idle_handle();

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

  static inline Environment* from_cares_timer_handle(uv_timer_t* handle);
  inline uv_timer_t* cares_timer_handle();
  inline ares_channel cares_channel();
  inline ares_channel* cares_channel_ptr();
  inline ares_task_list* cares_task_list();

  inline bool using_smalloc_alloc_cb() const;
  inline void set_using_smalloc_alloc_cb(bool value);

  inline bool using_domains() const;
  inline void set_using_domains(bool value);

  inline bool using_asyncwrap() const;
  inline void set_using_asyncwrap(bool value);

  inline bool printed_error() const;
  inline void set_printed_error(bool value);

  inline void ThrowError(const char* errmsg);
  inline void ThrowTypeError(const char* errmsg);
  inline void ThrowRangeError(const char* errmsg);
  inline void ThrowErrnoException(int errorno,
                                  const char* syscall = NULL,
                                  const char* message = NULL,
                                  const char* path = NULL);
  inline void ThrowUVException(int errorno,
                               const char* syscall = NULL,
                               const char* message = NULL,
                               const char* path = NULL);

  // Convenience methods for contextify
  inline static void ThrowError(v8::Isolate* isolate, const char* errmsg);
  inline static void ThrowTypeError(v8::Isolate* isolate, const char* errmsg);
  inline static void ThrowRangeError(v8::Isolate* isolate, const char* errmsg);

  // Strings are shared across shared contexts. The getters simply proxy to
  // the per-isolate primitive.
#define V(PropertyName, StringValue)                                          \
  inline v8::Local<v8::String> PropertyName() const;
  PER_ISOLATE_STRING_PROPERTIES(V)
#undef V

#define V(PropertyName, TypeName)                                             \
  inline v8::Local<TypeName> PropertyName() const;                            \
  inline void set_ ## PropertyName(v8::Local<TypeName> value);
  ENVIRONMENT_STRONG_PERSISTENT_PROPERTIES(V)
#undef V

  inline debugger::Agent* debugger_agent() {
    return &debugger_agent_;
  }

  inline QUEUE* handle_wrap_queue() { return &handle_wrap_queue_; }
  inline QUEUE* req_wrap_queue() { return &req_wrap_queue_; }

 private:
  static const int kIsolateSlot = NODE_ISOLATE_SLOT;

  class GCInfo;
  class IsolateData;
  inline Environment(v8::Local<v8::Context> context, uv_loop_t* loop);
  inline ~Environment();
  inline IsolateData* isolate_data() const;
  void AfterGarbageCollectionCallback(const GCInfo* before,
                                      const GCInfo* after);

  enum ContextEmbedderDataIndex {
    kContextEmbedderDataIndex = NODE_CONTEXT_EMBEDDER_DATA_INDEX
  };

  v8::Isolate* const isolate_;
  IsolateData* const isolate_data_;
  uv_check_t immediate_check_handle_;
  uv_idle_t immediate_idle_handle_;
  uv_prepare_t idle_prepare_handle_;
  uv_check_t idle_check_handle_;
  AsyncHooks async_hooks_;
  DomainFlag domain_flag_;
  TickInfo tick_info_;
  uv_timer_t cares_timer_handle_;
  ares_channel cares_channel_;
  ares_task_list cares_task_list_;
  bool using_smalloc_alloc_cb_;
  bool using_domains_;
  bool using_asyncwrap_;
  QUEUE gc_tracker_queue_;
  bool printed_error_;
  debugger::Agent debugger_agent_;

  QUEUE handle_wrap_queue_;
  QUEUE req_wrap_queue_;
  QUEUE handle_cleanup_queue_;
  int handle_cleanup_waiting_;

#define V(PropertyName, TypeName)                                             \
  v8::Persistent<TypeName> PropertyName ## _;
  ENVIRONMENT_STRONG_PERSISTENT_PROPERTIES(V)
#undef V

  class GCInfo {
   public:
    inline GCInfo();
    inline GCInfo(v8::Isolate* isolate,
                  v8::GCType type,
                  v8::GCCallbackFlags flags,
                  uint64_t timestamp);
    inline v8::GCType type() const;
    inline v8::GCCallbackFlags flags() const;
    // TODO(bnoordhuis) Const-ify once https://codereview.chromium.org/63693005
    // lands and makes it way into a stable release.
    inline v8::HeapStatistics* stats() const;
    inline uint64_t timestamp() const;
   private:
    v8::GCType type_;
    v8::GCCallbackFlags flags_;
    v8::HeapStatistics stats_;
    uint64_t timestamp_;
  };

  // Per-thread, reference-counted singleton.
  class IsolateData {
   public:
    static inline IsolateData* GetOrCreate(v8::Isolate* isolate,
                                           uv_loop_t* loop);
    inline void Put();
    inline uv_loop_t* event_loop() const;

    // Defined in src/node_profiler.cc.
    void StartGarbageCollectionTracking(Environment* env);
    void StopGarbageCollectionTracking(Environment* env);

#define V(PropertyName, StringValue)                                          \
    inline v8::Local<v8::String> PropertyName() const;
    PER_ISOLATE_STRING_PROPERTIES(V)
#undef V

   private:
    inline static IsolateData* Get(v8::Isolate* isolate);
    inline explicit IsolateData(v8::Isolate* isolate, uv_loop_t* loop);
    inline v8::Isolate* isolate() const;

    // Defined in src/node_profiler.cc.
    static void BeforeGarbageCollection(v8::Isolate* isolate,
                                        v8::GCType type,
                                        v8::GCCallbackFlags flags);
    static void AfterGarbageCollection(v8::Isolate* isolate,
                                       v8::GCType type,
                                       v8::GCCallbackFlags flags);
    void BeforeGarbageCollection(v8::GCType type, v8::GCCallbackFlags flags);
    void AfterGarbageCollection(v8::GCType type, v8::GCCallbackFlags flags);

    uv_loop_t* const event_loop_;
    v8::Isolate* const isolate_;

#define V(PropertyName, StringValue)                                          \
    v8::Eternal<v8::String> PropertyName ## _;
    PER_ISOLATE_STRING_PROPERTIES(V)
#undef V

    unsigned int ref_count_;
    QUEUE gc_tracker_queue_;
    GCInfo gc_info_before_;
    GCInfo gc_info_after_;

    DISALLOW_COPY_AND_ASSIGN(IsolateData);
  };

  DISALLOW_COPY_AND_ASSIGN(Environment);
};

}  // namespace node

#endif  // SRC_ENV_H_
