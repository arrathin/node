#include "env-inl.h"
#include "node_report.h"
#include "debug_utils.h"
#include "diagnosticfilename-inl.h"
#include "node_internals.h"
#include "node_metadata.h"
#include "util.h"

#ifdef _WIN32
#include <Windows.h>
#else  // !_WIN32
#include <sys/resource.h>
#include <cxxabi.h>
#include <dlfcn.h>
#endif

#include <cstring>
#include <ctime>
#include <cwctype>
#include <fstream>
#include <iomanip>

#ifdef __MVS__
#define OPEN_MODE std::ios::out
#else
#define OPEN_MODE std::ios::out | std::ios::binary
#endif

constexpr int NODE_REPORT_VERSION = 1;
constexpr int NANOS_PER_SEC = 1000 * 1000 * 1000;
constexpr double SEC_PER_MICROS = 1e-6;

namespace report {
using node::arraysize;
using node::DiagnosticFilename;
using node::Environment;
using node::Mutex;
using node::NativeSymbolDebuggingContext;
using node::PerIsolateOptions;
using node::TIME_TYPE;
using v8::HeapSpaceStatistics;
using v8::HeapStatistics;
using v8::Isolate;
using v8::Local;
using v8::Number;
using v8::StackTrace;
using v8::String;
using v8::V8;
using v8::Value;

// Internal/static function declarations
static void WriteNodeReport(Isolate* isolate,
                            Environment* env,
                            const char* message,
                            const char* trigger,
                            const std::string& filename,
                            std::ostream& out,
                            Local<String> stackstr);
static void PrintVersionInformation(JSONWriter* writer);
static void PrintJavaScriptStack(JSONWriter* writer,
                                 Isolate* isolate,
                                 Local<String> stackstr,
                                 const char* trigger);
static void PrintNativeStack(JSONWriter* writer);
static void PrintResourceUsage(JSONWriter* writer);
static void PrintGCStatistics(JSONWriter* writer, Isolate* isolate);
static void PrintSystemInformation(JSONWriter* writer);
static void PrintLoadedLibraries(JSONWriter* writer);
static void PrintComponentVersions(JSONWriter* writer);
static void PrintRelease(JSONWriter* writer);
static void PrintCpuInfo(JSONWriter* writer);
static void PrintNetworkInterfaceInfo(JSONWriter* writer);

// External function to trigger a report, writing to file.
// The 'name' parameter is in/out: an input filename is used
// if supplied, and the actual filename is returned.
std::string TriggerNodeReport(Isolate* isolate,
                              Environment* env,
                              const char* message,
                              const char* trigger,
                              const std::string& name,
                              Local<String> stackstr) {
  std::string filename;
  std::shared_ptr<PerIsolateOptions> options;
  if (env != nullptr) options = env->isolate_data()->options();

  // Determine the required report filename. In order of priority:
  //   1) supplied on API 2) configured on startup 3) default generated
  if (!name.empty()) {
    // Filename was specified as API parameter.
    filename = name;
  } else if (env != nullptr && options->report_filename.length() > 0) {
    // File name was supplied via start-up option.
    filename = options->report_filename;
  } else {
    filename = *DiagnosticFilename(env != nullptr ? env->thread_id() : 0,
                                   "report", "json");
  }

  // Open the report file stream for writing. Supports stdout/err,
  // user-specified or (default) generated name
  std::ofstream outfile;
  std::ostream* outstream;
  if (filename == "stdout") {
    outstream = &std::cout;
  } else if (filename == "stderr") {
    outstream = &std::cerr;
  } else {
    // Regular file. Append filename to directory path if one was specified
    if (env != nullptr && options->report_directory.length() > 0) {
      std::string pathname = options->report_directory;
      pathname += node::kPathSeparator;
      pathname += filename;
      outfile.open(pathname, OPEN_MODE);
    } else {
      outfile.open(filename, OPEN_MODE);
    }
    // Check for errors on the file open
    if (!outfile.is_open()) {
      std::cerr << std::endl
                << "Failed to open Node.js report file: " << filename;

      if (env != nullptr && options->report_directory.length() > 0)
        std::cerr << " directory: " << options->report_directory;

      std::cerr << " (errno: " << errno << ")" << std::endl;
      return "";
    }
    outstream = &outfile;
    std::cerr << std::endl << "Writing Node.js report to file: " << filename;
  }

  WriteNodeReport(isolate, env, message, trigger, filename, *outstream,
                  stackstr);

  // Do not close stdout/stderr, only close files we opened.
  if (outfile.is_open()) {
    outfile.close();
  }

  std::cerr << std::endl << "Node.js report completed" << std::endl;
  return filename;
}

// External function to trigger a report, writing to a supplied stream.
void GetNodeReport(Isolate* isolate,
                   Environment* env,
                   const char* message,
                   const char* trigger,
                   Local<String> stackstr,
                   std::ostream& out) {
  WriteNodeReport(isolate, env, message, trigger, "", out, stackstr);
}

// Internal function to coordinate and write the various
// sections of the report to the supplied stream
static void WriteNodeReport(Isolate* isolate,
                            Environment* env,
                            const char* message,
                            const char* trigger,
                            const std::string& filename,
                            std::ostream& out,
                            Local<String> stackstr) {
  // Obtain the current time and the pid.
  TIME_TYPE tm_struct;
  DiagnosticFilename::LocalTime(&tm_struct);
  uv_pid_t pid = uv_os_getpid();

  // Save formatting for output stream.
  std::ios old_state(nullptr);
  old_state.copyfmt(out);

  // File stream opened OK, now start printing the report content:
  // the title and header information (event, filename, timestamp and pid)

  JSONWriter writer(out);
  writer.json_start();
  writer.json_objectstart("header");
  writer.json_keyvalue("reportVersion", NODE_REPORT_VERSION);
  writer.json_keyvalue("event", message);
  writer.json_keyvalue("trigger", trigger);
  if (!filename.empty())
    writer.json_keyvalue("filename", filename);
  else
    writer.json_keyvalue("filename", JSONWriter::Null{});

  // Report dump event and module load date/time stamps
  char timebuf[64];
#ifdef _WIN32
  snprintf(timebuf,
           sizeof(timebuf),
           "%4d-%02d-%02dT%02d:%02d:%02dZ",
           tm_struct.wYear,
           tm_struct.wMonth,
           tm_struct.wDay,
           tm_struct.wHour,
           tm_struct.wMinute,
           tm_struct.wSecond);
  writer.json_keyvalue("dumpEventTime", timebuf);
#else  // UNIX, OSX
  snprintf(timebuf,
           sizeof(timebuf),
           "%4d-%02d-%02dT%02d:%02d:%02dZ",
           tm_struct.tm_year + 1900,
           tm_struct.tm_mon + 1,
           tm_struct.tm_mday,
           tm_struct.tm_hour,
           tm_struct.tm_min,
           tm_struct.tm_sec);
  writer.json_keyvalue("dumpEventTime", timebuf);
#endif

  uv_timeval64_t ts;
  if (uv_gettimeofday(&ts) == 0) {
    writer.json_keyvalue("dumpEventTimeStamp",
                         std::to_string(ts.tv_sec * 1000 + ts.tv_usec / 1000));
  }

  // Report native process ID
  writer.json_keyvalue("processId", pid);

  {
    // Report the process cwd.
    char buf[PATH_MAX_BYTES];
    size_t cwd_size = sizeof(buf);
    if (uv_cwd(buf, &cwd_size) == 0)
      writer.json_keyvalue("cwd", buf);
  }

  // Report out the command line.
  if (!node::per_process::cli_options->cmdline.empty()) {
    writer.json_arraystart("commandLine");
    for (const std::string& arg : node::per_process::cli_options->cmdline) {
      writer.json_element(arg);
    }
    writer.json_arrayend();
  }

  // Report Node.js and OS version information
  PrintVersionInformation(&writer);
  writer.json_objectend();

  // Report summary JavaScript stack backtrace
  PrintJavaScriptStack(&writer, isolate, stackstr, trigger);

  // Report native stack backtrace
  PrintNativeStack(&writer);

  // Report V8 Heap and Garbage Collector information
  PrintGCStatistics(&writer, isolate);

  // Report OS and current thread resource usage
  PrintResourceUsage(&writer);

  writer.json_arraystart("libuv");
  if (env != nullptr) {
    uv_walk(env->event_loop(), WalkHandle, static_cast<void*>(&writer));

    writer.json_start();
    writer.json_keyvalue("type", "loop");
    writer.json_keyvalue("is_active",
        static_cast<bool>(uv_loop_alive(env->event_loop())));
    writer.json_keyvalue("address",
        ValueToHexString(reinterpret_cast<int64_t>(env->event_loop())));
    writer.json_end();
  }

  writer.json_arrayend();

  // Report operating system information
  PrintSystemInformation(&writer);

  writer.json_objectend();

  // Restore output stream formatting.
  out.copyfmt(old_state);
}

// Report Node.js version, OS version and machine information.
static void PrintVersionInformation(JSONWriter* writer) {
  std::ostringstream buf;
  // Report Node version
  buf << "v" << NODE_VERSION_STRING;
  writer->json_keyvalue("nodejsVersion", buf.str());
  buf.str("");

#if !defined(_WIN32) && !defined(__MVS__)
  // Report compiler and runtime glibc versions where possible.
  const char* (*libc_version)();
  *(reinterpret_cast<void**>(&libc_version)) =
      dlsym(RTLD_DEFAULT, "gnu_get_libc_version");
  if (libc_version != nullptr)
    writer->json_keyvalue("glibcVersionRuntime", (*libc_version)());
#endif /* _WIN32 */

#if defined(__GLIBC__) 
  buf << __GLIBC__ << "." << __GLIBC_MINOR__;
  writer->json_keyvalue("glibcVersionCompiler", buf.str());
  buf.str("");
#endif

#ifdef __MVS__
    char *r;
    __asm(" llgt %0,1208 \n"
          " lg   %0,88(%0) \n"
          " lg   %0,8(%0) \n"
          " lg   %0,984(%0) \n"
          : "=r"(r)::);
    if (r != NULL) {
      const char *prod = (int)r[80]==4 ? " (MVS LE)" : "";
      buf << "\nProduct " << (int)r[80] << prod << " Version " << (int)r[81] << " Release " << (int)r[82] << " Modification " << (int)r[83];
    }
  writer->json_keyvalue("leVersion", buf.str());
  buf.str("");
#endif

  // Report Process word size
  writer->json_keyvalue("wordSize", sizeof(void*) * 8);
  writer->json_keyvalue("arch", node::per_process::metadata.arch);
  writer->json_keyvalue("platform", node::per_process::metadata.platform);

  // Report deps component versions
  PrintComponentVersions(writer);

  // Report release metadata.
  PrintRelease(writer);

  // Report operating system and machine information
  uv_utsname_t os_info;

  if (uv_os_uname(&os_info) == 0) {
    writer->json_keyvalue("osName", os_info.sysname);
    writer->json_keyvalue("osRelease", os_info.release);
    writer->json_keyvalue("osVersion", os_info.version);
    writer->json_keyvalue("osMachine", os_info.machine);
  }

  PrintCpuInfo(writer);
  PrintNetworkInterfaceInfo(writer);

  char host[UV_MAXHOSTNAMESIZE];
  size_t host_size = sizeof(host);

  if (uv_os_gethostname(host, &host_size) == 0)
    writer->json_keyvalue("host", host);
}

// Report CPU info
static void PrintCpuInfo(JSONWriter* writer) {
  uv_cpu_info_t* cpu_info;
  int count;
  if (uv_cpu_info(&cpu_info, &count) == 0) {
    writer->json_arraystart("cpus");
    for (int i = 0; i < count; i++) {
      writer->json_start();
      writer->json_keyvalue("model", cpu_info[i].model);
      writer->json_keyvalue("speed", cpu_info[i].speed);
      writer->json_keyvalue("user", cpu_info[i].cpu_times.user);
      writer->json_keyvalue("nice", cpu_info[i].cpu_times.nice);
      writer->json_keyvalue("sys", cpu_info[i].cpu_times.sys);
      writer->json_keyvalue("idle", cpu_info[i].cpu_times.idle);
      writer->json_keyvalue("irq", cpu_info[i].cpu_times.irq);
      writer->json_end();
    }
    writer->json_arrayend();
    uv_free_cpu_info(cpu_info, count);
  }
}

static void PrintNetworkInterfaceInfo(JSONWriter* writer) {
  uv_interface_address_t* interfaces;
  char ip[INET6_ADDRSTRLEN];
  char netmask[INET6_ADDRSTRLEN];
  char mac[18];
  int count;

  if (uv_interface_addresses(&interfaces, &count) == 0) {
    writer->json_arraystart("networkInterfaces");

    for (int i = 0; i < count; i++) {
      writer->json_start();
      writer->json_keyvalue("name", interfaces[i].name);
      writer->json_keyvalue("internal", !!interfaces[i].is_internal);
      snprintf(mac,
               sizeof(mac),
               "%02x:%02x:%02x:%02x:%02x:%02x",
               static_cast<unsigned char>(interfaces[i].phys_addr[0]),
               static_cast<unsigned char>(interfaces[i].phys_addr[1]),
               static_cast<unsigned char>(interfaces[i].phys_addr[2]),
               static_cast<unsigned char>(interfaces[i].phys_addr[3]),
               static_cast<unsigned char>(interfaces[i].phys_addr[4]),
               static_cast<unsigned char>(interfaces[i].phys_addr[5]));
      writer->json_keyvalue("mac", mac);

      if (interfaces[i].address.address4.sin_family == AF_INET) {
        uv_ip4_name(&interfaces[i].address.address4, ip, sizeof(ip));
        uv_ip4_name(&interfaces[i].netmask.netmask4, netmask, sizeof(netmask));
        writer->json_keyvalue("address", ip);
        writer->json_keyvalue("netmask", netmask);
        writer->json_keyvalue("family", "IPv4");
      } else if (interfaces[i].address.address4.sin_family == AF_INET6) {
        uv_ip6_name(&interfaces[i].address.address6, ip, sizeof(ip));
        uv_ip6_name(&interfaces[i].netmask.netmask6, netmask, sizeof(netmask));
        writer->json_keyvalue("address", ip);
        writer->json_keyvalue("netmask", netmask);
        writer->json_keyvalue("family", "IPv6");
        writer->json_keyvalue("scopeid",
                              interfaces[i].address.address6.sin6_scope_id);
      } else {
        writer->json_keyvalue("family", "unknown");
      }

      writer->json_end();
    }

    writer->json_arrayend();
    uv_free_interface_addresses(interfaces, count);
  }
}

// Report the JavaScript stack.
static void PrintJavaScriptStack(JSONWriter* writer,
                                 Isolate* isolate,
                                 Local<String> stackstr,
                                 const char* trigger) {
  writer->json_objectstart("javascriptStack");

  std::string ss;
  if ((!strcmp(trigger, "FatalError")) ||
      (!strcmp(trigger, "Signal"))) {
    ss = "No stack.\nUnavailable.\n";
  } else {
    String::Utf8Value sv(isolate, stackstr);
    ss = std::string(*sv, sv.length());
  }
  int line = ss.find('\n');
  if (line == -1) {
    writer->json_keyvalue("message", ss);
  } else {
    std::string l = ss.substr(0, line);
    writer->json_keyvalue("message", l);
    writer->json_arraystart("stack");
    ss = ss.substr(line + 1);
    line = ss.find('\n');
    while (line != -1) {
      l = ss.substr(0, line);
      l.erase(l.begin(), std::find_if(l.begin(), l.end(), [](int ch) {
                return !std::iswspace(ch);
              }));
      writer->json_element(l);
      ss = ss.substr(line + 1);
      line = ss.find('\n');
    }
    writer->json_arrayend();
  }
  writer->json_objectend();
}

// Report a native stack backtrace
static void PrintNativeStack(JSONWriter* writer) {
  auto sym_ctx = NativeSymbolDebuggingContext::New();
  void* frames[256];
  const int size = sym_ctx->GetStackTrace(frames, arraysize(frames));
  writer->json_arraystart("nativeStack");
  int i;
  for (i = 1; i < size; i++) {
    void* frame = frames[i];
    writer->json_start();
    writer->json_keyvalue("pc",
                          ValueToHexString(reinterpret_cast<uintptr_t>(frame)));
    writer->json_keyvalue("symbol", sym_ctx->LookupSymbol(frame).Display());
    writer->json_end();
  }
  writer->json_arrayend();
}

// Report V8 JavaScript heap information.
// This uses the existing V8 HeapStatistics and HeapSpaceStatistics APIs.
// The isolate->GetGCStatistics(&heap_stats) internal V8 API could potentially
// provide some more useful information - the GC history and the handle counts
static void PrintGCStatistics(JSONWriter* writer, Isolate* isolate) {
  HeapStatistics v8_heap_stats;
  isolate->GetHeapStatistics(&v8_heap_stats);
  HeapSpaceStatistics v8_heap_space_stats;

  writer->json_objectstart("javascriptHeap");
  writer->json_keyvalue("totalMemory", v8_heap_stats.total_heap_size());
  writer->json_keyvalue("totalCommittedMemory",
                        v8_heap_stats.total_physical_size());
  writer->json_keyvalue("usedMemory", v8_heap_stats.used_heap_size());
  writer->json_keyvalue("availableMemory",
                        v8_heap_stats.total_available_size());
  writer->json_keyvalue("memoryLimit", v8_heap_stats.heap_size_limit());

  writer->json_objectstart("heapSpaces");
  // Loop through heap spaces
  for (size_t i = 0; i < isolate->NumberOfHeapSpaces(); i++) {
    isolate->GetHeapSpaceStatistics(&v8_heap_space_stats, i);
    writer->json_objectstart(v8_heap_space_stats.space_name());
    writer->json_keyvalue("memorySize", v8_heap_space_stats.space_size());
    writer->json_keyvalue(
        "committedMemory",
        v8_heap_space_stats.physical_space_size());
    writer->json_keyvalue(
        "capacity",
        v8_heap_space_stats.space_used_size() +
            v8_heap_space_stats.space_available_size());
    writer->json_keyvalue("used", v8_heap_space_stats.space_used_size());
    writer->json_keyvalue(
        "available", v8_heap_space_stats.space_available_size());
    writer->json_objectend();
  }

  writer->json_objectend();
  writer->json_objectend();
}

static void PrintResourceUsage(JSONWriter* writer) {
  // Get process uptime in seconds
  uint64_t uptime =
      (uv_hrtime() - node::per_process::node_start_time) / (NANOS_PER_SEC);
  if (uptime == 0) uptime = 1;  // avoid division by zero.

  // Process and current thread usage statistics
  uv_rusage_t rusage;
  writer->json_objectstart("resourceUsage");
  if (uv_getrusage(&rusage) == 0) {
    double user_cpu =
        rusage.ru_utime.tv_sec + SEC_PER_MICROS * rusage.ru_utime.tv_usec;
    double kernel_cpu =
        rusage.ru_stime.tv_sec + SEC_PER_MICROS * rusage.ru_stime.tv_usec;
    writer->json_keyvalue("userCpuSeconds", user_cpu);
    writer->json_keyvalue("kernelCpuSeconds", kernel_cpu);
    double cpu_abs = user_cpu + kernel_cpu;
    double cpu_percentage = (cpu_abs / uptime) * 100.0;
    writer->json_keyvalue("cpuConsumptionPercent", cpu_percentage);
    writer->json_keyvalue("maxRss", rusage.ru_maxrss * 1024);
    writer->json_objectstart("pageFaults");
    writer->json_keyvalue("IORequired", rusage.ru_majflt);
    writer->json_keyvalue("IONotRequired", rusage.ru_minflt);
    writer->json_objectend();
    writer->json_objectstart("fsActivity");
    writer->json_keyvalue("reads", rusage.ru_inblock);
    writer->json_keyvalue("writes", rusage.ru_oublock);
    writer->json_objectend();
  }
  writer->json_objectend();
#ifdef RUSAGE_THREAD
  struct rusage stats;
  if (getrusage(RUSAGE_THREAD, &stats) == 0) {
    writer->json_objectstart("uvthreadResourceUsage");
    double user_cpu =
        stats.ru_utime.tv_sec + SEC_PER_MICROS * stats.ru_utime.tv_usec;
    double kernel_cpu =
        stats.ru_stime.tv_sec + SEC_PER_MICROS * stats.ru_stime.tv_usec;
    writer->json_keyvalue("userCpuSeconds", user_cpu);
    writer->json_keyvalue("kernelCpuSeconds", kernel_cpu);
    double cpu_abs = user_cpu + kernel_cpu;
    double cpu_percentage = (cpu_abs / uptime) * 100.0;
    writer->json_keyvalue("cpuConsumptionPercent", cpu_percentage);
    writer->json_objectstart("fsActivity");
    writer->json_keyvalue("reads", stats.ru_inblock);
    writer->json_keyvalue("writes", stats.ru_oublock);
    writer->json_objectend();
    writer->json_objectend();
  }
#endif
}

// Report operating system information.
static void PrintSystemInformation(JSONWriter* writer) {
  uv_env_item_t* envitems;
  int envcount;
  int r;

  writer->json_objectstart("environmentVariables");

  {
    Mutex::ScopedLock lock(node::per_process::env_var_mutex);
    r = uv_os_environ(&envitems, &envcount);
  }

  if (r == 0) {
    for (int i = 0; i < envcount; i++)
      writer->json_keyvalue(envitems[i].name, envitems[i].value);

    uv_os_free_environ(envitems, envcount);
  }

  writer->json_objectend();

#ifndef _WIN32
  static struct {
    const char* description;
    int id;
  } rlimit_strings[] = {
    {"core_file_size_blocks", RLIMIT_CORE},
    {"data_seg_size_kbytes", RLIMIT_DATA},
    {"file_size_blocks", RLIMIT_FSIZE},
#if !(defined(_AIX) || defined(__sun) || defined(__MVS__))
    {"max_locked_memory_bytes", RLIMIT_MEMLOCK},
#endif
#if !(defined(__sun) || defined(__MVS__))
    {"max_memory_size_kbytes", RLIMIT_RSS},
#endif
    {"open_files", RLIMIT_NOFILE},
    {"stack_size_bytes", RLIMIT_STACK},
    {"cpu_time_seconds", RLIMIT_CPU},
#if !(defined(__sun) || defined(__MVS__))
    {"max_user_processes", RLIMIT_NPROC},
#endif
#ifndef __OpenBSD__
    {"virtual_memory_kbytes", RLIMIT_AS}
#endif
  };

  writer->json_objectstart("userLimits");
  struct rlimit limit;
  std::string soft, hard;

  for (size_t i = 0; i < arraysize(rlimit_strings); i++) {
    if (getrlimit(rlimit_strings[i].id, &limit) == 0) {
      writer->json_objectstart(rlimit_strings[i].description);

      if (limit.rlim_cur == RLIM_INFINITY)
        writer->json_keyvalue("soft", "unlimited");
      else
        writer->json_keyvalue("soft", limit.rlim_cur);

      if (limit.rlim_max == RLIM_INFINITY)
        writer->json_keyvalue("hard", "unlimited");
      else
        writer->json_keyvalue("hard", limit.rlim_max);

      writer->json_objectend();
    }
  }
  writer->json_objectend();
#endif  // _WIN32

  PrintLoadedLibraries(writer);
}

// Report a list of loaded native libraries.
static void PrintLoadedLibraries(JSONWriter* writer) {
  writer->json_arraystart("sharedObjects");
  std::vector<std::string> modules =
      NativeSymbolDebuggingContext::GetLoadedLibraries();
  for (auto const& module_name : modules) writer->json_element(module_name);
  writer->json_arrayend();
}

// Obtain and report the node and subcomponent version strings.
static void PrintComponentVersions(JSONWriter* writer) {
  std::stringstream buf;

  writer->json_objectstart("componentVersions");

#define V(key)                                                                 \
  writer->json_keyvalue(#key, node::per_process::metadata.versions.key);
  NODE_VERSIONS_KEYS(V)
#undef V

  writer->json_objectend();
}

// Report runtime release information.
static void PrintRelease(JSONWriter* writer) {
  writer->json_objectstart("release");
  writer->json_keyvalue("name", node::per_process::metadata.release.name);
#if NODE_VERSION_IS_LTS
  writer->json_keyvalue("lts", node::per_process::metadata.release.lts);
#endif

#ifdef NODE_HAS_RELEASE_URLS
  writer->json_keyvalue("headersUrl",
                        node::per_process::metadata.release.headers_url);
  writer->json_keyvalue("sourceUrl",
                        node::per_process::metadata.release.source_url);
#ifdef _WIN32
  writer->json_keyvalue("libUrl", node::per_process::metadata.release.lib_url);
#endif  // _WIN32
#endif  // NODE_HAS_RELEASE_URLS

  writer->json_objectend();
}

}  // namespace report
