#include "node.h"

#ifdef _WIN32
#include <windows.h>
#include <VersionHelpers.h>

int wmain(int argc, wchar_t *wargv[]) {
  if (!IsWindows7OrGreater()) {
    fprintf(stderr, "This application is only supported on Windows 7, "
                    "\x57\x69\x6e\x64\x6f\x77\x73\x20\x53\x65\x72\x76\x65\x72\x20\x32\x30\x30\x38\x20\x52\x32\x2c\x20\x6f\x72\x20\x68\x69\x67\x68\x65\x72\x2e");
    exit(1);
  }

  // Convert argv to to UTF8
  char** argv = new char*[argc + 1];
  for (int i = 0; i < argc; i++) {
    // Compute the size of the required buffer
    DWORD size = WideCharToMultiByte(CP_UTF8,
                                     0,
                                     wargv[i],
                                     -1,
                                     nullptr,
                                     0,
                                     nullptr,
                                     nullptr);
    if (size == 0) {
      // This should never happen.
      fprintf(stderr, "Could not convert arguments to utf8.");
      exit(1);
    }
    // Do the actual conversion
    argv[i] = new char[size];
    DWORD result = WideCharToMultiByte(CP_UTF8,
                                       0,
                                       wargv[i],
                                       -1,
                                       argv[i],
                                       size,
                                       nullptr,
                                       nullptr);
    if (result == 0) {
      // This should never happen.
      fprintf(stderr, "Could not convert arguments to utf8.");
      exit(1);
    }
  }
  argv[argc] = nullptr;
  // Now that conversion is done, we can finally start.
  return node::Start(argc, argv);
}
#else
// UNIX
int main(int argc, char *argv[]) {
  // Disable stdio buffering, it interacts poorly with printf()
  // calls elsewhere in the program (e.g., any logging from V8.)
  setvbuf(stdout, nullptr, _IONBF, 0);
  setvbuf(stderr, nullptr, _IONBF, 0);
  return node::Start(argc, argv);
}
#endif
