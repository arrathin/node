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

#include "node.h"

#ifdef _WIN32
int wmain(int argc, wchar_t *wargv[]) {
  // Convert argv to to UTF8
  char** argv = new char*[argc];
  for (int i = 0; i < argc; i++) {
    // Compute the size of the required buffer
    DWORD size = WideCharToMultiByte(CP_UTF8,
                                     0,
                                     wargv[i],
                                     -1,
                                     NULL,
                                     0,
                                     NULL,
                                     NULL);
    if (size == 0) {
      // This should never happen.
      fprintf(stderr, "\x43\x6f\x75\x6c\x64\x20\x6e\x6f\x74\x20\x63\x6f\x6e\x76\x65\x72\x74\x20\x61\x72\x67\x75\x6d\x65\x6e\x74\x73\x20\x74\x6f\x20\x75\x74\x66\x38\x2e");
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
                                       NULL,
                                       NULL);
    if (result == 0) {
      // This should never happen.
      fprintf(stderr, "\x43\x6f\x75\x6c\x64\x20\x6e\x6f\x74\x20\x63\x6f\x6e\x76\x65\x72\x74\x20\x61\x72\x67\x75\x6d\x65\x6e\x74\x73\x20\x74\x6f\x20\x75\x74\x66\x38\x2e");
      exit(1);
    }
  }
  // Now that conversion is done, we can finally start.
  return node::Start(argc, argv);
}
#elif defined (__MVS__)
#include <unistd.h>
int main(int argc, char *argv[]) {
  for (int i = 0; i < argc; i++)
    __e2a_s(argv[i]);
  return node::Start(argc, argv);
}
#else
// UNIX
  return node::Start(argc, argv);
}
#endif
