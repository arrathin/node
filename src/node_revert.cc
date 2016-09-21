// Copyright Node Contributors.
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
#include "node_revert.h"
#include <stdio.h>
#include <string.h>

namespace node {

unsigned int reverted = 0;

const char* RevertMessage(const unsigned int cve) {
#define V(code, label, msg) case REVERT_ ## code: return label "\x3a\x20" msg;
  switch (cve) {
    REVERSIONS(V)
    default:
      return "\x55\x6e\x6b\x6e\x6f\x77\x6e";
  }
#undef V
}

void Revert(const unsigned int cve) {
  reverted |= 1 << cve;
  printf("\x53\x45\x43\x55\x52\x49\x54\x59\x20\x57\x41\x52\x4e\x49\x4e\x47\x3a\x20\x52\x65\x76\x65\x72\x74\x69\x6e\x67\x20\x6c\xa2\xa", RevertMessage(cve));
}

void Revert(const char* cve) {
#define V(code, label, _)                                                     \
  do {                                                                        \
    if (strcmp(cve, label) == 0) {                                            \
      Revert(static_cast<unsigned int>(REVERT_ ## code));                     \
      return;                                                                 \
    }                                                                         \
  } while (0);
  REVERSIONS(V)
#undef V
  printf("\x45\x72\x72\x6f\x72\x3a\x20\x41\x74\x74\x65\x6d\x70\x74\x20\x74\x6f\x20\x72\x65\x76\x65\x72\x74\x20\x61\x6e\x20\x75\x6e\x6b\x6e\x6f\x77\x6e\x20\x43\x56\x45\x20\x5b\x6c\xa2\x5d\xa", cve);
  exit(12);
}

bool IsReverted(const unsigned int cve) {
  return reverted & (1 << cve);
}

bool IsReverted(const char * cve) {
#define V(code, label, _)                                                     \
  do {                                                                        \
    if (strcmp(cve, label) == 0)                                              \
      return IsReverted(static_cast<unsigned int>(REVERT_ ## code));          \
  } while (0);
  REVERSIONS(V)
  return false;
#undef V
}

}  // namespace node
