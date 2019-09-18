// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// On z/OS, this test needs a stack size of at least 204 kBytes.
// Flags: --stack-size=220
__v_0 = '(function() {\n';
for (var __v_1 = 0; __v_1 < 10000; __v_1++) {
    __v_0 += '  return function() {\n';
}
assertThrows(()=>eval(__v_0), RangeError);
