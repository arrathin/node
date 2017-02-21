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

var common = require('../common');
var assert = require('assert');
var fork = require('child_process').fork;
var N = 4 << 20;  // 4 MB
var timeout = 100;

if (process.platform == 'os390') {
  timeout = 5000;
}

for (var big = '*'; big.length < N; big += big);

if (process.argv[2] === 'child') {
  process.send(big);
  setTimeout(function () {
    process.exit(42);
  }, timeout)
}

var proc = fork(__filename, ['child']);

proc.on('message', common.mustCall(function(msg) {
  assert.equal(typeof msg, 'string');
  assert.equal(msg.length, N);
  assert.equal(msg, big);
}));

proc.on('exit', common.mustCall(function(exitCode) {
  assert.equal(exitCode, 42);
}));
