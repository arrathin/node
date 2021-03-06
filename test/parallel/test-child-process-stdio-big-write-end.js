'use strict';
const common = require('../common');
const assert = require('assert');
let bufsize = 0;

switch (process.argv[2]) {
  case undefined:
    return parent();
  case 'child':
    return child();
  default:
    throw new Error('invalid');
}

function parent() {
  const spawn = require('child_process').spawn;
  const child = spawn(process.execPath, [__filename, 'child']);
  let sent = 0;

  let n = '';
  child.stdout.setEncoding('ascii');
  child.stdout.on('data', function(c) {
    n += c;
  });
  child.stdout.on('end', common.mustCall(function() {
    assert.strictEqual(+n, sent);
    console.log('ok');
  }));

  // Write until the buffer fills up.
  let buf;
  do {
    bufsize += 1024;
    buf = Buffer.alloc(bufsize, '.');
    sent += bufsize;
  } while (child.stdin.write(buf));

  // then write a bunch more times.
  for (let i = 0; i < 100; i++) {
    const buf = Buffer.alloc(bufsize, '.');
    sent += bufsize;
    child.stdin.write(buf);
  }

  // now end, before it's all flushed.
  child.stdin.end();

  // now we wait...
}

function child() {
  let received = 0;
  process.stdin.on('data', function(c) {
    received += c.length;
  });
  process.stdin.on('end', function() {
    console.log(received);
  });
}
