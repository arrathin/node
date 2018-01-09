'use strict';
const common = require('../common');
const assert = require('assert');
const child_process = require('child_process');
const spawn = child_process.spawn;
const fork = child_process.fork;

if (common.isZos)
  var execArgv = ['--stack-size=2048'];
else
  var execArgv = ['--stack-size=256'];

if (process.argv[2] === 'fork') {
  process.stdout.write(JSON.stringify(process.execArgv), function() {
    process.exit();
  });
} else if (process.argv[2] === 'child') {
  fork(__filename, ['fork']);
} else {
  const args = [__filename, 'child', 'arg0'];

  const child = spawn(process.execPath, execArgv.concat(args));
  let out = '';

  child.stdout.on('data', function(chunk) {
    out += chunk;
  });

  child.on('exit', common.mustCall(function() {
    assert.deepStrictEqual(JSON.parse(out), execArgv);
  }));
}
