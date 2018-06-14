'use strict';
const common = require('../common');

const assert = require('assert');
const exec = require('child_process').exec;

const cmd = `${process.execPath} --help | grep "Usage: node"`

exec(cmd, common.mustCall((error, stdout, stderr) => {
  assert.strictEqual(stderr, '');

  // omitting trailing whitespace and \n
  assert.strictEqual(stdout.replace(/\s+$/, '').startsWith("Usage: node"), true);
}));
