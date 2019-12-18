'use strict';
const common = require('../../common');
const assert = require('assert');

let re = /^Error: Module did not self-register\.$/;

if (common.isZOS) {
  re = /^Error: CEE3552S/;
}

assert.throws(() => require(`./build/${common.buildType}/binding`), re);
