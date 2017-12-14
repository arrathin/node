'use strict';
const common = require('../../common');
const assert = require('assert');

if (common.isZos) {
  const re = /^Error: CEE3552S/;
  assert.throws(() => require(`./build/${common.buildType}/binding`), re);
}
else {
  const re = /^Error: Module did not self-register\.$/;
  assert.throws(() => require(`./build/${common.buildType}/binding`), re);
}
