'use strict';
const common = require('../../common');
const assert = require('assert');

let re = /^Error: Module did not self-register\.$/;

assert.throws(() => require(`./build/${common.buildType}/binding`), re);
