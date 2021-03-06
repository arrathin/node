'use strict';
// just like test/gc/http-client.js,
// but aborting every connection that comes in.

require('../common');

function serverHandler(req, res) {
  res.connection.destroy();
}

const http = require('http');
const weak = require('weak');
const assert = require('assert');
const todo = 500;
let done = 0;
let count = 0;
let countGC = 0;

console.log(`We should do ${todo} requests`);

const server = http.createServer(serverHandler);
server.listen(0, getall);

function getall() {
  if (count >= todo)
    return;

  (function() {
    function cb(res) {
      done += 1;
      statusLater();
    }

    const req = http.get({
      hostname: 'localhost',
      pathname: '/',
      port: server.address().port
    }, cb).on('error', cb);

    count++;
    weak(req, afterGC);
  })();

  setImmediate(getall);
}

for (let i = 0; i < 10; i++)
  getall();

function afterGC() {
  countGC++;
}

let timer;
function statusLater() {
  global.gc();
  if (timer) clearTimeout(timer);
  timer = setTimeout(status, 1);
}

function status() {
  global.gc();
  console.log('Done: %d/%d', done, todo);
  console.log('Collected: %d/%d', countGC, count);
  if (done === todo) {
    console.log('All should be collected now.');
    assert.strictEqual(count, countGC);
    process.exit(0);
  }
}
