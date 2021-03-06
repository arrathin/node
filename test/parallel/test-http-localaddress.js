'use strict';
const common = require('../common');
if (!common.hasMultiLocalhost())
  common.skip('platform-specific test.');

const http = require('http');
const assert = require('assert');

const server = http.createServer(function(req, res) {
  console.log(`Connect from: ${req.connection.remoteAddress}`);
  assert.strictEqual('127.0.0.2', req.connection.remoteAddress);

  req.on('end', function() {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(`You are from: ${req.connection.remoteAddress}`);
  });
  req.resume();
});

server.listen(0, '127.0.0.1', function() {
  const options = { host: 'localhost',
                    port: this.address().port,
                    path: '/',
                    method: 'GET',
                    localAddress: '127.0.0.2' };

  const req = http.request(options, function(res) {
    res.on('end', function() {
      server.close();
      process.exit();
    });
    res.resume();
  });
  req.end();
});
