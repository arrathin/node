'use strict';
const common = require('../common');
if (!common.hasCrypto)
  common.skip('missing crypto');

const assert = require('assert');
const fs = require('fs');
const https = require('https');

const options = {
  key: fs.readFileSync(`${common.fixturesDir}/keys/agent1-key.pem`),
  cert: fs.readFileSync(`${common.fixturesDir}/keys/agent1-cert.pem`)
};

process.stdout.write('build body...');
const body = 'hello world\n'.repeat(1024 * 1024);
process.stdout.write('done\n');

const server = https.createServer(options, common.mustCall(function(req, res) {
  console.log('got request');
  res.writeHead(200, { 'content-type': 'text/plain' });
  res.end(body);
}));

server.listen(common.PORT, common.mustCall(function() {
  https.get({
    port: common.PORT,
    rejectUnauthorized: false
  }, common.mustCall(function(res) {
    console.log('response!');

    let count = 0;

    res.on('data', function(d) {
      process.stdout.write('.');
      count += d.length;
      res.pause();
      process.nextTick(function() {
        res.resume();
      });
    });

    res.on('end', common.mustCall(function(d) {
      process.stdout.write('\n');
      console.log('expected: ', body.length);
      console.log('     got: ', count);
      server.close();
      assert.strictEqual(count, body.length);
    }));
  }));
}));
