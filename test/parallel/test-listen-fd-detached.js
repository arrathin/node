'use strict';
const common = require('../common');
if (common.isWindows)
  common.skip('This test is disabled on windows.');

const assert = require('assert');
const http = require('http');
const net = require('net');
const spawn = require('child_process').spawn;

switch (process.argv[2]) {
  case 'child': return child();
  case 'parent': return parent();
  default: return test();
}

// spawn the parent, and listen for it to tell us the pid of the child.
// WARNING: This is an example of listening on some arbitrary FD number
// that has already been bound elsewhere in advance.  However, binding
// server handles to stdio fd's is NOT a good or reliable way to do
// concurrency in HTTP servers!  Use the cluster module, or if you want
// a more low-level approach, use child process IPC manually.
function test() {
  const parent = spawn(process.execPath, [__filename, 'parent'], {
    stdio: [ 0, 'pipe', 2 ]
  });
  let json = '';
  parent.stdout.on('data', function(c) {
    json += c.toString();
    if (json.includes('\n')) next();
  });
  function next() {
    console.error('output from parent = %s', json);
    const child = JSON.parse(json);
    // now make sure that we can request to the child, then kill it.
    http.get({
      server: 'localhost',
      port: child.port,
      path: '/',
    }).on('response', function(res) {
      let s = '';
      res.on('data', function(c) {
        s += c.toString();
      });
      res.on('end', function() {
        // kill the child before we start doing asserts.
        // it's really annoying when tests leave orphans!
        process.kill(child.pid, 'SIGKILL');
        try {
          parent.kill();
        } catch (e) {}

        assert.strictEqual(s, 'hello from child\n');
        assert.strictEqual(res.statusCode, 200);
      });
    });
  }
}

function parent() {
  const server = net.createServer(function(conn) {
    console.error('connection on parent');
    conn.end('hello from parent\n');
  }).listen(0, function() {
    console.error('server listening on %d', this.address().port);

    const child = spawn(process.execPath, [__filename, 'child'], {
      stdio: [ 'ignore', 'ignore', 'ignore', server._handle ],
      detached: true
    });

    console.log('%j\n', { pid: child.pid, port: this.address().port });

    // Now close the parent, so that the child is the only thing
    // referencing that handle.  Note that connections will still
    // be accepted, because the child has the fd open, but the parent
    // will exit gracefully.
    server.close();
    child.unref();
  });
}

function child() {
  // start a server on fd=3
  http.createServer(function(req, res) {
    console.error('request on child');
    console.error('%s %s', req.method, req.url, req.headers);
    res.end('hello from child\n');
  }).listen({ fd: 3 }, function() {
    console.error('child listening on fd=3');
  });
}
