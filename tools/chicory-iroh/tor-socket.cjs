'use strict';
const assert = require('node:assert/strict');
const { Duplex } = require('node:stream');

// Qualification host adapter only. Portable net delegates onion routing to its
// SocketFactory. The real native phone uses its own native Tor socket instead.
function createTorSocketFactory({ host, port, connect }) {
  assert(/^[a-z2-7]{56}\.onion$/.test(host));
  assert(Number.isInteger(port) && port > 0 && port <= 65535);
  const active = new Set();
  return target => {
    assert(target.host === host && target.port === port && !target.tls,
      'Tor qualification refused an unexpected destination');
    assert(active.size < 8, 'Tor qualification connection limit');
    let socket;
    const transport = new Duplex({
      readableHighWaterMark: 32768, writableHighWaterMark: 32768,
      construct(callback) {
        Promise.resolve().then(() => connect(host, port)).then(value => {
          socket = value;
          socket.on('error', error => transport.destroy(error));
          socket.on('data', bytes => { if (!transport.push(bytes)) socket.pause(); });
          socket.once('end', () => transport.push(null));
          socket.once('close', () => transport.destroy());
          if (transport.destroyed) { socket.destroy(); callback(); return; }
          callback();
          transport.emit('connect');
        }, callback);
      },
      read() { socket?.resume(); },
      write(bytes, encoding, callback) { socket.write(bytes, callback); },
      final(callback) { socket.end(callback); },
      destroy(error, callback) { socket?.destroy(); callback(error); },
    });
    const write = transport.write.bind(transport);
    transport.write = (bytes, ...args) => {
      if (transport.writableLength + Buffer.byteLength(bytes) > 262144) {
        const error = Error('Tor qualification write buffer exceeded');
        const callback = args.find(value => typeof value === 'function');
        if (callback) queueMicrotask(() => callback(error));
        transport.destroy(error);
        return false;
      }
      return write(bytes, ...args);
    };
    active.add(transport);
    transport.once('close', () => active.delete(transport));
    return transport;
  };
}
module.exports = { createTorSocketFactory };
