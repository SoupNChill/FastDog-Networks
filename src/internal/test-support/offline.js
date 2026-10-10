// Preload only for local test runs; never imported by either server.
import dns from 'node:dns';
import net from 'node:net';
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';

const unavailable = () => Object.assign(new Error('offline test resolver: no record'), { code: 'ENOTFOUND' });
for (const method of ['resolve', 'resolve4', 'resolve6', 'resolveCname', 'resolveTxt', 'resolveNs', 'resolveMx', 'resolveSoa', 'reverse']) {
  dns.promises[method] = async () => { throw unavailable(); };
  dns[method] = (...args) => { const callback = args.at(-1); queueMicrotask(() => callback(unavailable())); };
}
const blockedCommands = new Set(['ssh', 'scp', 'sftp', 'pgrep', 'pkill', 'systemctl', 'dig', 'curl', 'wget']);
const spawnSync = childProcess.spawnSync;
childProcess.spawnSync = function (command, ...args) {
  if (blockedCommands.has(command.split('/').at(-1))) {
    return { status: 1, stdout: '', stderr: 'offline test: subprocess blocked', signal: null };
  }
  return spawnSync.call(this, command, ...args);
};
const execFile = childProcess.execFile;
childProcess.execFile = function (command, ...args) {
  if (blockedCommands.has(command.split('/').at(-1))) {
    queueMicrotask(() => args.at(-1)(new Error('offline test: subprocess blocked'), '', ''));
    return { kill() {} };
  }
  return execFile.call(this, command, ...args);
};
const ports = new Set();
const listen = net.Server.prototype.listen;
net.Server.prototype.listen = function (...args) {
  this.once('listening', () => {
    const address = this.address();
    if (address?.port) { ports.add(address.port); this.once('close', () => ports.delete(address.port)); }
  });
  return listen.apply(this, args);
};
const connect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function (...args) {
  const options = Array.isArray(args[0]) ? args[0][0] : args[0];
  const port = Number(typeof options === 'object' ? options.port : options);
  const host = typeof options === 'object' ? options.host : typeof args[1] === 'string' ? args[1] : 'localhost';
  if (!['127.0.0.1', '::1', 'localhost', undefined].includes(host) || !ports.has(port)) {
    queueMicrotask(() => this.destroy(Object.assign(new Error('offline test: connection blocked'), { code: 'ECONNREFUSED' })));
    return this;
  }
  return connect.apply(this, args);
};
syncBuiltinESMExports();
