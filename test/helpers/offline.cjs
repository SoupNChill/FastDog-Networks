// Preload for the legacy suite: no external DNS, remote commands, or external sockets.
const dns = require('node:dns');
const dnsPromises = require('node:dns/promises');
const net = require('node:net');
const childProcess = require('node:child_process');
const { syncBuiltinESMExports } = require('node:module');
const missing = () => Object.assign(new Error('offline test resolver'), { code: 'ENOTFOUND' });
for (const name of Object.keys(dnsPromises).filter((key) => key.startsWith('resolve') || key === 'reverse')) {
  dnsPromises[name] = async () => { throw missing(); };
  if (typeof dns[name] === 'function') dns[name] = (...args) => queueMicrotask(() => args.at(-1)(missing()));
}
for (const Type of [dnsPromises.Resolver, dns.Resolver]) {
  for (const name of Object.getOwnPropertyNames(Type.prototype).filter((key) => key.startsWith('resolve') || key === 'reverse')) {
    Type.prototype[name] = Type === dnsPromises.Resolver
      ? async () => { throw missing(); }
      : (...args) => queueMicrotask(() => args.at(-1)(missing()));
  }
}
const lookup = dns.lookup;
dns.lookup = function (host, ...args) {
  if (net.isIP(host) || host === 'localhost') return lookup.call(this, host, ...args);
  queueMicrotask(() => args.at(-1)(missing()));
};
dnsPromises.lookup = async (host) => {
  if (!net.isIP(host)) throw missing();
  return { address: host, family: net.isIP(host) };
};
const connect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function (...args) {
  const normalized = Array.isArray(args[0]) ? args[0] : args;
  const options = typeof normalized[0] === 'object' ? normalized[0] : { host: typeof normalized[1] === 'string' ? normalized[1] : 'localhost' };
  const host = options.host || options.hostname || 'localhost';
  if (options.path || !['127.0.0.1', '::1', 'localhost'].includes(host)) throw new Error('offline tests forbid external sockets');
  return connect.apply(this, args);
};
const spawnSync = childProcess.spawnSync;
childProcess.spawnSync = function (command, args, options) {
  if (['ssh', 'scp', 'rsync', 'pgrep', 'pkill', 'systemctl', 'curl', 'wget', 'dig'].includes(command.split('/').at(-1))) {
    return { status: 1, stdout: '', stderr: 'offline test: external command disabled' };
  }
  return spawnSync.call(this, command, args, options);
};
syncBuiltinESMExports();
