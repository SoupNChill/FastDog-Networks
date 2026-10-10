export function fakeResolver() {
  const answers = new Map();
  const calls = [];
  const key = (type, name) => `${type}:${name.toLowerCase().replace(/\.$/, '')}`;
  const resolve = async (type, name) => {
    calls.push({ type, name });
    const answer = answers.get(key(type, name));
    if (answer === undefined) throw Object.assign(new Error('fake DNS missing'), { code: 'ENODATA' });
    if (answer instanceof Error) throw answer;
    return typeof answer === 'function' ? answer() : structuredClone(answer);
  };
  return {
    calls,
    set(type, name, answer) { answers.set(key(type, name), answer); return this; },
    resolveCname: (name) => resolve('CNAME', name),
    resolve4: (name) => resolve('A', name),
    resolveTxt: (name) => resolve('TXT', name),
  };
}
