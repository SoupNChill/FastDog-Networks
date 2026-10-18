import { createHash, timingSafeEqual } from 'node:crypto';

export function equalToken(value, expected) {
  if (typeof value !== 'string' || typeof expected !== 'string' || !value || !expected) return false;
  const hash = (token) => createHash('sha256').update(token).digest();
  return timingSafeEqual(hash(value), hash(expected));
}

export function operatorAuth(expected) {
  return (req, res, next) => {
    if (!equalToken(req.headers['x-fastdog-token'], expected) && !equalToken(req.body?.token, expected)) {
      return res.status(401).json({ error: 'unauthorized' });
    }
    next();
  };
}

export function equalHash(a, b) {
  const left = Buffer.from(a ?? '', 'hex'), right = Buffer.from(b ?? '', 'hex');
  return left.length === 32 && right.length === 32 && timingSafeEqual(left, right);
}
