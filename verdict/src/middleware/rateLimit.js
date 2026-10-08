export function createRateLimiter({
  windowMs = Number(process.env.VERDICT_RATE_LIMIT_WINDOW_MS || 60_000),
  max = Number(process.env.VERDICT_RATE_LIMIT_MAX || 60),
} = {}) {
  const safeWindow = Number.isFinite(windowMs) && windowMs > 0 ? windowMs : 60_000;
  const safeMax = Number.isFinite(max) && max > 0 ? max : 60;
  const buckets = new Map();

  return function rateLimit(req, res, next) {
    const key = req.apiKey?.id || req.ip || 'anonymous';
    const now = Date.now();
    let bucket = buckets.get(key);
    if (!bucket || now - bucket.startedAt >= safeWindow) {
      bucket = { startedAt: now, count: 0 };
      buckets.set(key, bucket);
    }
    bucket.count += 1;
    const remaining = Math.max(0, safeMax - bucket.count);
    res.setHeader('X-RateLimit-Limit', String(safeMax));
    res.setHeader('X-RateLimit-Remaining', String(remaining));
    res.setHeader('X-RateLimit-Reset', String(Math.ceil((bucket.startedAt + safeWindow) / 1000)));
    if (bucket.count > safeMax) {
      const retryAfter = Math.max(1, Math.ceil((bucket.startedAt + safeWindow - now) / 1000));
      res.setHeader('Retry-After', String(retryAfter));
      return res.status(429).json({ error: 'rate_limited', retry_after_seconds: retryAfter });
    }
    next();
  };
}
