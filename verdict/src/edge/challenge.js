import { randomBytes, randomInt } from 'node:crypto';
import { Router, urlencoded } from 'express';
import { binding, issueClearance, difficultyFor, hasWork, seal, unseal, ipPrefix, DEMO_HOST } from './security.js';
import { safeNext, cookieName } from './routes.js';
const escape = value => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const identity = req => { const b=binding(req); return JSON.stringify({...b, ip:ipPrefix(b.ip)}); };
export function challengeRouter({secret, ttl, now = () => Date.now(), capacity = 10000}) {
  const router=Router(), pending=new Map(), limits=new Map();
  router.use((req,res,next) => {
    res.set({'Cache-Control':'no-store', 'X-Content-Type-Options':'nosniff', 'Referrer-Policy':'no-referrer', 'Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; worker-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"});
    if (!secret) return res.status(503).json({error:'clearance_unconfigured'});
    if (!binding(req).host) return res.status(400).json({error:'invalid_host'});
    next();
  });
  function issue(req,res,kind) {
    const time=now();
    for (const [id,row] of pending) if(row.exp<=time) pending.delete(id);
    for (const [ip,row] of limits) if(row.exp<=time) limits.delete(ip);
    const ip=ipPrefix(binding(req).ip), rate=limits.get(ip) || {count:0,exp:time+120000};
    if(rate.count>=30 || pending.size>=capacity || (!limits.has(ip) && limits.size>=capacity)) { res.set('Retry-After','120').status(429).json({error:'challenge_limit'}); return null; }
    rate.count++; limits.set(ip,rate);
    let score=0, next=safeNext(req.query.next);
    if(req.query.hint !== undefined) {
      const hint=unseal(req.query.hint,secret);
      if(!hint || JSON.stringify(hint.bound)!==JSON.stringify(binding(req))) { res.status(400).json({error:'invalid_hint'}); return null; }
      score=hint.score; next=safeNext(hint.next);
    }
    const id=randomBytes(24).toString('hex'), exp=time+120000;
    const row={ exp, identity:identity(req), kind, next, difficulty:difficultyFor(score) };
    pending.set(id,row);
    return {id,row};
  }
  function consume(req,id,kind) {
    const row=pending.get(id);
    if(!row || row.exp<=now() || row.identity!==identity(req) || row.kind!==kind) return null;
    pending.delete(id); return row;
  }
  function clear(req,res) { res.set('Set-Cookie',`${cookieName}=${issueClearance(secret,binding(req),ttl)}; Path=/; Max-Age=${ttl}; HttpOnly; Secure; SameSite=Lax`); }
  router.get('/issue',(req,res) => { const item=issue(req,res,'pow'); if(item) res.json({challenge_id:item.id,difficulty:item.row.difficulty,expires_at:item.row.exp}); });
  router.post('/verify',(req,res) => {
    const {challenge_id,nonce}=req.body || {};
    if(typeof challenge_id!=='string' || typeof nonce!=='string' || !/^\d{1,20}$/.test(nonce)) return res.status(400).json({error:'invalid_proof'});
    const row=consume(req,challenge_id,'pow');
    if(!row || !hasWork(challenge_id,nonce,row.difficulty)) return res.status(400).json({error:'invalid_proof'});
    clear(req,res); res.json({ok:true,next:row.next});
  });
  router.post('/verify-fallback',urlencoded({extended:false,limit:'4kb'}),(req,res) => {
    if (binding(req).host !== DEMO_HOST) return res.status(403).json({error:'proof_required'});
    const token=unseal(req.body?.token,secret);
    const row=token && consume(req,token.id,'fallback');
    if(!row || now()-token.iat<2000 || req.body.website || req.body.confirm!=='yes' || req.body.answer!==String(token.a+token.b)) return res.status(400).type('text').send('Verification failed or expired. Return to /challenge and try again.');
    clear(req,res); res.redirect(303,row.next);
  });
  router.get('/',(req,res) => {
    const item=issue(req,res,'fallback'); if(!item) return;
    const a=randomInt(10,50),b=randomInt(1,20);
    const token=seal({id:item.id,a,b,iat:now(),exp:item.row.exp},secret);
    res.type('html').send(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Security check · FastDog</title><link rel="stylesheet" href="/branding/challenge.css"><script src="/branding/challenge.js" defer></script></head><body><main><img class="logo" src="/branding/lockup-light.svg" alt="FastDog"><p class="eyebrow">VERDICT / SECURITY CHECK</p><h1>A quick check before you continue.</h1><p id="status" role="status" aria-live="polite">Your browser will complete a small security task. Keep this page open.</p><button id="retry" type="button" hidden>Try again</button>${binding(req).host === DEMO_HOST ? `<details><summary>Use an accessible verification form</summary><p>Answer the addition below, then confirm to continue. This option also works without JavaScript.</p><form action="/challenge/verify-fallback" method="post"><input type="hidden" name="token" value="${escape(token)}"><label for="answer">What is ${a} + ${b}?</label><input id="answer" name="answer" inputmode="numeric" pattern="[0-9]+" required autocomplete="off"><div class="trap" aria-hidden="true"><label>Leave empty<input name="website" tabindex="-1" autocomplete="off"></label></div><label class="confirm"><input name="confirm" value="yes" type="checkbox" required> I completed the calculation.</label><button type="submit">Continue</button></form></details>` : '<p>JavaScript proof of work is required on this host.</p>'}<footer>Protected by FastDog</footer></main></body></html>`);
  });
  return router;
}
