import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, webcrypto } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';
import express from 'express';
import { challengeRouter } from '../src/edge/challenge.js';
import { edgeRouter } from '../src/edge/routes.js';
import { issueClearance, validClearance, ipPrefix, difficultyFor, hasWork, seal } from '../src/edge/security.js';
const secret='test-only-secret';
const bound={host:'shop.example',ip:'192.0.2.42',ua:'headless'};
const headers={'x-forwarded-host':bound.host,'x-forwarded-for':bound.ip,'user-agent':bound.ua};
async function server(fn,options={}) {
  const app=express(); app.use(express.json());
  if(options.edge) app.use(edgeRouter({secret,logDecision:async () => {}}));
  else app.use('/challenge',challengeRouter({secret,ttl:300,...options}));
  const listener=app.listen(0,'127.0.0.1'); await new Promise(r=>listener.once('listening',r));
  const base=`http://127.0.0.1:${listener.address().port}`;
  const get=path=>fetch(base+path,{headers});
  const post=(path,body,extra={})=>fetch(base+path,{method:'POST',headers:{...headers,'content-type':'application/json',...extra},body:JSON.stringify(body),redirect:'manual'});
  try {await fn({base,get,post});} finally {listener.closeAllConnections();await new Promise(r=>listener.close(r));}
}
function solve(id,bits) {for(let n=0;;n++) if(hasWork(id,String(n),bits)) return String(n);}
test('prefix normalization and clearance host/UA/prefix/signature/expiry binding',()=>{
  assert.equal(ipPrefix('::ffff:192.0.2.4'),'192.0.2.0/24');
  assert.equal(ipPrefix('::ffff:c000:204'),'192.0.2.0/24');
  assert.equal(ipPrefix('2001:DB8::1'),ipPrefix('2001:0db8:0:0:abcd::2'));
  assert.notEqual(ipPrefix('2001:db8:0:1::1'),ipPrefix('2001:db8::1'));
  const token=issueClearance(secret,bound,300,1000000);
  assert.ok(validClearance(token,secret,{...bound,ip:'192.0.2.99'},1000000));
  for(const b of [{...bound,host:'other.example'},{...bound,ua:'other'},{...bound,ip:'192.0.3.1'}]) assert.equal(validClearance(token,secret,b,1000000),false);
  assert.equal(validClearance(token,secret,bound,1300000),false);
  assert.equal(validClearance(token,'wrong',bound,1000000),false);
  for(const t of [token+'x','garbage','',null]) assert.equal(validClearance(t,secret,bound,1000000),false);
  const v6={...bound,ip:'2001:db8::1'};
  assert.ok(validClearance(issueClearance(secret,v6),secret,{...v6,ip:'2001:0DB8:0:0::2'}));
  const payload=Buffer.from(token.split('.')[0],'base64url').toString();
  assert.equal(payload,`1300.shop.example.192.0.2.0/24.${createHash('sha256').update(bound.ua).digest('hex').slice(0,8)}`);
});
test('difficulty thresholds and partial-byte work checks',()=>{
  assert.deepEqual([0,.449,.45,.649,.65,.749,.75,1].map(difficultyFor),[16,16,18,18,20,20,22,22]);
  const nonce=solve('known',18); const hash=createHash('sha256').update('known:'+nonce).digest();
  assert.equal(hash[0],0);assert.equal(hash[1],0);assert.equal(hash[2]&192,0);
});
test('proof required, successful clearance, replay and changed binding rejected',()=>server(async({get,post,base})=>{
  assert.equal((await post('/challenge/verify',{})).status,400);
  const challenge=await (await get('/challenge/issue?next=%2Faccount')).json();
  assert.equal(challenge.difficulty,16);
  const proof={challenge_id:challenge.challenge_id,nonce:solve(challenge.challenge_id,16)};
  assert.equal((await post('/challenge/verify',proof,{'user-agent':'other'})).status,400);
  const response=await post('/challenge/verify',proof);
  assert.deepEqual(await response.json(),{ok:true,next:'/account'});
  const cookie=response.headers.get('set-cookie');
  for(const flag of ['HttpOnly','Secure','SameSite=Lax','Path=/','Max-Age=300']) assert.ok(cookie.includes(flag));
  assert.ok(validClearance(cookie.split(';')[0].split('=')[1],secret,bound));
  assert.equal((await post('/challenge/verify',proof)).status,400);
  const bad=await (await get('/challenge/issue')).json();
  let nonce='0';while(hasWork(bad.challenge_id,nonce,16)) nonce=String(+nonce+1);
  assert.equal((await post('/challenge/verify',{challenge_id:bad.challenge_id,nonce})).status,400);
  assert.equal((await post('/challenge/verify',{challenge_id:bad.challenge_id,nonce:solve(bad.challenge_id,16)})).status,400);
}));
test('challenge expiry, capacity and request rate are bounded',()=>{
  let time=Date.now();
  return server(async({get,post})=>{
    const c=await(await get('/challenge/issue')).json();
    assert.equal((await get('/challenge/issue')).status,429);
    time+=120000;
    assert.equal((await post('/challenge/verify',{challenge_id:c.challenge_id,nonce:solve(c.challenge_id,16)})).status,400);
    assert.equal((await get('/challenge/issue')).status,200);
  },{capacity:1,now:()=>time});
});
test('issue rate limit survives consumption',()=>server(async({get})=>{
  for(let i=0;i<30;i++) assert.equal((await get('/challenge/issue')).status,200);
  const res=await get('/challenge/issue');assert.equal(res.status,429);assert.equal(res.headers.get('retry-after'),'120');
}));
test('signed hints preserve edge score, reject alteration, expiration and cross-host use',()=>server(async({get,base})=>{
  const response=await get('/v1/edge-auth'); assert.equal(response.status,401);
  const location=response.headers.get('location');
  const hint=new URL(location,base).searchParams.get('hint');
  assert.equal((await(await get('/challenge/issue?hint='+hint)).json()).difficulty,18);
  for(const score of [.45,.65,.75]) {
    const token=seal({score,bound,next:'/account',exp:Date.now()+120000},secret);
    assert.equal((await(await get('/challenge/issue?hint='+token+'&score=0')).json()).difficulty,difficultyFor(score));
  }
  assert.equal((await get('/challenge/issue?hint='+hint+'x')).status,400);
  assert.equal((await get('/challenge/issue?hint='+seal({score:1,bound,exp:Date.now()-1},secret))).status,400);
  assert.equal((await fetch(base+'/challenge/issue?hint='+hint,{headers:{...headers,'x-forwarded-host':'other'}})).status,400);
  const cookie='fd_verdict_clearance='+issueClearance(secret,bound);
  const allowed=await fetch(base+'/v1/edge-auth',{headers:{...headers,cookie,accept:'application/json'}});
  assert.equal(allowed.status,200); assert.equal((await allowed.json()).engine,'clearance');
},{edge:true}));
test('fallback signed arithmetic, timing, honeypot, replay and safe redirect',()=>{
  let time=Date.now();
  return server(async({get,base})=>{
    async function form(){const r=await fetch(base+'/challenge?next=//evil.test',{headers:{...headers,'x-forwarded-host':'verdict-demo.fastdognetworks.com'}});assert.ok(r.headers.get('content-security-policy').includes("frame-ancestors 'none'"));const html=await r.text(); const token=html.match(/name="token" value="([^"]+)"/)[1];const [,a,b]=html.match(/What is (\d+) \+ (\d+)\?/);return {token,answer:String(+a + +b),confirm:'yes'};}
    const submit=body=>fetch(base+'/challenge/verify-fallback',{method:'POST',headers:{...headers,'x-forwarded-host':'verdict-demo.fastdognetworks.com'},body:new URLSearchParams(body),redirect:'manual'});
    let body=await form(); assert.equal((await submit(body)).status,400);
    body=await form(); time+=2000; assert.equal((await submit({...body,website:'bot'})).status,400);
    body=await form(); time+=2000; assert.equal((await submit({...body,answer:'999'})).status,400);
    body=await form(); time+=2000; assert.equal((await submit({...body,token:body.token+'x'})).status,400);
    const result=await submit(body); assert.equal(result.status,303);assert.equal(result.headers.get('location'),'/');assert.ok(result.headers.get('set-cookie')); assert.equal((await submit(body)).status,400);
    body=await form();time+=120000;assert.equal((await submit(body)).status,400);
  },{now:()=>time});
});
test('shipped worker computes a real SHA-256 proof',async()=>{
  const source=await readFile('public/branding/pow-worker.js','utf8');
  let nonce;const self={postMessage:value=>{nonce=value;}};
  runInNewContext(source,{self,crypto:webcrypto,TextEncoder,Uint8Array,Number});
  await self.onmessage({data:{challenge_id:'browser-test',difficulty:16}});
  assert.equal(typeof nonce,'string');assert.ok(hasWork('browser-test',nonce,16));
});
test('worker SHA-256 matches native digest across block boundaries and varied nonces',async()=>{
  const source=await readFile('public/branding/pow-worker.js','utf8');
  const digest=runInNewContext(source+'\n(text) => Array.from(sha256(text), x => x.toString(16).padStart(8,"0")).join("")',{self:{},TextEncoder,Uint8Array});
  for(const message of ['', 'abc', 'a'.repeat(55),'a'.repeat(56),'a'.repeat(64),'a'.repeat(119),...Array.from({length:100},(_,i)=>'b'.repeat(48)+':'+String(i*999999))]) {
    assert.equal(digest(message),createHash('sha256').update(message).digest('hex'));
  }
});
test('browser script submits proof, uses safe server redirect and exposes retry on failure',async()=>{
  const source=await readFile('public/branding/challenge.js','utf8');
  for(const destination of ['/account','//evil.test','/\\evil.test','https://evil.test']) {
    let redirected,posted,terminated=false;
    const status={},retry={addEventListener(){}};
    class Worker { postMessage(){queueMicrotask(()=>this.onmessage({data:'123'}));} terminate(){terminated=true;} }
    await runInNewContext(source,{window:{isSecureContext:true,Worker,addEventListener(){}},Worker,document:{getElementById:id=>id==='status'?status:retry},location:{search:'?hint=signed',replace:value=>{redirected=value;}},setTimeout,clearTimeout,fetch:async(path,options)=>{
      if(path.startsWith('/challenge/issue'))return {ok:true,json:async()=>({challenge_id:'id',difficulty:16,expires_at:Date.now()+120000})};
      assert.equal(path,'/challenge/verify');posted=JSON.parse(options.body);return {ok:true,json:async()=>({ok:true,next:destination})};
    }});
    assert.deepEqual(posted,{challenge_id:'id',nonce:'123'});assert.equal(redirected,destination==='/account'?destination:'/');assert.ok(terminated);
  }
  const status={},retry={addEventListener(){}};
  await runInNewContext(source,{window:{isSecureContext:false,addEventListener(){}},document:{getElementById:id=>id==='status'?status:retry}});
  assert.equal(retry.hidden,false);assert.ok(status.textContent.includes('verification form'));
});
