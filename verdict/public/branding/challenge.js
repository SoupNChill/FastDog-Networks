/* All work stays on this origin. A worker keeps the form and assistive UI responsive. */
let worker;
const status = document.getElementById('status');
const retry = document.getElementById('retry');
async function run() {
  retry.hidden = true;
  status.textContent = 'Checking your browser…';
  try {
    if (!window.isSecureContext || !window.Worker) throw new Error('unsupported');
    const response = await fetch('/challenge/issue' + location.search, {cache:'no-store'});
    if (!response.ok) throw new Error('issue');
    const challenge = await response.json();
    worker = new Worker('/branding/pow-worker.js');
    const nonce = await new Promise((resolve,reject) => {
      const timer = setTimeout(() => { worker.terminate(); reject(new Error('expired')); }, Math.max(1, Math.min(115000, challenge.expires_at-Date.now())));
      worker.onmessage = event => { clearTimeout(timer); resolve(event.data); };
      worker.onerror = () => { clearTimeout(timer); reject(new Error('worker')); };
      worker.postMessage(challenge);
    });
    worker.terminate();
    const verified = await fetch('/challenge/verify', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({challenge_id:challenge.challenge_id,nonce})});
    if (!verified.ok) throw new Error('verify');
    const result = await verified.json();
    const next = result.next;
    location.replace(typeof next === 'string' && next.startsWith('/') && !next.startsWith('//') && !/[\\\s\x00-\x1f\x7f]/.test(next) ? next : '/');
  } catch {
    worker?.terminate();
    status.textContent = 'The browser check could not finish. Try again or use the verification form below.';
    retry.hidden = false;
  }
}
retry.addEventListener('click',run);
window.addEventListener('pagehide',() => worker?.terminate());
run();
