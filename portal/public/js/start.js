import { api, init, message } from './api.js';
import { startState } from './start-state.js';
let timer;
let stopped = false;
window.addEventListener('pagehide', () => { stopped = true; clearTimeout(timer); });
async function refresh() {
  try {
    const { hostnames } = await api('/api/hostnames');
    if (stopped) return;
    const state = startState(hostnames);
    document.querySelectorAll('#start-steps > li').forEach((item, index) => {
      const progress = state.steps[index];
      item.dataset.state = progress;
      item.removeAttribute('aria-current');
      if (progress === 'current') item.setAttribute('aria-current', 'step');
      let marker = item.querySelector('.step-state');
      if (!marker) {
        marker = document.createElement('span');
        marker.className = 'step-state';
        item.prepend(marker);
      }
      marker.textContent = `${index + 1} · ${progress[0].toUpperCase()}${progress.slice(1)}`;
    });
    message(state.live ? 'Your first website is live. Open Website to see its status.' : 'Follow the steps below. Progress updates automatically.');
  } catch (error) { message(`${error.message} Your progress will be checked again shortly.`); }
  finally { if (!stopped) timer = setTimeout(refresh, 10000); }
}
try { await init(true); await refresh(); } catch (error) { message(error.message); }
