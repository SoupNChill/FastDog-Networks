// An advisory panel: account pages remain usable even when acceptance cannot be saved.
export function showTermsUpdate(update, api, continueTo = () => {}) {
  if (!update?.required) return false;
  document.querySelector('#terms-update')?.remove();
  const panel = document.createElement('form');
  panel.id = 'terms-update';
  panel.className = 'portal-body';
  const heading = document.createElement('p');
  heading.textContent = 'We’ve updated our Terms of Service and Privacy Policy.';
  const label = document.createElement('label');
  const checkbox = document.createElement('input');
  checkbox.type = 'checkbox';
  checkbox.required = true;
  label.append(checkbox, ' I agree to the ');
  for (const [index, [text, url]] of [['Terms of Service', update.terms_url], ['Privacy Policy', update.privacy_url]].entries()) {
    if (index) label.append(' and ');
    const link = document.createElement('a');
    link.textContent = text;
    link.href = url;
    link.target = '_blank';
    link.rel = 'noopener';
    label.append(link);
  }
  const accept = document.createElement('button');
  accept.type = 'submit';
  accept.textContent = 'Accept';
  const skip = document.createElement('button');
  skip.type = 'button';
  skip.textContent = 'Continue for now';
  const finish = () => { panel.remove(); continueTo(); };
  skip.onclick = () => { try { sessionStorage.setItem('fd-terms-skip', '1'); } catch { /* storage may be off */ } finish(); };
  panel.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!checkbox.checked) return;
    accept.disabled = true;
    try { await api('/api/terms/accept', 'POST', { accept_terms: true }); }
    catch { /* A failed write must never trap the user. */ }
    finally { finish(); }
  });
  panel.append(heading, label, accept, skip);
  const body = document.querySelector('.portal-body');
  if (!body) return false;
  body.prepend(panel);
  return true;
}
