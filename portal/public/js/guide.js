// Reusable setup guide. An active claim means DNS ownership is verified, not that TLS was tested.
export const steps = ['Add your website address', 'Add two DNS records', 'Connect your server', 'Live with HTTPS'];
export function guideStep(record, agent = record?.agent) {
  if (!record) return 1;
  if (record.status !== 'active') return 2;
  return agent?.connected ? 4 : 3;
}
export function renderGuide(container, record, agent) {
  const step = guideStep(record, agent);
  const heading = document.createElement('h2');
  heading.textContent = record ? `Setup for ${record.hostname}` : 'Getting started';
  const progress = document.createElement('p');
  progress.textContent = `Step ${step} of 4: ${steps[step - 1]}`;
  const list = document.createElement('ol');
  for (const [index, title] of steps.entries()) {
    const item = document.createElement('li');
    const state = index + 1 < step ? 'done' : index + 1 === step ? 'current' : 'upcoming';
    item.setAttribute('data-state', state);
    item.textContent = `${title}${state === 'done' ? ' — Done' : ''}`;
    if (index + 1 === step) item.setAttribute('aria-current', 'step');
    list.append(item);
  }
  container.replaceChildren(heading, progress, list);
}
