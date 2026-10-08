import { randomUUID } from 'node:crypto';
import { localDecision } from './heuristic.js';
import { claimedGoodBot } from './goodbots.js';

const actions = new Set(['allow', 'challenge', 'block']);

export async function decide(state, { apiKey = process.env.TYPESAFE_API_KEY, baseUrl = process.env.TYPESAFE_BASE_URL || 'https://api.typesafe.ai', fetchImpl = fetch } = {}) {
  if (!apiKey || claimedGoodBot(state)) return localDecision(state);
  try {
    const response = await fetchImpl(`${baseUrl.replace(/\/$/, '')}/v1/systemone`, {
      method: 'POST',
      headers: { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'jev-latest', state, questions: { verdict: { type: 'choice', instructions: 'Choose the appropriate threat response for this request.', criteria: { allow: 'Low risk, no intervention needed', challenge: 'Uncertain risk or suspicious automation; require verification', block: 'Strong malicious indicators; deny the request' } } } }),
      signal: AbortSignal.timeout(2500),
    });
    if (!response.ok) throw new Error(`TypeSafe HTTP ${response.status}`);
    const data = await response.json();
    const answer = data.answers?.verdict;
    const action = answer?.choice;
    const confidence = answer?.confidence;
    if (!actions.has(action) || typeof confidence !== 'number' || confidence < 0 || confidence > 1) throw new Error('Invalid TypeSafe response');
    return { action, confidence, reason: 'jev_choice', reasons: ['jev_choice'], engine: 'typesafe_jev', request_id: randomUUID() };
  } catch (error) {
    console.warn('Jev unavailable; using heuristic:', error.message);
    return localDecision(state);
  }
}
