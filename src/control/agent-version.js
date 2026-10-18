export const validAgentVersion = (value) => typeof value === 'string' && /^\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value);
