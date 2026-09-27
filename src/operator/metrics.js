export function summarizeOperatorMetrics({ zones = [], invites = [], accounts = [], agents = [], edgeHealthOk = false, now = Date.now() }) {
  const active = invites.filter((invite) => invite.remaining_uses > 0 && (!invite.expires_at || Date.parse(invite.expires_at) > now));
  const paid = accounts.filter((account) => account.status === 'paid_test' && Number.isFinite(Date.parse(account.updated_at)));
  paid.sort((a, b) => Date.parse(b.updated_at) - Date.parse(a.updated_at));
  const connected = agents.filter((agent) => agent.connected);
  connected.sort((a, b) => Date.parse(b.lastSeen || 0) - Date.parse(a.lastSeen || 0));
  return {
    zoneCount: zones.length,
    invitesRemaining: active.reduce((sum, invite) => sum + invite.remaining_uses, 0),
    unusedInviteCount: active.filter((invite) => invite.remaining_uses === invite.max_uses).length,
    lastPaidTest: paid[0]?.updated_at || null,
    edgeHealthOk,
    agentsConnected: connected.length,
    agentsRegistered: agents.length,
    tunnelConnected: agents.some((agent) => agent.connected),
    newestConnectedLastSeen: connected[0]?.lastSeen || null,
  };
}
