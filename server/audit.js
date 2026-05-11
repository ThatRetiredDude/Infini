import { run } from './db.js';

/**
 * Append an audit log entry. Never throws — audit failures should never break
 * the calling request.
 */
export function audit({
  actionType,
  actorId = null,
  actorUsername = null,
  targetType = null,
  targetId = null,
  payload = null,
  ip = null,
  userAgent = null,
}) {
  try {
    run(
      `INSERT INTO audit_log
       (action_type, actor_id, actor_username, target_type, target_id, payload, ip, user_agent)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        actionType,
        actorId,
        actorUsername,
        targetType,
        targetId,
        payload == null ? null : JSON.stringify(payload),
        ip,
        userAgent,
      ],
    );
  } catch (err) {
     
    console.warn('[audit] insert failed:', err?.message || err);
  }
}

/**
 * Convenience for routes — derives actor + IP/UA from the request.
 */
export function auditReq(req, partial) {
  audit({
    ...partial,
    actorId: partial.actorId ?? req.user?.id ?? null,
    actorUsername: partial.actorUsername ?? req.user?.username ?? null,
    ip: partial.ip ?? getRequestIp(req),
    userAgent: partial.userAgent ?? req.headers['user-agent'] ?? null,
  });
}

export function getRequestIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) {
    const first = String(fwd).split(',')[0].trim();
    if (first) return first;
  }
  return req.ip || req.socket?.remoteAddress || null;
}
