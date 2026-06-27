'use strict';

const geoVelocity = require('./geoVelocity');
const threatEngine = require('./threatEngine');
const logger = require('./logger');
const { cairoNow } = require('./timeUtils');
const { cleanIP } = threatEngine;

const sessionMonitor = {
  active: Object.create(null),
  history: [],
  maxHistory: 500
};

function getClientIP(req) {
  const forwarded = req.headers['x-forwarded-for'];
  const remote = cleanIP(req.socket?.remoteAddress || req.connection?.remoteAddress || req.ip || '0.0.0.0');
  const trustHeaders = String(
    process.env.TRUST_PROXY_HEADERS ||
    (process.env.RAILWAY_ENVIRONMENT || process.env.RAILWAY_PUBLIC_DOMAIN ? 'true' : 'false')
  ).toLowerCase() === 'true';

  if (forwarded && trustHeaders) return cleanIP(String(forwarded).split(',')[0].trim());
  return cleanIP(req.ip || remote);
}

function pushSessionEvent(event) {
  const item = {
    id: event.id || `SESS-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
    time: event.time || cairoNow(),
    isoTime: event.isoTime || new Date().toISOString(),
    user: event.user || 'System',
    role: event.role || 'Admin',
    ip: cleanIP(event.ip || '0.0.0.0'),
    action: event.action || 'EVENT',
    duration: event.duration || '',
    note: event.note || ''
  };
  sessionMonitor.history.unshift(item);
  if (sessionMonitor.history.length > sessionMonitor.maxHistory) sessionMonitor.history.length = sessionMonitor.maxHistory;
  return item;
}

function isHeartbeatAction(action) {
  return /^APP_SESSION_ACTIVE$/i.test(String(action || ''));
}

function getSessionIdentity(record) {
  const email = String(record?.email || record?.note || '').trim().toLowerCase();
  if (email && email.includes('@')) return `email:${email}`;
  const userId = String(record?.userId || '').trim().toLowerCase();
  if (userId) return `user:${userId}`;
  const user = String(record?.user || '').trim().toLowerCase();
  return user ? `name:${user}` : '';
}

function removeDuplicateAppSessions(currentId, identity) {
  if (!identity) return;
  Object.entries(sessionMonitor.active).forEach(([id, rec]) => {
    if (id !== currentId && rec?.source === 'TABIBI_APP' && getSessionIdentity(rec) === identity) {
      delete sessionMonitor.active[id];
    }
  });
}

function emitSessionEvent(io, event) {
  if (!event || !io) return null;
  io.emit('session-event', event);
  return event;
}

function normalizeRole(role) {
  const value = String(role || 'Patient').toLowerCase();
  if (value === 'doctor') return 'Doctor';
  if (value === 'admin') return 'Admin';
  return 'Patient';
}

function recordAppSession(user, req, action) {
  if (!user || !user._id) return null;
  const role = normalizeRole(user.role);
  const ip = getClientIP(req);
  const id = `app:${String(user._id)}`;
  const now = Date.now();
  const existing = sessionMonitor.active[id];
  sessionMonitor.active[id] = {
    id,
    userId: String(user._id),
    user: user.name || user.email || String(user._id),
    email: user.email || '',
    role,
    ip,
    startedAt: existing?.startedAt || now,
    startedAtIso: existing?.startedAtIso || new Date(now).toISOString(),
    lastSeen: now,
    lastSeenIso: new Date(now).toISOString(),
    expiresAt: now + 30 * 60000,
    userAgent: req.headers['user-agent'] || '',
    status: 'ACTIVE',
    source: 'TABIBI_APP'
  };
  return pushSessionEvent({
    user: sessionMonitor.active[id].user,
    role,
    ip,
    action,
    note: user.email || 'TABIBI app session'
  });
}

async function runGeoVelocityCheck(user, req, action, io) {
  if (!user) return null;
  const userId = user._id || user.id || user.email;
  if (!userId) return null;
  const ip = getClientIP(req);
  const result = await geoVelocity.check(userId, ip, {
    user: user.name || user.email || String(userId),
    email: user.email || '',
    action
  });
  if (result.impossible || result.suspicious) {
    const entry = {
      ip,
      type: result.impossible ? 'GEO_VELOCITY_IMPOSSIBLE' : 'GEO_VELOCITY_SUSPICIOUS',
      score: result.impossible ? 100 : 55,
      action: result.impossible ? 'BLOCKED' : 'FLAGGED',
      time: cairoNow(),
      isoTime: new Date().toISOString(),
      path: req.originalUrl || req.path,
      method: req.method,
      payload: result.reason,
      analysis: {
        type: 'GEO_VELOCITY',
        risk: result.impossible ? 'CRITICAL' : 'MEDIUM',
        target: result.email || result.userId,
        technique: result.reason,
        from: result.fromCity,
        to: result.toCity,
        speedKph: result.speedKph,
        distanceKm: result.distanceKm
      }
    };
    logger(entry);
    if (io) {
      io.emit('geo-velocity-alert', result);
      io.emit('geo-velocity-state', geoVelocity.getSnapshot());
      if (result.impossible) io.emit('attack', entry);
    }
  } else {
    if (io) io.emit('geo-velocity-state', geoVelocity.getSnapshot());
  }
  return result;
}

function pruneExpiredSessions() {
  const now = Date.now();
  Object.entries(sessionMonitor.active).forEach(([id, rec]) => {
    if (rec.expiresAt && rec.expiresAt < now) {
      delete sessionMonitor.active[id];
      pushSessionEvent({
        user: rec.user,
        role: rec.role,
        ip: rec.ip,
        action: 'SESSION_EXPIRED',
        duration: Math.max(1, Math.round((now - Number(rec.startedAt || now)) / 1000)) + 's',
        note: rec.email || rec.id
      });
    }
  });
}

function getSessionSnapshot() {
  pruneExpiredSessions();
  const dedupedActive = Object.create(null);
  Object.values(sessionMonitor.active).forEach(rec => {
    const key = rec.source === 'TABIBI_APP' ? getSessionIdentity(rec) : `socket:${rec.id}`;
    const current = dedupedActive[key];
    if (!current || Number(rec.lastSeen || rec.startedAt || 0) > Number(current.lastSeen || current.startedAt || 0)) {
      dedupedActive[key] = rec;
    }
  });
  const active = Object.values(dedupedActive).sort((a, b) => Number(b.lastSeen || b.startedAt || 0) - Number(a.lastSeen || a.startedAt || 0));
  const history = sessionMonitor.history.filter(item => !isHeartbeatAction(item.action));
  return {
    active,
    history,
    stats: {
      total: history.length,
      active: active.length,
      doctors: active.filter(e => e.role === 'Doctor').length,
      patients: active.filter(e => e.role === 'Patient').length,
      admins: active.filter(e => e.role === 'Admin').length
    }
  };
}

module.exports = {
  sessionMonitor,
  pushSessionEvent,
  isHeartbeatAction,
  getSessionIdentity,
  removeDuplicateAppSessions,
  emitSessionEvent,
  normalizeRole,
  recordAppSession,
  runGeoVelocityCheck,
  pruneExpiredSessions,
  getSessionSnapshot,
  getClientIP
};
