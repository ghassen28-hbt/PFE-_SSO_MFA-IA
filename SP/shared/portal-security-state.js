const crypto = require("node:crypto");

const PORTAL_SECURITY_STATE_ATTR = "portal_security_state";

function singleAttributeValue(attributes, key) {
  const raw = attributes?.[key];
  if (Array.isArray(raw)) return raw[0] || "";
  if (typeof raw === "string") return raw;
  return "";
}

function normalizePortalSecurityState(raw = {}) {
  const adminBootstrap = raw?.admin_bootstrap || {};
  const recoveryCodes = raw?.recovery_codes || {};
  const onboarding = raw?.onboarding || {};

  const hashes = Array.isArray(recoveryCodes.hashes)
    ? recoveryCodes.hashes
        .map((item) => String(item || "").trim())
        .filter(Boolean)
    : [];

  return {
    onboarding: {
      required: onboarding.required !== false,
      completed: onboarding.completed === true,
      completed_at: onboarding.completed_at || null,
      required_since: onboarding.required_since || null,
      completed_by: onboarding.completed_by || null,
    },
    admin_bootstrap: {
      status: String(adminBootstrap.status || "none"),
      requested_at: adminBootstrap.requested_at || null,
      requested_by: adminBootstrap.requested_by || null,
      requested_reason: adminBootstrap.requested_reason || null,
      requested_decision: adminBootstrap.requested_decision || null,
      requested_policy_reason: adminBootstrap.requested_policy_reason || null,
      requested_risk_label: adminBootstrap.requested_risk_label || null,
      requested_risk_score:
        adminBootstrap.requested_risk_score == null
          ? null
          : Number(adminBootstrap.requested_risk_score),
      request_ip: adminBootstrap.request_ip || null,
      approved_at: adminBootstrap.approved_at || null,
      approved_by: adminBootstrap.approved_by || null,
      approved_until: adminBootstrap.approved_until || null,
      rejection_reason: adminBootstrap.rejection_reason || null,
    },
    recovery_codes: {
      hashes,
      generated_at: recoveryCodes.generated_at || null,
      generated_by: recoveryCodes.generated_by || null,
      last_used_at: recoveryCodes.last_used_at || null,
      remaining: hashes.length,
    },
  };
}

function readPortalSecurityState(attributes) {
  const raw = singleAttributeValue(attributes, PORTAL_SECURITY_STATE_ATTR);
  if (!raw) {
    return normalizePortalSecurityState({});
  }

  try {
    return normalizePortalSecurityState(JSON.parse(raw));
  } catch {
    return normalizePortalSecurityState({});
  }
}

function writePortalSecurityState(attributes, state) {
  return {
    ...(attributes || {}),
    [PORTAL_SECURITY_STATE_ATTR]: [
      JSON.stringify(normalizePortalSecurityState(state)),
    ],
  };
}

function hasActiveBootstrapApproval(state, now = Date.now()) {
  const normalized = normalizePortalSecurityState(state);
  if (normalized.admin_bootstrap.status !== "approved") return false;
  const approvedUntilMs = Date.parse(normalized.admin_bootstrap.approved_until || "");
  return Number.isFinite(approvedUntilMs) && approvedUntilMs > now;
}

function hasRecoveryCodes(state) {
  return normalizePortalSecurityState(state).recovery_codes.hashes.length > 0;
}

function normalizeRecoveryCode(code) {
  return String(code || "")
    .toUpperCase()
    .replace(/[^A-Z2-9]/g, "");
}

function hashRecoveryCode(userId, code) {
  return crypto
    .createHash("sha256")
    .update(`${userId}:${normalizeRecoveryCode(code)}`)
    .digest("hex");
}

function randomRecoveryCode() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let token = "";
  for (let i = 0; i < 8; i += 1) {
    token += alphabet[Math.floor(Math.random() * alphabet.length)];
  }
  return `${token.slice(0, 4)}-${token.slice(4)}`;
}

function createRecoveryCodes(userId, count = 8) {
  const codes = [];
  const hashes = [];

  while (codes.length < count) {
    const code = randomRecoveryCode();
    if (codes.includes(code)) continue;
    codes.push(code);
    hashes.push(hashRecoveryCode(userId, code));
  }

  return { codes, hashes };
}

function consumeRecoveryCode(state, userId, candidateCode) {
  const normalized = normalizePortalSecurityState(state);
  const candidateHash = hashRecoveryCode(userId, candidateCode);
  const index = normalized.recovery_codes.hashes.indexOf(candidateHash);

  if (index < 0) {
    return {
      matched: false,
      nextState: normalized,
    };
  }

  const nextHashes = normalized.recovery_codes.hashes.filter(
    (_, currentIndex) => currentIndex !== index
  );

  return {
    matched: true,
    nextState: normalizePortalSecurityState({
      ...normalized,
      recovery_codes: {
        ...normalized.recovery_codes,
        hashes: nextHashes,
        last_used_at: new Date().toISOString(),
      },
    }),
  };
}

module.exports = {
  PORTAL_SECURITY_STATE_ATTR,
  createRecoveryCodes,
  consumeRecoveryCode,
  hasActiveBootstrapApproval,
  hasRecoveryCodes,
  normalizePortalSecurityState,
  readPortalSecurityState,
  writePortalSecurityState,
};
