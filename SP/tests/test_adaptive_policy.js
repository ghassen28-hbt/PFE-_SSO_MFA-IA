const test = require("node:test");
const assert = require("node:assert/strict");

const { resolveAdaptiveDecision } = require("../shared/adaptive-policy");

function baseDecision(decision, overrides = {}) {
  return {
    risk_score: 0.42,
    risk_label: "moderate",
    decision,
    required_factor: "TOTP_OR_WEBAUTHN",
    auth_path: "SECOND_FACTOR",
    policy_reason: "ml_predicted_moderate",
    completed: false,
    ...overrides,
  };
}

test("moderate risk keeps TOTP when it is configured", () => {
  const resolved = resolveAdaptiveDecision({
    baseDecision: baseDecision("STEP_UP_TOTP"),
    factorAvailability: {
      totp: { configured: true },
      biometric: { enrolled: false },
    },
  });

  assert.equal(resolved.decision, "STEP_UP_TOTP");
  assert.equal(resolved.resolution_status, "totp_primary");
  assert.equal(resolved.requested_decision, "STEP_UP_TOTP");
});

test("moderate risk falls back to biometric when TOTP is unavailable and biometric exists", () => {
  const resolved = resolveAdaptiveDecision({
    baseDecision: baseDecision("STEP_UP_TOTP"),
    factorAvailability: {
      totp: { configured: false },
      biometric: { enrolled: true },
    },
  });

  assert.equal(resolved.decision, "STEP_UP_BIOMETRIC");
  assert.equal(resolved.required_factor, "FACE_RECOGNITION");
  assert.equal(resolved.policy_reason, "totp_unavailable_biometric_fallback");
  assert.equal(resolved.fallback_factor, "FACE_RECOGNITION");
});

test("moderate risk requires recovery when no registered fallback factor exists", () => {
  const resolved = resolveAdaptiveDecision({
    baseDecision: baseDecision("STEP_UP_TOTP"),
    factorAvailability: {
      totp: { configured: false },
      biometric: { enrolled: false },
    },
  });

  assert.equal(resolved.decision, "RECOVERY_REQUIRED");
  assert.equal(resolved.required_factor, "ACCOUNT_RECOVERY");
  assert.equal(resolved.recovery_reason, "totp_missing_or_unavailable");
});

test("high risk does not downgrade to TOTP when biometric is missing", () => {
  const resolved = resolveAdaptiveDecision({
    baseDecision: baseDecision("STEP_UP_BIOMETRIC", {
      risk_label: "high",
      required_factor: "FACE_RECOGNITION",
      auth_path: "BIOMETRIC_FACTOR",
    }),
    factorAvailability: {
      totp: { configured: true },
      biometric: { enrolled: false },
    },
  });

  assert.equal(resolved.decision, "RECOVERY_REQUIRED");
  assert.equal(
    resolved.resolution_reason,
    "high_risk_does_not_downgrade_to_totp_when_biometric_is_missing"
  );
  assert.equal(resolved.fallback_factor, "KEYCLOAK_TOTP_NOT_SUFFICIENT");
});

test("critical risk keeps hard block semantics", () => {
  const resolved = resolveAdaptiveDecision({
    baseDecision: baseDecision("BLOCK_REVIEW", {
      risk_label: "critical",
      required_factor: "ADMIN_REVIEW",
      auth_path: "TEMP_BLOCK",
    }),
    factorAvailability: {
      totp: { configured: true },
      biometric: { enrolled: true },
    },
  });

  assert.equal(resolved.decision, "BLOCK_REVIEW");
  assert.equal(resolved.resolution_status, "hard_block");
});
