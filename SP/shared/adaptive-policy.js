function normalizeNullableBoolean(value) {
  if (value === true) return true;
  if (value === false) return false;
  return null;
}

function normalizeFactorAvailability(raw = {}) {
  const totpConfigured = normalizeNullableBoolean(
    raw?.totp?.configured ?? raw?.totpConfigured
  );
  const biometricEnrolled = normalizeNullableBoolean(
    raw?.biometric?.enrolled ?? raw?.biometricEnrolled
  );

  return {
    totp: {
      configured: totpConfigured,
      known: typeof totpConfigured === "boolean",
      source: raw?.totp?.source || "unknown",
    },
    biometric: {
      enrolled: biometricEnrolled,
      known: typeof biometricEnrolled === "boolean",
      source: raw?.biometric?.source || "unknown",
    },
  };
}

function snapshotRequestedDecision(baseDecision = {}) {
  return {
    requested_decision: baseDecision.decision || "ALLOW",
    requested_required_factor: baseDecision.required_factor || "NONE",
    requested_auth_path: baseDecision.auth_path || "SSO_ONLY",
    requested_policy_reason:
      baseDecision.policy_reason || "unknown_policy_reason",
  };
}

function withResolution(baseDecision, factorAvailability, updates = {}) {
  return {
    ...baseDecision,
    ...snapshotRequestedDecision(baseDecision),
    factor_availability: factorAvailability,
    resolution_status: "enforced_as_requested",
    resolution_reason: "requested_factor_is_available",
    completed: baseDecision.completed === true,
    ...updates,
  };
}

function resolveAdaptiveDecision({ baseDecision = {}, factorAvailability = {} }) {
  const normalizedFactors = normalizeFactorAvailability(factorAvailability);
  const totpConfigured = normalizedFactors.totp.configured;
  const biometricEnrolled = normalizedFactors.biometric.enrolled;

  if (baseDecision.decision === "ALLOW") {
    return withResolution(baseDecision, normalizedFactors, {
      resolution_status: "sso_only_allowed",
      resolution_reason: "no_step_up_required",
      completed: true,
    });
  }

  if (baseDecision.decision === "BLOCK_REVIEW") {
    return withResolution(baseDecision, normalizedFactors, {
      resolution_status: "hard_block",
      resolution_reason: "critical_risk_requires_admin_review",
      completed: false,
    });
  }

  if (baseDecision.decision === "STEP_UP_TOTP") {
    if (totpConfigured === true) {
      return withResolution(baseDecision, normalizedFactors, {
        resolution_status: "totp_primary",
        resolution_reason: "registered_totp_available",
        completed: false,
      });
    }

    if (totpConfigured === false && biometricEnrolled === true) {
      return withResolution(baseDecision, normalizedFactors, {
        decision: "STEP_UP_BIOMETRIC",
        required_factor: "FACE_RECOGNITION",
        auth_path: "BIOMETRIC_FACTOR",
        policy_reason: "totp_unavailable_biometric_fallback",
        resolution_status: "fallback_biometric",
        resolution_reason:
          "moderate_risk_can_use_registered_biometric_as_stronger_fallback",
        fallback_factor: "FACE_RECOGNITION",
        completed: false,
      });
    }

    if (totpConfigured === false) {
      return withResolution(baseDecision, normalizedFactors, {
        decision: "RECOVERY_REQUIRED",
        required_factor: "ACCOUNT_RECOVERY",
        auth_path: "RECOVERY_PENDING",
        policy_reason: "totp_unavailable_no_registered_alternative",
        resolution_status: "recovery_required",
        resolution_reason:
          "moderate_risk_requires_a_previously_registered_second_factor",
        recovery_reason: "totp_missing_or_unavailable",
        recovery_channel: "ADMIN_RESET_OR_FUTURE_RECOVERY_CODE",
        completed: false,
      });
    }

    return withResolution(baseDecision, normalizedFactors, {
      resolution_status: "totp_status_unverified",
      resolution_reason: "totp_availability_could_not_be_verified",
      completed: false,
    });
  }

  if (baseDecision.decision === "STEP_UP_BIOMETRIC") {
    if (biometricEnrolled === true) {
      return withResolution(baseDecision, normalizedFactors, {
        resolution_status: "biometric_primary",
        resolution_reason: "registered_biometric_available",
        completed: false,
      });
    }

    if (biometricEnrolled === false) {
      return withResolution(baseDecision, normalizedFactors, {
        decision: "RECOVERY_REQUIRED",
        required_factor: "ACCOUNT_RECOVERY",
        auth_path: "RECOVERY_PENDING",
        policy_reason: "high_risk_requires_registered_biometric",
        resolution_status: "recovery_required",
        resolution_reason:
          "high_risk_does_not_downgrade_to_totp_when_biometric_is_missing",
        recovery_reason: "biometric_not_enrolled_for_high_risk",
        recovery_channel: "TRUSTED_SESSION_ENROLLMENT_OR_ADMIN_RESET",
        fallback_factor:
          totpConfigured === true ? "KEYCLOAK_TOTP_NOT_SUFFICIENT" : "NONE",
        completed: false,
      });
    }

    return withResolution(baseDecision, normalizedFactors, {
      resolution_status: "biometric_status_unverified",
      resolution_reason: "biometric_availability_could_not_be_verified",
      completed: false,
    });
  }

  return withResolution(baseDecision, normalizedFactors, {
    resolution_status: "unknown_decision_passthrough",
    resolution_reason: "no_factor_resolution_rule_matched",
  });
}

module.exports = {
  normalizeFactorAvailability,
  resolveAdaptiveDecision,
};
