const test = require("node:test");
const assert = require("node:assert/strict");

const {
  createRecoveryCodes,
  consumeRecoveryCode,
  hasActiveBootstrapApproval,
  hasRecoveryCodes,
  readPortalSecurityState,
  writePortalSecurityState,
} = require("../shared/portal-security-state");

test("recovery codes are generated and can be consumed only once", () => {
  const { codes, hashes } = createRecoveryCodes("user-1", 4);
  assert.equal(codes.length, 4);
  assert.equal(new Set(codes).size, 4);
  assert.equal(hashes.length, 4);

  const state = {
    recovery_codes: {
      hashes,
    },
  };

  const firstUse = consumeRecoveryCode(state, "user-1", codes[0]);
  assert.equal(firstUse.matched, true);
  assert.equal(firstUse.nextState.recovery_codes.hashes.length, 3);

  const secondUse = consumeRecoveryCode(
    firstUse.nextState,
    "user-1",
    codes[0]
  );
  assert.equal(secondUse.matched, false);
});

test("bootstrap approval expires based on approved_until", () => {
  const active = hasActiveBootstrapApproval({
    admin_bootstrap: {
      status: "approved",
      approved_until: "2099-01-01T00:00:00.000Z",
    },
  });
  const expired = hasActiveBootstrapApproval({
    admin_bootstrap: {
      status: "approved",
      approved_until: "2000-01-01T00:00:00.000Z",
    },
  });

  assert.equal(active, true);
  assert.equal(expired, false);
});

test("portal security state survives attribute roundtrip", () => {
  const attributes = writePortalSecurityState(
    {},
    {
      onboarding: { required: true, completed: false },
      admin_bootstrap: { status: "pending", requested_by: "portal" },
      recovery_codes: { hashes: ["abc"] },
    }
  );

  const restored = readPortalSecurityState(attributes);

  assert.equal(restored.onboarding.required, true);
  assert.equal(restored.admin_bootstrap.status, "pending");
  assert.equal(hasRecoveryCodes(restored), true);
});
