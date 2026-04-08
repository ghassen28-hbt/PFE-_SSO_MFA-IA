const express = require("express");
const session = require("express-session");
const dotenv = require("dotenv");
const { Issuer } = require("openid-client");
const { resolveAdaptiveDecision } = require("../shared/adaptive-policy");
const {
  createRecoveryCodes,
  consumeRecoveryCode,
  hasActiveBootstrapApproval,
  hasRecoveryCodes,
  readPortalSecurityState,
  writePortalSecurityState,
} = require("../shared/portal-security-state");

dotenv.config();

const app = express();
const PORT = Number(process.env.PORTAL_PORT || 4005);

app.use(express.json({ limit: "15mb" }));
app.use(
  express.urlencoded({
    extended: true,
    limit: "15mb",
    parameterLimit: 50000,
  })
);

app.set("trust proxy", true);

const CH_HEADER_VALUE =
  "Sec-CH-UA, Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version, Sec-CH-UA-Full-Version-List";

app.use((req, res, next) => {
  res.setHeader("Accept-CH", CH_HEADER_VALUE);
  res.setHeader("Critical-CH", CH_HEADER_VALUE);
  res.setHeader(
    "Permissions-Policy",
    'ch-ua=(self), ch-ua-platform=(self), ch-ua-platform-version=(self), ch-ua-full-version-list=(self)'
  );
  next();
});

const KC_BASE_URL = (process.env.KC_BASE_URL || "http://localhost:8081")
  .trim()
  .replace(/\/+$/, "");
const KC_PUBLIC_URL = (process.env.KC_PUBLIC_URL || KC_BASE_URL)
  .trim()
  .replace(/\/+$/, "");
const KC_REALM = (process.env.KC_REALM || "PFE-SSO").trim();

const CLIENT_ID = (process.env.PORTAL_CLIENT_ID || "portal-main-client").trim();
const CLIENT_SECRET = (process.env.PORTAL_CLIENT_SECRET || "").trim();

const STEPUP_TOTP_CLIENT_ID = (
  process.env.PORTAL_STEPUP_TOTP_CLIENT_ID || "portal-stepup-totp-client"
).trim();
const STEPUP_TOTP_CLIENT_SECRET = (
  process.env.PORTAL_STEPUP_TOTP_CLIENT_SECRET || ""
).trim();

const EVENT_COLLECTOR_URL = (
  process.env.EVENT_COLLECTOR_URL || "http://localhost:8088/events"
).trim();

const ASSESS_URL = (
  process.env.ASSESS_URL || "http://localhost:8088/assess"
).trim();

const CHECK_PASSWORD_URL = (
  process.env.CHECK_PASSWORD_URL || "http://localhost:8088/check-password"
).trim();

const BIOMETRIC_SERVICE_URL = (
  process.env.BIOMETRIC_SERVICE_URL || "http://localhost:8091"
)
  .trim()
  .replace(/\/+$/, "");

const APP_BASE_URL = (
  process.env.PORTAL_BASE_URL || `http://localhost:${PORT}`
)
  .trim()
  .replace(/\/+$/, "");

const REDIRECT_URI = `${APP_BASE_URL}/callback`;
const STEPUP_TOTP_REDIRECT_URI = `${APP_BASE_URL}/callback-stepup-totp`;
const KC_ADMIN_REALM = (process.env.KC_ADMIN_REALM || "master").trim();
const KC_ADMIN_CLIENT_ID = (process.env.KC_ADMIN_CLIENT_ID || "admin-cli").trim();
const KC_ADMIN_USERNAME = (
  process.env.KC_ADMIN_USERNAME || process.env.KEYCLOAK_ADMIN || "admin"
).trim();
const KC_ADMIN_PASSWORD = (
  process.env.KC_ADMIN_PASSWORD || process.env.KEYCLOAK_ADMIN_PASSWORD || "admin"
).trim();
const RECOVERY_CODE_COUNT = Math.max(
  4,
  Number(process.env.PORTAL_RECOVERY_CODE_COUNT || 8)
);
const ADMIN_BOOTSTRAP_APPROVAL_HOURS = Math.max(
  1,
  Number(process.env.PORTAL_ADMIN_BOOTSTRAP_APPROVAL_HOURS || 24)
);

const IS_HTTPS_APP = APP_BASE_URL.startsWith("https://");
const SESSION_COOKIE_NAME =
  process.env.PORTAL_SESSION_COOKIE_NAME || "pfe_portal_sid";
const SESSION_COOKIE_OPTIONS = {
  path: "/",
  httpOnly: true,
  secure: IS_HTTPS_APP,
  sameSite: "lax",
};

if (!CLIENT_SECRET) {
  console.error("[portal] PORTAL_CLIENT_SECRET missing in .env");
  process.exit(1);
}

if (!STEPUP_TOTP_CLIENT_SECRET) {
  console.error("[portal] PORTAL_STEPUP_TOTP_CLIENT_SECRET missing in .env");
  process.exit(1);
}

app.use(
  session({
    name: SESSION_COOKIE_NAME,
    secret: process.env.SESSION_SECRET || "change_me",
    resave: false,
    saveUninitialized: false,
    cookie: SESSION_COOKIE_OPTIONS,
  })
);

let portalClient;
let stepupTotpClient;
let issuerUrl;
let keycloakAdminTokenCache = {
  token: null,
  expiresAt: 0,
};

function decodeJwtPayload(token) {
  try {
    if (!token || typeof token !== "string") return {};
    const parts = token.split(".");
    if (parts.length < 2) return {};
    const payload = parts[1];
    const normalized = payload.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
    return JSON.parse(Buffer.from(padded, "base64").toString("utf8"));
  } catch {
    return {};
  }
}

function extractRealmRoles(accessToken) {
  const payload = decodeJwtPayload(accessToken);
  const roles = payload?.realm_access?.roles;
  return Array.isArray(roles) ? roles : [];
}

function normalizeRiskScore(rawScore) {
  if (rawScore == null || rawScore === "") return null;
  const score = Number(rawScore);
  if (!Number.isFinite(score)) return null;
  const normalized = score > 1 ? score / 100 : score;
  return Number(normalized.toFixed(4));
}

function formatRiskScore(rawScore) {
  const normalized = normalizeRiskScore(rawScore);
  return normalized == null ? "n/a" : normalized.toFixed(4);
}

function looksLikeJwt(token) {
  return typeof token === "string" && token.split(".").length >= 3;
}

function selectLogoutContext(req) {
  const candidates = [
    {
      idToken: req.session?.tokens?.id_token,
      fallbackClientId: CLIENT_ID,
    },
    {
      idToken: req.session?.stepupTokens?.id_token,
      fallbackClientId: STEPUP_TOTP_CLIENT_ID,
    },
  ];

  for (const candidate of candidates) {
    if (!looksLikeJwt(candidate.idToken)) continue;
    const payload = decodeJwtPayload(candidate.idToken);
    const tokenClientId =
      payload?.azp ||
      (Array.isArray(payload?.aud) ? payload.aud[0] : payload?.aud) ||
      candidate.fallbackClientId;

    return {
      idToken: candidate.idToken,
      clientId: tokenClientId,
    };
  }

  return {
    idToken: null,
    clientId: CLIENT_ID,
  };
}

function buildLogoutUrl({ idToken, clientId }) {
  const logoutUrl = `${KC_PUBLIC_URL}/realms/${KC_REALM}/protocol/openid-connect/logout`;
  const params = new URLSearchParams();
  params.set("post_logout_redirect_uri", `${APP_BASE_URL}/`);

  if (looksLikeJwt(idToken)) {
    params.set("id_token_hint", idToken);
    return `${logoutUrl}?${params.toString()}`;
  }

  params.set("client_id", clientId || CLIENT_ID);
  return `${logoutUrl}?${params.toString()}`;
}

function buildFreshLoginUrl(oidcClient, extraParams = {}) {
  return oidcClient.authorizationUrl({
    scope: "openid profile email",
    prompt: "login",
    max_age: 0,
    ...extraParams,
  });
}

function buildStepupTotpUrl(req) {
  const user = req.session?.user || {};
  const loginHint =
    user.preferred_username || user.email || user.username || user.sub || "";

  const params = {
    scope: "openid profile email",
  };

  if (loginHint) {
    params.login_hint = loginHint;
  }

  return stepupTotpClient.authorizationUrl(params);
}

function buildConfigureTotpActionUrl(req) {
  const user = req.session?.user || {};
  const loginHint =
    user.preferred_username || user.email || user.username || user.sub || "";

  const params = {
    scope: "openid profile email",
    kc_action: "CONFIGURE_TOTP",
  };

  if (loginHint) {
    params.login_hint = loginHint;
  }

  return portalClient.authorizationUrl(params);
}

function canManageFactorsInSession(adaptive = {}) {
  return (
    adaptive.completed === true ||
    adaptive.decision === "ALLOW" ||
    adaptive.decision === "ONBOARDING_REQUIRED"
  );
}

function factorStatusLabel(configured, truthyLabel, falsyLabel) {
  if (configured === true) return truthyLabel;
  if (configured === false) return falsyLabel;
  return "status unavailable";
}

async function fetchKeycloakAdminToken() {
  const now = Date.now();
  if (
    keycloakAdminTokenCache.token &&
    now < keycloakAdminTokenCache.expiresAt - 15000
  ) {
    return keycloakAdminTokenCache.token;
  }

  const tokenUrl = `${KC_BASE_URL}/realms/${KC_ADMIN_REALM}/protocol/openid-connect/token`;
  const body = new URLSearchParams({
    grant_type: "password",
    client_id: KC_ADMIN_CLIENT_ID,
    username: KC_ADMIN_USERNAME,
    password: KC_ADMIN_PASSWORD,
  });

  const response = await fetch(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });

  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new Error(
      `[portal] keycloak admin token error: ${response.status} ${response.statusText} ${text}`.trim()
    );
  }

  const payload = await response.json();
  const expiresInSeconds = Math.max(Number(payload.expires_in || 60), 30);

  keycloakAdminTokenCache = {
    token: payload.access_token,
    expiresAt: now + expiresInSeconds * 1000,
  };

  return payload.access_token;
}

async function getKeycloakTotpStatus(user) {
  const userId = user?.sub;
  if (!userId) {
    return {
      configured: null,
      known: false,
      source: "missing_user_id",
    };
  }

  try {
    const adminToken = await fetchKeycloakAdminToken();
    const response = await fetch(
      `${KC_BASE_URL}/admin/realms/${KC_REALM}/users/${encodeURIComponent(userId)}/credentials`,
      {
        headers: {
          Authorization: `Bearer ${adminToken}`,
          Accept: "application/json",
        },
      }
    );

    if (!response.ok) {
      const text = await response.text().catch(() => "");
      throw new Error(
        `[portal] keycloak credentials error: ${response.status} ${response.statusText} ${text}`.trim()
      );
    }

    const credentials = await response.json();
    const configured = Array.isArray(credentials)
      ? credentials.some((credential) => String(credential?.type || "").toLowerCase() === "otp")
      : false;

    return {
      configured,
      known: true,
      source: "keycloak_admin_credentials",
    };
  } catch (error) {
    console.error("[portal] TOTP status lookup error:", error?.message || error);
    return {
      configured: null,
      known: false,
      source: "lookup_error",
    };
  }
}

async function getFactorAvailability(user) {
  const result = {
    totp: {
      configured: null,
      known: false,
      source: "unknown",
    },
    biometric: {
      enrolled: null,
      known: false,
      source: "unknown",
      enrolled_at: null,
    },
  };

  const [totpStatus, biometricStatus] = await Promise.allSettled([
    getKeycloakTotpStatus(user),
    getBiometricProfileStatus(user),
  ]);

  if (totpStatus.status === "fulfilled") {
    result.totp = {
      configured: totpStatus.value.configured,
      known: totpStatus.value.known === true,
      source: totpStatus.value.source || "unknown",
    };
  }

  if (biometricStatus.status === "fulfilled") {
    result.biometric = {
      enrolled:
        biometricStatus.value?.enrolled === true
          ? true
          : biometricStatus.value?.enrolled === false
            ? false
            : null,
      known: typeof biometricStatus.value?.enrolled === "boolean",
      source: "biometric_service",
      enrolled_at: biometricStatus.value?.enrolled_at || null,
    };
  } else {
    console.error(
      "[portal] biometric factor availability error:",
      biometricStatus.reason?.message || biometricStatus.reason || "unknown"
    );
  }

  return result;
}

async function getKeycloakUserRecord(userId) {
  const adminToken = await fetchKeycloakAdminToken();
  const response = await fetch(
    `${KC_BASE_URL}/admin/realms/${KC_REALM}/users/${encodeURIComponent(userId)}`,
    {
      headers: {
        Authorization: `Bearer ${adminToken}`,
        Accept: "application/json",
      },
    }
  );

  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new Error(
      `[portal] keycloak user read error: ${response.status} ${response.statusText} ${text}`.trim()
    );
  }

  return await response.json();
}

async function updateKeycloakUserState(userId, updater) {
  const adminToken = await fetchKeycloakAdminToken();
  const currentUser = await getKeycloakUserRecord(userId);
  const currentState = readPortalSecurityState(currentUser.attributes);
  const nextState = await updater(currentState, currentUser);
  const nextUser = {
    ...currentUser,
    attributes: writePortalSecurityState(currentUser.attributes, nextState),
  };

  const response = await fetch(
    `${KC_BASE_URL}/admin/realms/${KC_REALM}/users/${encodeURIComponent(userId)}`,
    {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${adminToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(nextUser),
    }
  );

  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new Error(
      `[portal] keycloak user update error: ${response.status} ${response.statusText} ${text}`.trim()
    );
  }

  return nextState;
}

async function getPortalSecurityState(user) {
  if (!user?.sub) {
    return readPortalSecurityState({});
  }

  try {
    const record = await getKeycloakUserRecord(user.sub);
    return readPortalSecurityState(record.attributes);
  } catch (error) {
    console.error("[portal] portal security state read error:", error?.message || error);
    return readPortalSecurityState({});
  }
}

function needsTrustedOnboarding({ factorAvailability }) {
  return factorAvailability?.totp?.configured !== true;
}

async function ensurePendingAdminBootstrapRequest({
  userinfo,
  adaptiveDecision,
  req,
}) {
  return await updateKeycloakUserState(userinfo.sub, (state) => ({
    ...state,
    onboarding: {
      ...state.onboarding,
      required: true,
      required_since: state.onboarding?.required_since || new Date().toISOString(),
    },
    admin_bootstrap: {
      ...state.admin_bootstrap,
      status: "pending",
      requested_at: new Date().toISOString(),
      requested_by: userinfo.preferred_username || userinfo.email || userinfo.sub,
      requested_reason: "risky_first_login_without_registered_totp",
      requested_decision:
        adaptiveDecision.requested_decision || adaptiveDecision.decision || "ALLOW",
      requested_policy_reason:
        adaptiveDecision.requested_policy_reason ||
        adaptiveDecision.policy_reason ||
        "unknown_policy_reason",
      requested_risk_label: adaptiveDecision.risk_label || "unknown",
      requested_risk_score:
        adaptiveDecision.risk_score == null ? null : Number(adaptiveDecision.risk_score),
      request_ip:
        req.headers["x-forwarded-for"]?.split(",")[0].trim() ||
        req.headers["x-real-ip"] ||
        req.socket?.remoteAddress ||
        null,
      approved_at: null,
      approved_by: null,
      approved_until: null,
      rejection_reason: null,
    },
  }));
}

async function markOnboardingCompleted(user, currentState, completedBy) {
  return await updateKeycloakUserState(user.sub, (state) => ({
    ...state,
    onboarding: {
      ...state.onboarding,
      required: false,
      completed: true,
      completed_at: new Date().toISOString(),
      completed_by: completedBy,
    },
    admin_bootstrap: {
      ...state.admin_bootstrap,
      status:
        state.admin_bootstrap?.status === "approved"
          ? "consumed"
          : state.admin_bootstrap?.status || "none",
    },
  }));
}

async function issueRecoveryCodesForUser(user, generatedBy) {
  const generated = createRecoveryCodes(user.sub, RECOVERY_CODE_COUNT);
  const nextState = await updateKeycloakUserState(user.sub, (state) => ({
    ...state,
    recovery_codes: {
      hashes: generated.hashes,
      generated_at: new Date().toISOString(),
      generated_by: generatedBy,
      last_used_at: state.recovery_codes?.last_used_at || null,
    },
  }));

  return {
    plainCodes: generated.codes,
    securityState: nextState,
  };
}

async function consumeRecoveryCodeForUser(user, candidateCode) {
  let matched = false;

  const nextState = await updateKeycloakUserState(user.sub, (state) => {
    const result = consumeRecoveryCode(state, user.sub, candidateCode);
    matched = result.matched;
    return result.nextState;
  });

  return {
    matched,
    securityState: nextState,
  };
}

function buildOnboardingDecision(baseDecision, source) {
  return {
    ...baseDecision,
    requested_decision: baseDecision.requested_decision || baseDecision.decision || "ALLOW",
    requested_required_factor:
      baseDecision.requested_required_factor || baseDecision.required_factor || "NONE",
    requested_auth_path:
      baseDecision.requested_auth_path || baseDecision.auth_path || "SSO_ONLY",
    requested_policy_reason:
      baseDecision.requested_policy_reason ||
      baseDecision.policy_reason ||
      "unknown_policy_reason",
    decision: "ONBOARDING_REQUIRED",
    required_factor: "KEYCLOAK_TOTP_SETUP",
    auth_path: "TRUSTED_ONBOARDING",
    policy_reason:
      source === "admin_approved"
        ? "admin_approved_trusted_onboarding"
        : "trusted_first_login_factor_bootstrap",
    completed: false,
    resolution_reason:
      source === "admin_approved"
        ? "admin_validated_bootstrap_allows_onboarding_only_session"
        : "low_risk_session_can_bootstrap_initial_totp",
  };
}

function buildAdminValidationRequiredDecision(baseDecision) {
  return {
    ...baseDecision,
    requested_decision: baseDecision.requested_decision || baseDecision.decision || "ALLOW",
    requested_required_factor:
      baseDecision.requested_required_factor || baseDecision.required_factor || "NONE",
    requested_auth_path:
      baseDecision.requested_auth_path || baseDecision.auth_path || "SSO_ONLY",
    requested_policy_reason:
      baseDecision.requested_policy_reason ||
      baseDecision.policy_reason ||
      "unknown_policy_reason",
    decision: "ADMIN_VALIDATION_REQUIRED",
    required_factor: "ADMIN_APPROVAL",
    auth_path: "ADMIN_BOOTSTRAP_REVIEW",
    policy_reason: "risky_first_login_requires_admin_bootstrap_approval",
    completed: false,
    resolution_reason:
      "no_registered_factor_exists_and_risk_is_not_low_for_initial_bootstrap",
  };
}

function randomBiometricChallengeType() {
  return Math.random() < 0.5 ? "turn_left" : "turn_right";
}

function issueBiometricChallenge(req) {
  const challengeType = randomBiometricChallengeType();
  if (req.session) {
    req.session.pendingBiometricChallenge = {
      type: challengeType,
      issued_at: new Date().toISOString(),
    };
  }
  return challengeType;
}

function redirectToFreshLogin(req, res, oidcClient, extraParams = {}) {
  const loginUrl = buildFreshLoginUrl(oidcClient, extraParams);

  const finishRedirect = () => {
    res.clearCookie(SESSION_COOKIE_NAME, SESSION_COOKIE_OPTIONS);
    res.redirect(loginUrl);
  };

  if (!req.session) {
    finishRedirect();
    return;
  }

  req.session.destroy((err) => {
    if (err) {
      console.error("[portal] Session destroy before login error:", err);
    }
    finishRedirect();
  });
}

async function buildClient({
  kcBaseUrl,
  realm,
  clientId,
  clientSecret,
  redirectUri,
}) {
  const discoveryUrl = `${kcBaseUrl}/realms/${realm}/.well-known/openid-configuration`;
  const issuer = await Issuer.discover(discoveryUrl);

  const oidcClient = new issuer.Client({
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uris: [redirectUri],
    response_types: ["code"],
    token_endpoint_auth_method: "client_secret_post",
  });

  return {
    issuerUrl: issuer.issuer,
    client: oidcClient,
  };
}

function normalizeIp(raw) {
  if (!raw) return "";
  const ip = String(raw).split(",")[0].trim();
  if (ip.startsWith("::ffff:")) return ip.slice(7);
  return ip;
}

function getClientIp(req) {
  return (
    normalizeIp(req.headers["cf-connecting-ip"]) ||
    normalizeIp(req.headers["x-forwarded-for"]) ||
    normalizeIp(req.headers["x-real-ip"]) ||
    normalizeIp(req.ip) ||
    normalizeIp(req.socket?.remoteAddress) ||
    ""
  );
}

function getClientHints(req) {
  return {
    http_sec_ch_ua: req.headers["sec-ch-ua"] || "",
    http_sec_ch_ua_platform: req.headers["sec-ch-ua-platform"] || "",
    http_sec_ch_ua_platform_version:
      req.headers["sec-ch-ua-platform-version"] || "",
    http_sec_ch_ua_full_version_list:
      req.headers["sec-ch-ua-full-version-list"] || "",
    http_accept_language: req.headers["accept-language"] || "",
  };
}

function buildCommonSecurityContext(req, userinfo) {
  const ip = getClientIp(req);
  const ua = req.headers["user-agent"] || "";
  const ch = getClientHints(req);

  return {
    realm: KC_REALM,
    clientId: CLIENT_ID,
    userId: userinfo.sub,
    details: {
      username: userinfo.preferred_username || userinfo.email || "",
    },
    ipAddress: ip,
    http_x_forwarded_for: ip,
    http_x_real_ip: ip,
    http_user_agent: ua,
    http_sec_ch_ua: ch.http_sec_ch_ua,
    http_sec_ch_ua_platform: ch.http_sec_ch_ua_platform,
    http_sec_ch_ua_platform_version: ch.http_sec_ch_ua_platform_version,
    http_sec_ch_ua_full_version_list: ch.http_sec_ch_ua_full_version_list,
    http_accept_language: ch.http_accept_language,
  };
}

function htmlPage(title, content) {
  return `
    ${styles}
    <div class="admin-container">
      <h2>${title}</h2>
      ${content}
    </div>
  `;
}

function renderForbidden(res, username, roles) {
  return res.status(403).send(
    htmlPage(
      "Accès refusé",
      `
        <p>Désolé <b>${username || "utilisateur"}</b>, tu n'as pas accès à cette application.</p>
        <p>Rôle(s): <b>${roles?.length ? roles.join(", ") : "aucun"}</b></p>
        <a href="/logout" class="btn btn-logout">Logout</a>
      `
    )
  );
}

function renderAdaptiveDecision(res, title, message, details, actions = "") {
  return res.status(403).send(
    htmlPage(
      title,
      `
        <p>${message}</p>
        ${details ? `<p>${details}</p>` : ""}
        ${actions}
      `
    )
  );
}

function requirePortalAccess(req, res, next) {
  const publicPaths = [
    "/login",
    "/callback",
    "/callback-stepup-totp",
    "/start-stepup-totp",
    "/logout",
    "/adaptive-stepup",
    "/adaptive-recovery",
    "/adaptive-recovery-code",
    "/adaptive-recovery-code/verify",
    "/adaptive-switch-to-biometric",
    "/adaptive-blocked",
    "/adaptive-biometric-verify",
    "/security/onboarding",
    "/security/onboarding/complete",
    "/security/recovery-codes",
    "/security/recovery-codes/generate",
    "/security/setup-face",
    "/security/setup-face/capture",
    "/security/manage-keycloak-otp",
    "/security/manage-keycloak-otp/start",
  ];

  if (publicPaths.includes(req.path)) return next();
  if (!req.session.user) return next();

  const roles = req.session?.user?.roles || [];
  const rolesNorm = roles.map((r) => String(r).toLowerCase());

  const allowed = ["ceo", "manager", "employee"];
  const ok = allowed.some((r) => rolesNorm.includes(r));

  if (!ok) {
    const username =
      req.session.user.preferred_username || req.session.user.email || "user";
    return renderForbidden(res, username, roles);
  }

  if (req.session.adaptiveAuth?.completed !== true) {
    const decision = req.session.adaptiveAuth?.decision;
    if (decision === "ONBOARDING_REQUIRED") {
      return res.redirect("/security/onboarding");
    }
    if (decision === "ADMIN_VALIDATION_REQUIRED") {
      return res.redirect("/adaptive-recovery");
    }
    if (decision === "STEP_UP_TOTP" || decision === "STEP_UP_BIOMETRIC") {
      return res.redirect("/adaptive-stepup");
    }
    if (decision === "RECOVERY_REQUIRED") {
      return res.redirect("/adaptive-recovery");
    }
    if (decision === "BLOCK_REVIEW") {
      return res.redirect("/adaptive-blocked");
    }
  }

  next();
}

const styles = `
  <style>
    body {
      margin: 0;
      min-height: 100vh;
      display: flex;
      justify-content: center;
      align-items: center;
      background-color: #f4f7f6;
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      padding: 20px;
      box-sizing: border-box;
    }
    .admin-container {
      background-color: #ffffff;
      padding: 40px;
      border-radius: 12px;
      box-shadow: 0 8px 16px rgba(0, 0, 0, 0.1);
      text-align: center;
      width: 100%;
      max-width: 620px;
    }
    h2 {
      color: #2c3e50;
      margin-top: 0;
      margin-bottom: 20px;
      font-size: 24px;
    }
    p {
      color: #555;
      font-size: 16px;
      margin-bottom: 18px;
      line-height: 1.5;
    }
    .btn {
      display: block;
      color: #ffffff;
      text-decoration: none;
      padding: 12px 24px;
      border-radius: 6px;
      font-weight: 600;
      font-size: 16px;
      width: 100%;
      box-sizing: border-box;
      transition: all 0.3s ease;
      margin-bottom: 12px;
      border: none;
      cursor: pointer;
    }
    .btn:last-child { margin-bottom: 0; }
    .btn-login { background-color: #007bff; }
    .btn-login:hover { background-color: #0056b3; transform: translateY(-2px); }
    .btn-secondary { background-color: #6c757d; }
    .btn-secondary:hover { background-color: #5a6268; transform: translateY(-2px); }
    .btn-logout { background-color: #dc3545; }
    .btn-logout:hover { background-color: #c82333; transform: translateY(-2px); }
    .btn-success { background-color: #28a745; }
    .btn-success:hover { background-color: #218838; transform: translateY(-2px); }
    .badge {
      display: inline-block;
      padding: 8px 12px;
      border-radius: 20px;
      font-size: 14px;
      font-weight: 700;
      margin-bottom: 14px;
      background: #eef2f7;
      color: #2c3e50;
    }
    .small {
      font-size: 14px;
      color: #6b7280;
    }
    .field {
      width: 100%;
      padding: 12px;
      border-radius: 6px;
      border: 1px solid #d1d5db;
      font-size: 16px;
      margin-bottom: 14px;
      box-sizing: border-box;
      text-align: center;
    }
    .error {
      color: #b91c1c;
      font-weight: 600;
    }
    .info-box {
      background: #f8fafc;
      border: 1px solid #e5e7eb;
      border-radius: 8px;
      padding: 14px;
      margin-bottom: 18px;
      text-align: left;
    }
  </style>
`;

app.use(requirePortalAccess);

(async () => {
  try {
    const portalBuilt = await buildClient({
      kcBaseUrl: KC_BASE_URL,
      realm: KC_REALM,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      redirectUri: REDIRECT_URI,
    });

    const stepupBuilt = await buildClient({
      kcBaseUrl: KC_BASE_URL,
      realm: KC_REALM,
      clientId: STEPUP_TOTP_CLIENT_ID,
      clientSecret: STEPUP_TOTP_CLIENT_SECRET,
      redirectUri: STEPUP_TOTP_REDIRECT_URI,
    });

    portalClient = portalBuilt.client;
    stepupTotpClient = stepupBuilt.client;
    issuerUrl = portalBuilt.issuerUrl;

    console.log(`[portal] ready: ${APP_BASE_URL}`);
    console.log(`[portal] issuerUrl: ${issuerUrl}`);
    console.log(`[portal] redirectUri: ${REDIRECT_URI}`);
    console.log(`[portal] stepup redirectUri: ${STEPUP_TOTP_REDIRECT_URI}`);
  } catch (err) {
    console.error("[portal] OIDC init error full:", err);
    console.error("[portal] OIDC init error message:", err?.message || err);
  }
})();

app.get("/", async (req, res) => {
  if (!req.session.user) {
    return res.send(
      htmlPage("Portal", `<a href="/login" class="btn btn-login">Login</a>`)
    );
  }

  const username =
    req.session.user.preferred_username || req.session.user.email || "user";
  const roles = (req.session.user.roles || []).join(", ") || "none";
  const adaptive = req.session.adaptiveAuth || {};
  const factorAvailability = await getFactorAvailability(req.session.user);
  const securityState = await getPortalSecurityState(req.session.user);

  const adaptiveInfo = adaptive.decision
    ? `
      <p><b>Risk label:</b> ${adaptive.risk_label || "unknown"}</p>
      <p><b>Decision:</b> ${adaptive.decision}</p>
      <p><b>Required factor:</b> ${adaptive.required_factor || "NONE"}</p>
      <p><b>Auth path:</b> ${adaptive.auth_path || "SSO_ONLY"}</p>
      <p><b>Policy reason:</b> ${adaptive.policy_reason || "n/a"}</p>
      <p><b>Risk score:</b> ${formatRiskScore(adaptive.risk_score)}</p>
      <p><b>Adaptive auth completed:</b> ${adaptive.completed ? "yes" : "no"}</p>
      ${
        adaptive.biometric_similarity_primary != null
          ? `<p><b>Biometric similarity primary:</b> ${adaptive.biometric_similarity_primary}</p>`
          : ""
      }
      ${
        adaptive.biometric_similarity_challenge != null
          ? `<p><b>Biometric similarity challenge:</b> ${adaptive.biometric_similarity_challenge}</p>`
          : ""
      }
      ${
        adaptive.liveness_passed != null
          ? `<p><b>Liveness passed:</b> ${adaptive.liveness_passed ? "yes" : "no"}</p>`
          : ""
      }
      ${
        adaptive.liveness_reason
          ? `<p><b>Liveness reason:</b> ${adaptive.liveness_reason}</p>`
          : ""
      }
    `
    : `<p><b>Adaptive auth:</b> not evaluated</p>`;

  const adaptiveResolutionInfo =
    adaptive.requested_decision && adaptive.requested_decision !== adaptive.decision
      ? `
        <p><b>Requested decision:</b> ${adaptive.requested_decision}</p>
        <p><b>Resolution reason:</b> ${adaptive.resolution_reason || "n/a"}</p>
      `
      : "";

  const totpInfoResolved = `
    <p><b>TOTP:</b> ${factorStatusLabel(
      factorAvailability.totp.configured,
      "configured in Keycloak",
      "not configured in Keycloak"
    )}</p>
    <p class="small">
      En cas de changement de tÃ©lÃ©phone, on tente d'abord un autre facteur dÃ©jÃ  enregistrÃ©. Sinon, l'accÃ¨s bascule vers une rÃ©cupÃ©ration contrÃ´lÃ©e.
    </p>
    <a href="/security/manage-keycloak-otp" class="btn btn-secondary">Gerer OTP Keycloak</a>
  `;

  const biometricInfoResolved = `
    <p><b>Biometric setup:</b> ${factorStatusLabel(
      factorAvailability.biometric.enrolled,
      "configured",
      "not configured"
    )}</p>
    ${
      factorAvailability.biometric.enrolled
        ? `<p class="small">Dernier enrÃ´lement: ${factorAvailability.biometric.enrolled_at || "n/a"}</p>`
        : `<p class="small">Configure d'abord ton profil facial depuis une session de confiance.</p>`
    }
  `;

  const totpInfoDisplay = `
    <p><b>TOTP:</b> ${factorStatusLabel(
      factorAvailability.totp.configured,
      "configured in Keycloak",
      "not configured in Keycloak"
    )}</p>
    <p><b>Recovery codes:</b> ${
      hasRecoveryCodes(securityState)
        ? `${securityState.recovery_codes.remaining} remaining`
        : "not generated"
    }</p>
    <p class="small">
      En cas de changement de telephone, on tente d'abord un autre facteur deja enregistre. Sinon, l'acces bascule vers une recuperation controlee.
    </p>
    <a href="/security/manage-keycloak-otp" class="btn btn-secondary">Gerer OTP Keycloak</a>
    ${
      factorAvailability.totp.configured === true && canManageFactorsInSession(adaptive)
        ? `<a href="/security/recovery-codes" class="btn btn-secondary">Voir les recovery codes</a>`
        : ""
    }
  `;

  const biometricInfoDisplay = `
    <p><b>Biometric setup:</b> ${factorStatusLabel(
      factorAvailability.biometric.enrolled,
      "configured",
      "not configured"
    )}</p>
    ${
      factorAvailability.biometric.enrolled
        ? `<p class="small">Dernier enrollement: ${factorAvailability.biometric.enrolled_at || "n/a"}</p>`
        : `<p class="small">Configure d'abord ton profil facial depuis une session de confiance.</p>`
    }
  `;

  const biometricStatus = {
    enrolled: factorAvailability.biometric.enrolled === true,
    enrolled_at: factorAvailability.biometric.enrolled_at || null,
  };

  const totpInfo = `
    <p><b>TOTP:</b> géré nativement par Keycloak</p>
    <p class="small">
      En cas de changement de téléphone, il faut réenrôler ou réinitialiser l’OTP côté Keycloak.
    </p>
  `;

  const biometricInfo = `
    <p><b>Biometric setup:</b> ${biometricStatus.enrolled ? "configured" : "not configured"}</p>
    ${
      biometricStatus.enrolled
        ? `<p class="small">Dernier enrôlement: ${biometricStatus.enrolled_at || "n/a"}</p>`
        : `<p class="small">Configure d’abord ton profil facial depuis une session de confiance.</p>`
    }
  `;

  res.send(
    htmlPage(
      "Portal",
      `
        <p>Connecté: <b>${username}</b></p>
        <p>Rôles: <b>${roles}</b></p>
        ${adaptiveInfo}
        ${adaptiveResolutionInfo}
        ${totpInfoDisplay}
        ${biometricInfoDisplay}
        
        <a href="/security/setup-face" class="btn btn-success">Configurer biométrie faciale</a>
        <a href="/protected" class="btn btn-secondary">Page protégée</a>
        <a href="/logout" class="btn btn-logout">Logout</a>
      `
    )
  );
});

app.get("/login", (req, res) => {
  if (!portalClient) return res.status(503).send("OIDC client not ready, retry.");
  redirectToFreshLogin(req, res, portalClient);
});

async function sendAppSessionStartedEvent({ userinfo, req, sessionId }) {
  const payload = {
    type: "APP_SESSION_STARTED",
    ...buildCommonSecurityContext(req, userinfo),
    sessionId,
  };

  const eventRes = await fetch(EVENT_COLLECTOR_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-forwarded-for": payload.ipAddress,
      "x-real-ip": payload.ipAddress,
    },
    body: JSON.stringify(payload),
  });

  if (!eventRes.ok) {
    const text = await eventRes.text().catch(() => "");
    throw new Error(
      `[portal] event-collector error: ${eventRes.status} ${eventRes.statusText} ${text}`.trim()
    );
  }

  return await eventRes.json().catch(() => ({}));
}

async function assessAdaptiveRisk({ userinfo, req }) {
  const payload = buildCommonSecurityContext(req, userinfo);

  const assessRes = await fetch(ASSESS_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-forwarded-for": payload.ipAddress,
      "x-real-ip": payload.ipAddress,
    },
    body: JSON.stringify(payload),
  });

  if (!assessRes.ok) {
    const text = await assessRes.text().catch(() => "");
    throw new Error(
      `[portal] assess error: ${assessRes.status} ${assessRes.statusText} ${text}`.trim()
    );
  }

  return await assessRes.json();
}

async function getBiometricProfileStatus(user) {
  const userId = user?.sub;
  if (!userId) return { enrolled: false };

  const res = await fetch(
    `${BIOMETRIC_SERVICE_URL}/profiles/${encodeURIComponent(userId)}`
  );

  if (res.status === 404) {
    return { enrolled: false };
  }

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(
      `[portal] biometric status error: ${res.status} ${res.statusText} ${text}`.trim()
    );
  }

  return await res.json();
}

async function enrollBiometricProfile(user, imageBase64) {
  const res = await fetch(`${BIOMETRIC_SERVICE_URL}/enroll`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      user_id: user.sub,
      username: user.preferred_username || user.email || "",
      image_base64: imageBase64,
    }),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(
      `[portal] biometric enroll error: ${res.status} ${res.statusText} ${text}`.trim()
    );
  }

  return await res.json();
}

async function verifyBiometricProfile(
  user,
  primaryImageBase64,
  challengeImageBase64,
  challengeType = "turn_left"
) {
  const res = await fetch(`${BIOMETRIC_SERVICE_URL}/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      user_id: user.sub,
      username: user.preferred_username || user.email || "",
      image_base64: primaryImageBase64,
      challenge_image_base64: challengeImageBase64,
      challenge_type: challengeType,
      enforce_liveness: true,
    }),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(
      `[portal] biometric verify error: ${res.status} ${res.statusText} ${text}`.trim()
    );
  }

  return await res.json();
}

function renderBiometricCapturePage({
  title,
  message,
  action,
  buttonLabel,
  infoHtml = "",
  errorMessage = "",
  activeLiveness = false,
  challengeType = "turn_left",
}) {
  const challengeLabel =
    challengeType === "turn_left"
      ? "Tourne légèrement la tête vers ta droite (effet miroir caméra)"
      : "Tourne légèrement la tête vers ta gauche (effet miroir caméra)";

  return htmlPage(
    title,
    `
      <p>${message}</p>
      <p class="small">Remarque : l’aperçu caméra est inversé comme un miroir.</p>
      ${infoHtml}
      ${errorMessage ? `<p class="error">${errorMessage}</p>` : ""}
      <div class="info-box">
        <video id="camera" autoplay playsinline style="width:100%; border-radius:8px; margin-bottom:12px; background:#111;"></video>
        <canvas id="snapshot" style="display:none;"></canvas>
        <p id="captureStatus" class="small">
          ${
            activeLiveness
              ? "Étape 1/2 : garde le visage bien en face de la caméra."
              : "Capture simple d’enrôlement."
          }
        </p>
      </div>

      <form id="biometricForm" method="post" action="${action}">
        <input type="hidden" name="image_base64" id="image_base64" />
        <input type="hidden" name="challenge_image_base64" id="challenge_image_base64" />
        <input type="hidden" name="challenge_type" id="challenge_type" value="${challengeType}" />
        <button type="button" id="captureBtn" class="btn btn-success">${buttonLabel}</button>
      </form>

      <a href="/" class="btn btn-secondary">Retour</a>
      <a href="/logout" class="btn btn-logout">Logout</a>

      <script>
        (async () => {
          const video = document.getElementById("camera");
          const canvas = document.getElementById("snapshot");
          const imageInput = document.getElementById("image_base64");
          const challengeInput = document.getElementById("challenge_image_base64");
          const captureBtn = document.getElementById("captureBtn");
          const form = document.getElementById("biometricForm");
          const captureStatus = document.getElementById("captureStatus");

          const activeLiveness = ${activeLiveness ? "true" : "false"};
          const challengeLabel = ${JSON.stringify(challengeLabel)};
          let captureStep = activeLiveness ? 1 : 0;
          let streamRef = null;

          try {
            const stream = await navigator.mediaDevices.getUserMedia({
              video: {
                width: { ideal: 640 },
                height: { ideal: 480 },
                facingMode: "user"
              },
              audio: false
            });
            streamRef = stream;
            video.srcObject = stream;
          } catch (err) {
            alert("Impossible d'accéder à la caméra: " + (err?.message || err));
            return;
          }

          function stopStream() {
            if (!streamRef) return;
            streamRef.getTracks().forEach((track) => track.stop());
          }

          function captureFrame() {
            const targetWidth = 480;
            const targetHeight = 360;

            canvas.width = targetWidth;
            canvas.height = targetHeight;

            const ctx = canvas.getContext("2d");
            ctx.drawImage(video, 0, 0, targetWidth, targetHeight);

            return canvas.toDataURL("image/jpeg", 0.82);
          }

          captureBtn.addEventListener("click", () => {
            if (!activeLiveness) {
              imageInput.value = captureFrame();
              captureBtn.disabled = true;
              captureBtn.textContent = "Envoi en cours...";
              stopStream();
              form.submit();
              return;
            }

            if (captureStep === 1) {
              imageInput.value = captureFrame();
              captureStep = 2;
              captureStatus.textContent = "Étape 2/2 : " + challengeLabel + ", puis clique de nouveau.";
              captureBtn.textContent = "Capturer l’étape 2";
              return;
            }

            challengeInput.value = captureFrame();
            captureBtn.disabled = true;
            captureBtn.textContent = "Vérification en cours...";
            stopStream();
            form.submit();
          });
        })();
      </script>
    `
  );
}

app.get("/callback", async (req, res) => {
  try {
    if (!portalClient) return res.status(503).send("OIDC client not ready, retry.");

    const pendingAccountAction = req.session?.pendingAccountAction || null;
    const params = portalClient.callbackParams(req);
    const tokenSet = await portalClient.callback(REDIRECT_URI, params);
    const userinfo = await portalClient.userinfo(tokenSet.access_token);

    const roles = extractRealmRoles(tokenSet.access_token);
    const isPendingConfigureTotpAction =
      pendingAccountAction?.type === "CONFIGURE_TOTP";

    let adaptiveDecision = isPendingConfigureTotpAction
      ? { ...(req.session?.adaptiveAuth || {}) }
      : {
          risk_score: null,
          risk_label: "unknown",
          decision: "ALLOW",
          required_factor: "NONE",
          auth_path: "SSO_ONLY",
          policy_reason: "assess_fallback_allow",
          completed: true,
        };

    if (!isPendingConfigureTotpAction) {
      try {
        const assess = await assessAdaptiveRisk({ userinfo, req });

        adaptiveDecision = {
          risk_score: normalizeRiskScore(assess.risk_score),
          risk_label: assess.risk_label || "unknown",
          decision: assess.decision || "ALLOW",
          required_factor: assess.required_factor || "NONE",
          auth_path: assess.auth_path || "SSO_ONLY",
          policy_reason: assess.policy_reason || "unknown_policy_reason",
          completed: assess.decision === "ALLOW",
        };

        console.log("[portal] adaptive assess:", adaptiveDecision);
      } catch (e) {
        console.error("[portal] Adaptive assess error:", e);
        adaptiveDecision = {
          risk_score: null,
          risk_label: "unknown",
          decision: "ALLOW",
          required_factor: "NONE",
          auth_path: "SSO_ONLY",
          policy_reason: "assess_fallback_allow",
          completed: true,
        };
      }

      try {
        const factorAvailability = await getFactorAvailability(userinfo);
        adaptiveDecision = resolveAdaptiveDecision({
          baseDecision: adaptiveDecision,
          factorAvailability,
        });
        console.log("[portal] adaptive resolved:", adaptiveDecision);

        const portalSecurityState = await getPortalSecurityState(userinfo);
        const approvalActive = hasActiveBootstrapApproval(portalSecurityState);

        if (needsTrustedOnboarding({ factorAvailability })) {
          if (adaptiveDecision.decision === "ALLOW" || approvalActive) {
            adaptiveDecision = buildOnboardingDecision(
              adaptiveDecision,
              approvalActive ? "admin_approved" : "trusted"
            );
          } else {
            await ensurePendingAdminBootstrapRequest({
              userinfo,
              adaptiveDecision,
              req,
            });
            adaptiveDecision = buildAdminValidationRequiredDecision(
              adaptiveDecision
            );
          }
        }
      } catch (e) {
        console.error("[portal] Adaptive factor resolution error:", e);
      }

      try {
        await sendAppSessionStartedEvent({
          userinfo,
          req,
          sessionId: req.sessionID,
        });
      } catch (e) {
        console.error("[portal] Event collector error:", e);
      }
    }

    req.session.user = { ...userinfo, roles };
    req.session.tokens = {
      access_token: tokenSet.access_token,
      refresh_token: tokenSet.refresh_token,
      id_token: tokenSet.id_token,
      expires_at: tokenSet.expires_at,
    };

    if (pendingAccountAction?.type === "CONFIGURE_TOTP") {
      const factorAvailability = await getFactorAvailability(userinfo);
      req.session.pendingAccountAction = null;
      req.session.lastAccountAction = {
        type: "CONFIGURE_TOTP",
        status:
          typeof req.query.kc_action_status === "string"
            ? req.query.kc_action_status
            : factorAvailability.totp.configured === true
              ? "success"
              : "unknown",
        completed_at: new Date().toISOString(),
      };
      if (req.session.adaptiveAuth?.decision === "ONBOARDING_REQUIRED") {
        return res.redirect("/security/onboarding");
      }
      return res.redirect("/security/manage-keycloak-otp");
    }

    req.session.adaptiveAuth = adaptiveDecision;

    if (adaptiveDecision.decision === "ALLOW") {
      return res.redirect("/");
    }

    if (adaptiveDecision.decision === "ONBOARDING_REQUIRED") {
      return res.redirect("/security/onboarding");
    }

    if (adaptiveDecision.decision === "STEP_UP_TOTP") {
      req.session.pendingStepup = {
        type: "KEYCLOAK_TOTP",
        created_at: new Date().toISOString(),
      };

      return res.redirect("/start-stepup-totp");
    }

    if (adaptiveDecision.decision === "STEP_UP_BIOMETRIC") {
      return res.redirect("/adaptive-stepup");
    }

    if (adaptiveDecision.decision === "RECOVERY_REQUIRED") {
      return res.redirect("/adaptive-recovery");
    }

    if (adaptiveDecision.decision === "ADMIN_VALIDATION_REQUIRED") {
      return res.redirect("/adaptive-recovery");
    }

    if (adaptiveDecision.decision === "BLOCK_REVIEW") {
      return res.redirect("/adaptive-blocked");
    }

    return res.redirect("/");
  } catch (e) {
    console.error("Callback error full:", e);
    console.error("Callback error message:", e?.message || e);
    console.error(
      "Callback error response:",
      e?.response?.data || e?.response?.body || ""
    );
    res.status(500).send(`Callback error: ${e?.message || "unknown"}`);
  }
});

app.get("/callback-stepup-totp", async (req, res) => {
  try {
    if (!stepupTotpClient) {
      return res.status(503).send("Step-up OIDC client not ready, retry.");
    }

    const params = stepupTotpClient.callbackParams(req);
    const tokenSet = await stepupTotpClient.callback(
      STEPUP_TOTP_REDIRECT_URI,
      params
    );
    const userinfo = await stepupTotpClient.userinfo(tokenSet.access_token);
    const roles = extractRealmRoles(tokenSet.access_token);

    req.session.user = { ...userinfo, roles };
    req.session.stepupTokens = {
      access_token: tokenSet.access_token,
      refresh_token: tokenSet.refresh_token,
      id_token: tokenSet.id_token,
      expires_at: tokenSet.expires_at,
    };
    req.session.pendingStepup = null;
    req.session.pendingBiometricChallenge = null;
    const previousAdaptive = req.session.adaptiveAuth || {};
    req.session.adaptiveAuth = {
      ...previousAdaptive,
      requested_decision:
        previousAdaptive.requested_decision || previousAdaptive.decision || "STEP_UP_TOTP",
      requested_required_factor:
        previousAdaptive.requested_required_factor ||
        previousAdaptive.required_factor ||
        "KEYCLOAK_TOTP",
      requested_auth_path:
        previousAdaptive.requested_auth_path ||
        previousAdaptive.auth_path ||
        "KEYCLOAK_NATIVE_OTP",
      requested_policy_reason:
        previousAdaptive.requested_policy_reason ||
        previousAdaptive.policy_reason ||
        "step_up_totp_requested",
      decision: "ALLOW",
      required_factor: "NONE",
      auth_path: "MFA_COMPLETED",
      policy_reason: "adaptive_keycloak_totp_verified",
      completed: true,
      completed_at: new Date().toISOString(),
      completed_factor: "KEYCLOAK_TOTP",
    };

    return res.redirect("/");
  } catch (e) {
    console.error("[portal] callback-stepup-totp error:", e);
    return res.status(500).send(`Step-up callback error: ${e?.message || "unknown"}`);
  }
});

app.get("/start-stepup-totp", (req, res) => {
  if (!req.session.user) return res.redirect("/login");
  if (!stepupTotpClient) {
    return res.status(503).send("Step-up OIDC client not ready, retry.");
  }

  req.session.pendingStepup = {
    type: "KEYCLOAK_TOTP",
    created_at: new Date().toISOString(),
  };

  return res.redirect(buildStepupTotpUrl(req));
});

app.get("/security/manage-keycloak-otp", async (req, res) => {
  if (!req.session.user) return res.redirect("/login");

  const adaptive = req.session.adaptiveAuth || {};
  if (!canManageFactorsInSession(adaptive)) {
    return res.status(403).send(
      htmlPage(
        "Gestion OTP refusee",
        `
          <p>La gestion ou l'enrolement OTP n'est pas autorise pendant une session deja jugee risquee.</p>
          <p><b>Decision:</b> ${adaptive.decision || "n/a"}</p>
          <p><b>Policy reason:</b> ${adaptive.policy_reason || "n/a"}</p>
          <p><b>Risk score:</b> ${formatRiskScore(adaptive.risk_score)}</p>
          <p class="small">La logique retenue est volontairement stricte: on configure les facteurs uniquement depuis une session de confiance.</p>
          <a href="/" class="btn btn-secondary">Retour</a>
          <a href="/logout" class="btn btn-logout">Logout</a>
        `
      )
    );
  }

  const factorAvailability = await getFactorAvailability(req.session.user);
  const lastAccountAction = req.session.lastAccountAction || null;
  const sessionMode =
    adaptive.decision === "ONBOARDING_REQUIRED"
      ? "onboarding_limited"
      : adaptive.completed
        ? "trusted"
        : "not trusted";
  const actionMessage =
    lastAccountAction?.type === "CONFIGURE_TOTP"
      ? `<p><b>Derniere action:</b> ${lastAccountAction.status || "unknown"}</p>`
      : "";
  const recoveryCodesAction =
    factorAvailability.totp.configured === true
      ? `<a href="/security/recovery-codes" class="btn btn-secondary">Voir ou regenerer les recovery codes</a>`
      : "";

  return res.send(
    htmlPage(
      "Gestion OTP Keycloak",
      `
        <p>Le TOTP reste gere par Keycloak. Cette page sert a l'activer, le reconfigurer ou preparer la future recuperation admin.</p>
        <div class="info-box">
          <p><b>TOTP status:</b> ${factorStatusLabel(
            factorAvailability.totp.configured,
            "configured",
            "not configured"
          )}</p>
          <p><b>Adaptive session:</b> ${sessionMode}</p>
          <p class="small">Si le telephone est perdu, la politique actuelle bascule d'abord vers un autre facteur deja enregistre. Sinon l'acces passe en recovery controlee, en attendant le dashboard admin et les recovery codes.</p>
          ${actionMessage}
        </div>
        <a href="/security/manage-keycloak-otp/start" class="btn btn-success">Configurer ou reconfigurer OTP</a>
        ${recoveryCodesAction}
        <a href="/" class="btn btn-secondary">Retour</a>
        <a href="/logout" class="btn btn-logout">Logout</a>
      `
    )
  );
});

app.get("/security/manage-keycloak-otp/start", (req, res) => {
  if (!req.session.user) return res.redirect("/login");
  if (!portalClient) return res.status(503).send("OIDC client not ready, retry.");

  const adaptive = req.session.adaptiveAuth || {};
  if (!canManageFactorsInSession(adaptive)) {
    return res.redirect("/security/manage-keycloak-otp");
  }

  req.session.pendingAccountAction = {
    type: "CONFIGURE_TOTP",
    started_at: new Date().toISOString(),
  };

  return res.redirect(buildConfigureTotpActionUrl(req));
});

app.get("/security/onboarding", async (req, res) => {
  if (!req.session.user) return res.redirect("/login");

  const adaptive = req.session.adaptiveAuth || {};
  const factorAvailability = await getFactorAvailability(req.session.user);
  const securityState = await getPortalSecurityState(req.session.user);
  const totpConfigured = factorAvailability.totp.configured === true;
  const recoveryReady = hasRecoveryCodes(securityState);
  const onboardingCompleted = securityState.onboarding.completed === true;

  if (adaptive.decision !== "ONBOARDING_REQUIRED" && !canManageFactorsInSession(adaptive)) {
    return res.redirect("/");
  }

  const actions = [
    totpConfigured
      ? `<div class="badge">TOTP configured</div>`
      : `<a href="/security/manage-keycloak-otp/start" class="btn btn-success">Configurer TOTP maintenant</a>`,
    totpConfigured
      ? `<form method="post" action="/security/recovery-codes/generate"><button type="submit" class="btn btn-secondary">Generer ou regenerer les recovery codes</button></form>`
      : `<button class="btn btn-secondary" disabled>Generer les recovery codes apres le TOTP</button>`,
    `<a href="/security/setup-face" class="btn btn-secondary">Configurer la biometrie (optionnel)</a>`,
    totpConfigured
      ? `<form method="post" action="/security/onboarding/complete"><button type="submit" class="btn btn-success">Terminer l'onboarding securise</button></form>`
      : "",
    `<a href="/logout" class="btn btn-logout">Logout</a>`,
  ]
    .filter(Boolean)
    .join("");

  return res.send(
    htmlPage(
      "Onboarding securite",
      `
        <p>Ce compte doit d'abord finaliser son bootstrap MFA avant d'obtenir un acces applicatif complet.</p>
        <div class="info-box">
          <p><b>TOTP:</b> ${factorStatusLabel(
            factorAvailability.totp.configured,
            "configured",
            "not configured"
          )}</p>
          <p><b>Recovery codes:</b> ${recoveryReady ? "available" : "not generated"}</p>
          <p><b>Biometric:</b> ${factorStatusLabel(
            factorAvailability.biometric.enrolled,
            "configured",
            "not configured"
          )}</p>
          <p><b>Onboarding completed:</b> ${onboardingCompleted ? "yes" : "no"}</p>
          <p class="small">Choix retenu: le premier acces autorise uniquement la configuration des facteurs. Tant que le bootstrap n'est pas termine, l'application complete reste fermee.</p>
        </div>
        ${actions}
      `
    )
  );
});

app.post("/security/onboarding/complete", async (req, res) => {
  if (!req.session.user) return res.redirect("/login");

  const adaptive = req.session.adaptiveAuth || {};
  const factorAvailability = await getFactorAvailability(req.session.user);
  if (factorAvailability.totp.configured !== true) {
    return res.redirect("/security/onboarding");
  }

  await markOnboardingCompleted(
    req.session.user,
    await getPortalSecurityState(req.session.user),
    req.session.user.preferred_username || req.session.user.email || req.session.user.sub
  );

  req.session.adaptiveAuth = {
    ...adaptive,
    decision: "ALLOW",
    required_factor: "NONE",
    auth_path: "ONBOARDING_COMPLETED",
    policy_reason: "trusted_onboarding_completed",
    completed: true,
    completed_at: new Date().toISOString(),
    completed_factor: "TOTP_BASELINE",
  };

  return res.redirect("/");
});

app.post("/security/recovery-codes/generate", async (req, res) => {
  if (!req.session.user) return res.redirect("/login");

  const adaptive = req.session.adaptiveAuth || {};
  if (!canManageFactorsInSession(adaptive)) {
    return res.redirect("/");
  }

  const factorAvailability = await getFactorAvailability(req.session.user);
  if (factorAvailability.totp.configured !== true) {
    return res.redirect("/security/onboarding");
  }

  const generated = await issueRecoveryCodesForUser(
    req.session.user,
    req.session.user.preferred_username || req.session.user.email || req.session.user.sub
  );

  return res.send(
    htmlPage(
      "Recovery codes",
      `
        <p>Conserve ces codes hors ligne. Chaque code est a usage unique et permet de terminer un step-up TOTP si le telephone n'est pas disponible.</p>
        <div class="info-box">
          ${generated.plainCodes.map((code) => `<p><b>${code}</b></p>`).join("")}
          <p class="small">Les versions en clair ne seront plus affichees ensuite. Cote serveur, seuls les hash sont conserves.</p>
        </div>
        <a href="/security/onboarding" class="btn btn-success">Retour a l'onboarding</a>
        <a href="/" class="btn btn-secondary">Retour portail</a>
      `
    )
  );
});

app.get("/security/recovery-codes", async (req, res) => {
  if (!req.session.user) return res.redirect("/login");

  const adaptive = req.session.adaptiveAuth || {};
  if (!canManageFactorsInSession(adaptive)) {
    return res.status(403).send(
      htmlPage(
        "Recovery codes refuses",
        `
          <p>Les recovery codes ne sont consultables ou regenerables que depuis une session de confiance.</p>
          <p><b>Decision:</b> ${adaptive.decision || "n/a"}</p>
          <a href="/" class="btn btn-secondary">Retour</a>
          <a href="/logout" class="btn btn-logout">Logout</a>
        `
      )
    );
  }

  const factorAvailability = await getFactorAvailability(req.session.user);
  if (factorAvailability.totp.configured !== true) {
    return res.redirect("/security/manage-keycloak-otp");
  }

  const securityState = await getPortalSecurityState(req.session.user);
  const remaining = securityState.recovery_codes.remaining || 0;
  const generatedAt = securityState.recovery_codes.generated_at || "n/a";
  const returnPath =
    adaptive.decision === "ONBOARDING_REQUIRED" ? "/security/onboarding" : "/";

  return res.send(
    htmlPage(
      "Recovery codes",
      `
        <p>Ces codes servent uniquement de secours pour un step-up TOTP quand le telephone n'est pas disponible.</p>
        <div class="info-box">
          <p><b>TOTP:</b> configured</p>
          <p><b>Codes disponibles:</b> ${remaining}</p>
          <p><b>Derniere generation:</b> ${generatedAt}</p>
          <p class="small">Les codes sont a usage unique. Seuls les hash sont conserves cote serveur.</p>
        </div>
        <form method="post" action="/security/recovery-codes/generate">
          <button type="submit" class="btn btn-success">${
            remaining > 0 ? "Regenerer les recovery codes" : "Generer les recovery codes"
          }</button>
        </form>
        <a href="${returnPath}" class="btn btn-secondary">Retour</a>
        <a href="/logout" class="btn btn-logout">Logout</a>
      `
    )
  );
});

app.get("/adaptive-recovery-code", async (req, res) => {
  if (!req.session.user) return res.redirect("/login");

  const adaptive = req.session.adaptiveAuth || {};
  const securityState = await getPortalSecurityState(req.session.user);
  const allowedForRecoveryCode =
    adaptive.requested_decision === "STEP_UP_TOTP" ||
    adaptive.decision === "STEP_UP_TOTP";

  if (!allowedForRecoveryCode || !hasRecoveryCodes(securityState)) {
    return res.redirect("/adaptive-recovery");
  }

  return res.send(
    htmlPage(
      "Recovery code",
      `
        <p>Entre un recovery code a usage unique pour terminer ce step-up sans telephone.</p>
        <p><b>Codes restants:</b> ${securityState.recovery_codes.remaining}</p>
        <form method="post" action="/adaptive-recovery-code/verify">
          <input type="text" name="recovery_code" placeholder="ABCD-EFGH" style="width:100%;padding:12px;margin-bottom:12px;box-sizing:border-box;" />
          <button type="submit" class="btn btn-success">Verifier le recovery code</button>
        </form>
        <p class="small">Ce fallback n'est accepte que pour un step-up de niveau TOTP/moderate.</p>
        <a href="/adaptive-stepup" class="btn btn-secondary">Retour</a>
        <a href="/logout" class="btn btn-logout">Logout</a>
      `
    )
  );
});

app.post("/adaptive-recovery-code/verify", async (req, res) => {
  if (!req.session.user) return res.redirect("/login");

  const adaptive = req.session.adaptiveAuth || {};
  const allowedForRecoveryCode =
    adaptive.requested_decision === "STEP_UP_TOTP" ||
    adaptive.decision === "STEP_UP_TOTP";

  if (!allowedForRecoveryCode) {
    return res.redirect("/adaptive-recovery");
  }

  const recoveryCode = String(req.body.recovery_code || "").trim();
  const result = await consumeRecoveryCodeForUser(req.session.user, recoveryCode);
  if (!result.matched) {
    return res.status(400).send(
      htmlPage(
        "Recovery code invalide",
        `
          <p>Le code fourni est invalide ou deja utilise.</p>
          <a href="/adaptive-recovery-code" class="btn btn-secondary">Reessayer</a>
          <a href="/logout" class="btn btn-logout">Logout</a>
        `
      )
    );
  }

  req.session.adaptiveAuth = {
    ...adaptive,
    decision: "ALLOW",
    required_factor: "NONE",
    auth_path: "MFA_COMPLETED",
    policy_reason: "adaptive_recovery_code_verified",
    completed: true,
    completed_at: new Date().toISOString(),
    completed_factor: "RECOVERY_CODE",
  };

  return res.redirect("/");
});

app.get("/security/setup-face", async (req, res) => {
  if (!req.session.user) return res.redirect("/login");

  const adaptive = req.session.adaptiveAuth || {};
  if (!canManageFactorsInSession(adaptive)) {
    return res.status(403).send(
      htmlPage(
        "Configuration refusée",
        `
          <p>L'enrôlement biométrique n'est pas autorisé pendant une session jugée suspecte.</p>
          <p><b>Policy reason:</b> ${adaptive.policy_reason || "n/a"}</p>
          <p><b>Risk score:</b> ${formatRiskScore(adaptive.risk_score)}</p>
          <p class="small">Reconnecte-toi dans un contexte normal, puis configure ton facteur biométrique.</p>
          <a href="/" class="btn btn-secondary">Retour</a>
          <a href="/logout" class="btn btn-logout">Logout</a>
        `
      )
    );
  }

  return res.send(
    renderBiometricCapturePage({
      title: "Configuration biométrique",
      message:
        "Capture une image de ton visage pour enrôler le facteur biométrique utilisé lors des accès à haut risque.",
      action: "/security/setup-face/capture",
      buttonLabel: "Capturer et enrôler le visage",
      activeLiveness: false,
      infoHtml: `
        <p><b>Utilisateur:</b> ${
          req.session.user.preferred_username || req.session.user.email || "user"
        }</p>
        <p class="small">Cette opération crée le profil de référence côté service biométrique.</p>
      `,
    })
  );
});

app.post("/security/setup-face/capture", async (req, res) => {
  if (!req.session.user) return res.redirect("/login");

  const imageBase64 = String(req.body.image_base64 || "").trim();
  if (!imageBase64) {
    return res.status(400).send(
      renderBiometricCapturePage({
        title: "Configuration biométrique",
        message: "La capture webcam est requise pour enrôler le profil biométrique.",
        action: "/security/setup-face/capture",
        buttonLabel: "Capturer et enrôler le visage",
        activeLiveness: false,
        errorMessage: "Aucune image n’a été transmise.",
      })
    );
  }

  try {
    const result = await enrollBiometricProfile(req.session.user, imageBase64);

    return res.send(
      htmlPage(
        "Biométrie configurée",
        `
          <p>Le profil biométrique a été enregistré avec succès.</p>
          <p><b>Quality score:</b> ${result.quality_score ?? "n/a"}</p>
          <p><b>Face confidence:</b> ${result.face_confidence ?? "n/a"}</p>
          <a href="/" class="btn btn-success">Retour à l’accueil</a>
          <a href="/logout" class="btn btn-logout">Logout</a>
        `
      )
    );
  } catch (e) {
    console.error("[portal] biometric enroll error:", e);
    return res.status(400).send(
      renderBiometricCapturePage({
        title: "Configuration biométrique",
        message: "La capture a échoué. Vérifie la lumière, le cadrage et réessaie.",
        action: "/security/setup-face/capture",
        buttonLabel: "Capturer et enrôler le visage",
        activeLiveness: false,
        errorMessage: e?.message || "Erreur d’enrôlement biométrique.",
      })
    );
  }
});

app.get("/adaptive-switch-to-biometric", async (req, res) => {
  if (!req.session.user) return res.redirect("/login");

  const adaptive = req.session.adaptiveAuth || {};
  const requestedDecision = adaptive.requested_decision || adaptive.decision;
  if (requestedDecision !== "STEP_UP_TOTP") {
    return res.redirect("/adaptive-stepup");
  }

  const factorAvailability = await getFactorAvailability(req.session.user);

  if (factorAvailability.biometric.enrolled !== true) {
    req.session.adaptiveAuth = {
      ...adaptive,
      decision: "RECOVERY_REQUIRED",
      required_factor: "ACCOUNT_RECOVERY",
      auth_path: "RECOVERY_PENDING",
      policy_reason: "totp_unavailable_biometric_not_registered",
      resolution_status: "recovery_required",
      resolution_reason: "user_requested_biometric_fallback_but_no_biometric_profile_exists",
      recovery_reason: "no_registered_biometric_fallback",
      recovery_channel: "ADMIN_RESET_OR_FUTURE_RECOVERY_CODE",
      factor_availability: factorAvailability,
      completed: false,
    };
    return res.redirect("/adaptive-recovery");
  }

  req.session.pendingStepup = null;
  req.session.adaptiveAuth = {
    ...adaptive,
    requested_decision: adaptive.requested_decision || adaptive.decision,
    requested_required_factor:
      adaptive.requested_required_factor || adaptive.required_factor || "TOTP_OR_WEBAUTHN",
    requested_auth_path:
      adaptive.requested_auth_path || adaptive.auth_path || "SECOND_FACTOR",
    requested_policy_reason:
      adaptive.requested_policy_reason || adaptive.policy_reason || "step_up_totp",
    decision: "STEP_UP_BIOMETRIC",
    required_factor: "FACE_RECOGNITION",
    auth_path: "BIOMETRIC_FACTOR",
    policy_reason: "totp_recovery_biometric_fallback",
    resolution_status: "fallback_biometric",
    resolution_reason:
      "user_reported_totp_unavailable_and_switched_to_registered_biometric",
    factor_availability: factorAvailability,
    completed: false,
  };

  return res.redirect("/adaptive-stepup");
});

app.get("/adaptive-recovery", async (req, res) => {
  if (!req.session.user) return res.redirect("/login");

  const adaptive = req.session.adaptiveAuth || {};
  const factorAvailability = await getFactorAvailability(req.session.user);
  const securityState = await getPortalSecurityState(req.session.user);
  req.session.adaptiveAuth = {
    ...adaptive,
    factor_availability: factorAvailability,
  };

  const username =
    req.session.user.preferred_username || req.session.user.email || "user";

  if (adaptive.decision === "ADMIN_VALIDATION_REQUIRED") {
    if (hasActiveBootstrapApproval(securityState)) {
      req.session.adaptiveAuth = buildOnboardingDecision(
        req.session.adaptiveAuth || adaptive,
        "admin_approved"
      );
      return res.redirect("/security/onboarding");
    }

    const adminStatus = securityState.admin_bootstrap.status || "pending";
    const adminStatusMessage =
      adminStatus === "rejected"
        ? "La validation admin a ete refusee pour cette tentative. Il faut repasser par un login normal ou attendre une nouvelle approbation explicite."
        : adminStatus === "approved"
          ? "Une approbation a existe, mais sa fenetre a expire avant le bootstrap. Il faut demander une nouvelle validation."
          : "Une validation admin est requise avant d'autoriser un onboarding MFA limite pour ce compte.";
    const rejectionReason = securityState.admin_bootstrap.rejection_reason
      ? `<p><b>Motif du refus:</b> ${securityState.admin_bootstrap.rejection_reason}</p>`
      : "";

    return res.status(403).send(
      htmlPage(
        "Validation admin requise",
        `
          <p>Le premier bootstrap MFA de ce compte a ete juge trop sensible pour etre autorise automatiquement.</p>
          <div class="info-box">
            <p><b>Utilisateur:</b> ${username}</p>
            <p><b>Statut admin:</b> ${adminStatus}</p>
            <p><b>Decision demandee:</b> ${adaptive.requested_decision || adaptive.decision || "n/a"}</p>
            <p><b>Policy reason:</b> ${adaptive.policy_reason || "n/a"}</p>
            <p><b>Risk score:</b> ${formatRiskScore(adaptive.risk_score)}</p>
            <p><b>Demande creee le:</b> ${securityState.admin_bootstrap.requested_at || "n/a"}</p>
            ${rejectionReason}
            <p class="small">${adminStatusMessage}</p>
            <p class="small">Choix retenu: un premier enrollement MFA dans une session risquee doit etre valide par un administrateur plutot que laisse a l'utilisateur seul.</p>
          </div>
          <a href="/adaptive-recovery" class="btn btn-secondary">Reverifier maintenant</a>
          <a href="/logout" class="btn btn-logout">Logout</a>
        `
      )
    );
  }

  const canUseBiometricFallback =
    adaptive.requested_decision === "STEP_UP_TOTP" &&
    factorAvailability.biometric.enrolled === true;
  const canUseRecoveryCode =
    (adaptive.requested_decision === "STEP_UP_TOTP" ||
      adaptive.decision === "STEP_UP_TOTP") &&
    hasRecoveryCodes(securityState);

  const recoverySpecificMessage =
    adaptive.recovery_reason === "biometric_not_enrolled_for_high_risk"
      ? "Le risque est eleve. La politique retenue n'autorise pas de degrader vers TOTP quand la biometrie requise n'a jamais ete enregistree."
      : canUseRecoveryCode
        ? "Le telephone n'est pas disponible, mais un recovery code a usage unique peut encore terminer ce step-up TOTP."
        : "Aucun facteur deja enregistre ne permet de terminer ce step-up dans de bonnes conditions.";

  const recoveryActions = [
    canUseBiometricFallback
      ? `<a href="/adaptive-switch-to-biometric" class="btn btn-success">Utiliser la biometrie deja configuree</a>`
      : "",
    canUseRecoveryCode
      ? `<a href="/adaptive-recovery-code" class="btn btn-secondary">Utiliser un recovery code</a>`
      : "",
    `<a href="/logout" class="btn btn-logout">Logout</a>`,
  ]
    .filter(Boolean)
    .join("");

  return res.status(403).send(
    htmlPage(
      "Recuperation requise",
      `
        <p>La session a ete authentifiee, mais aucun facteur exploitable n'est disponible pour terminer le controle adaptatif.</p>
        <div class="info-box">
          <p><b>Utilisateur:</b> ${username}</p>
          <p><b>Decision demandee:</b> ${adaptive.requested_decision || adaptive.decision || "n/a"}</p>
          <p><b>Decision effective:</b> ${adaptive.decision || "RECOVERY_REQUIRED"}</p>
          <p><b>Policy reason:</b> ${adaptive.policy_reason || "n/a"}</p>
          <p><b>Resolution reason:</b> ${adaptive.resolution_reason || "n/a"}</p>
          <p><b>Risk score:</b> ${formatRiskScore(adaptive.risk_score)}</p>
          <p><b>TOTP:</b> ${factorStatusLabel(
            factorAvailability.totp.configured,
            "configured",
            "not configured"
          )}</p>
          <p><b>Biometric:</b> ${factorStatusLabel(
            factorAvailability.biometric.enrolled,
            "configured",
            "not configured"
          )}</p>
          <p><b>Recovery codes:</b> ${
            hasRecoveryCodes(securityState)
              ? `${securityState.recovery_codes.remaining} remaining`
              : "not available"
          }</p>
          <p><b>Recovery channel:</b> ${adaptive.recovery_channel || "future_admin_dashboard"}</p>
          <p class="small">${recoverySpecificMessage}</p>
          <p class="small">Choix defendable retenu: on n'enrole jamais un nouveau facteur au milieu d'une session deja jugee suspecte. Les futures evolutions seront un reset admin et des recovery codes a usage unique.</p>
        </div>
        ${recoveryActions}
      `
    )
  );
});

app.get("/adaptive-stepup", async (req, res) => {
  if (!req.session.user) return res.redirect("/login");

  const adaptive = req.session.adaptiveAuth || {};
  const factorAvailability = await getFactorAvailability(req.session.user);
  const securityState = await getPortalSecurityState(req.session.user);
  const username =
    req.session.user.preferred_username || req.session.user.email || "user";

  if (adaptive.completed === true || adaptive.decision === "ALLOW") {
    return res.redirect("/");
  }

  if (adaptive.decision === "RECOVERY_REQUIRED") {
    return res.redirect("/adaptive-recovery");
  }

  if (adaptive.decision === "STEP_UP_TOTP") {
    const recoveryCodeAction = hasRecoveryCodes(securityState)
      ? `<a href="/adaptive-recovery-code" class="btn btn-secondary">Utiliser un recovery code</a>`
      : "";
    const fallbackActions = factorAvailability.biometric.enrolled === true
      ? `<a href="/adaptive-switch-to-biometric" class="btn btn-secondary">Je n'ai pas mon telephone, utiliser la biometrie</a>`
      : `<a href="/adaptive-recovery" class="btn btn-secondary">Je n'ai pas acces a mon telephone</a>`;

    return res.send(
      htmlPage(
        "Redirection vers Keycloak OTP",
        `
          <p>Le niveau de risque est modere. La verification OTP native Keycloak est requise.</p>
          <p><b>Policy reason:</b> ${adaptive.policy_reason || "n/a"}</p>
          <p><b>Risk score:</b> ${formatRiskScore(adaptive.risk_score)}</p>
          <p><b>TOTP status:</b> ${factorStatusLabel(
            factorAvailability.totp.configured,
            "configured",
            "not configured"
          )}</p>
          <p><b>Recovery codes:</b> ${
            hasRecoveryCodes(securityState)
              ? `${securityState.recovery_codes.remaining} remaining`
              : "not available"
          }</p>
          <p><b>Biometric fallback:</b> ${factorStatusLabel(
            factorAvailability.biometric.enrolled,
            "configured",
            "not configured"
          )}</p>
          <p class="small">Clique ci-dessous pour poursuivre la verification OTP geree par Keycloak. Si le telephone n'est pas disponible, on bascule vers un autre facteur deja configure ou vers la recovery.</p>
          <a href="/start-stepup-totp" class="btn btn-success">Continuer avec le code OTP Keycloak</a>
          ${recoveryCodeAction}
          ${fallbackActions}
          <a href="/logout" class="btn btn-logout">Logout</a>
        `
      )
    );
  }

  if (false && adaptive.decision === "STEP_UP_TOTP") {
    return res.send(
      htmlPage(
        "Redirection vers Keycloak OTP",
        `
          <p>Le niveau de risque est modéré. La vérification OTP native Keycloak est requise.</p>
          <p><b>Policy reason:</b> ${adaptive.policy_reason || "n/a"}</p>
          <p><b>Risk score:</b> ${formatRiskScore(adaptive.risk_score)}</p>
          <p class="small">Clique ci-dessous pour poursuivre la vérification OTP gérée par Keycloak.</p>
          <a href="/start-stepup-totp" class="btn btn-success">Continuer avec le code OTP Keycloak</a>
          <a href="/logout" class="btn btn-logout">Logout</a>
        `
      )
    );
  }

  if (adaptive.decision === "STEP_UP_BIOMETRIC") {
    if (factorAvailability.biometric.enrolled === false) {
      req.session.adaptiveAuth = {
        ...adaptive,
        factor_availability: factorAvailability,
        decision: "RECOVERY_REQUIRED",
        required_factor: "ACCOUNT_RECOVERY",
        auth_path: "RECOVERY_PENDING",
        policy_reason: "high_risk_requires_registered_biometric",
        resolution_status: "recovery_required",
        resolution_reason:
          "high_risk_does_not_allow_biometric_enrollment_inside_the_same_risky_session",
        recovery_reason: "biometric_not_enrolled_for_high_risk",
        recovery_channel: "TRUSTED_SESSION_ENROLLMENT_OR_ADMIN_RESET",
        completed: false,
      };
      return res.redirect("/adaptive-recovery");
    }
  }

  if (adaptive.decision === "STEP_UP_BIOMETRIC") {
    const challengeType = issueBiometricChallenge(req);
    let biometricStatus = { enrolled: false };
    try {
      biometricStatus = await getBiometricProfileStatus(req.session.user);
    } catch (e) {
      console.error("[portal] biometric status error:", e?.message || e);
    }

    if (!biometricStatus.enrolled) {
      return res.status(403).send(
        htmlPage(
          "Biométrie non initialisée",
          `
            <p>Le niveau de risque est élevé et une vérification faciale est requise.</p>
            <div class="info-box">
              <p><b>Utilisateur:</b> ${username}</p>
              <p><b>Problème:</b> aucun profil biométrique n’est encore enrôlé.</p>
              <p><b>Risk label:</b> ${adaptive.risk_label || "high"}</p>
              <p><b>Policy reason:</b> ${adaptive.policy_reason || "n/a"}</p>
              <p><b>Risk score:</b> ${formatRiskScore(adaptive.risk_score)}</p>
              <p class="small">Par sécurité, l’enrôlement n’est pas autorisé pendant une session déjà jugée à haut risque.</p>
            </div>
            <a href="/logout" class="btn btn-logout">Logout</a>
          `
        )
      );
    }

    return res.send(
      renderBiometricCapturePage({
        title: "Étape biométrique requise",
        message:
          "Le niveau de risque est élevé. Réalise 2 captures : une frontale, puis une avec légère rotation de tête.",
        action: "/adaptive-biometric-verify",
        buttonLabel: "Capturer l’étape 1",
        activeLiveness: true,
        challengeType,
        infoHtml: `
          <div class="badge">${adaptive.decision || "STEP_UP_BIOMETRIC"}</div>
          <p><b>Utilisateur:</b> ${username}</p>
          <p><b>Risk label:</b> ${adaptive.risk_label || "unknown"}</p>
          <p><b>Required factor:</b> ${adaptive.required_factor || "UNKNOWN"}</p>
          <p><b>Policy reason:</b> ${adaptive.policy_reason || "n/a"}</p>
          <p><b>Risk score:</b> ${formatRiskScore(adaptive.risk_score)}</p>
        `,
      })
    );
  }

  return res.send(
    htmlPage(
      "Vérification supplémentaire requise",
      `
        <p>Votre tentative d’accès nécessite une vérification supplémentaire avant l’ouverture complète de la session.</p>
        <a href="/logout" class="btn btn-logout">Logout</a>
      `
    )
  );
});

app.post("/adaptive-biometric-verify", async (req, res) => {
  if (!req.session.user) return res.redirect("/login");

  const primaryImageBase64 = String(req.body.image_base64 || "").trim();
  const challengeImageBase64 = String(req.body.challenge_image_base64 || "").trim();
  const expectedChallengeType = req.session?.pendingBiometricChallenge?.type || "";
  const challengeType = String(
    req.body.challenge_type || expectedChallengeType || "turn_left"
  ).trim();
  const adaptive = req.session.adaptiveAuth || {};

  if (expectedChallengeType && challengeType !== expectedChallengeType) {
    const nextChallengeType = issueBiometricChallenge(req);
    return res.status(400).send(
      renderBiometricCapturePage({
        title: "Étape biométrique requise",
        message:
          "Le challenge biométrique a expiré ou ne correspond pas à la demande courante.",
        action: "/adaptive-biometric-verify",
        buttonLabel: "Capturer l’étape 1",
        activeLiveness: true,
        challengeType: nextChallengeType,
        infoHtml: `
          <p><b>Risk label:</b> ${adaptive.risk_label || "unknown"}</p>
          <p><b>Policy reason:</b> ${adaptive.policy_reason || "n/a"}</p>
          <p><b>Risk score:</b> ${formatRiskScore(adaptive.risk_score)}</p>
        `,
        errorMessage: "Le challenge doit être relancé avec une nouvelle consigne.",
      })
    );
  }

  if (!primaryImageBase64 || !challengeImageBase64) {
    const nextChallengeType = issueBiometricChallenge(req);
    return res.status(400).send(
      renderBiometricCapturePage({
        title: "Étape biométrique requise",
        message:
          "Deux captures sont requises pour finaliser la vérification biométrique active.",
        action: "/adaptive-biometric-verify",
        buttonLabel: "Capturer l’étape 1",
        activeLiveness: true,
        challengeType: nextChallengeType,
        infoHtml: `
          <p><b>Risk label:</b> ${adaptive.risk_label || "unknown"}</p>
          <p><b>Policy reason:</b> ${adaptive.policy_reason || "n/a"}</p>
          <p><b>Risk score:</b> ${formatRiskScore(adaptive.risk_score)}</p>
        `,
        errorMessage: "Les deux captures sont obligatoires.",
      })
    );
  }

  try {
    const result = await verifyBiometricProfile(
      req.session.user,
      primaryImageBase64,
      challengeImageBase64,
      challengeType
    );

    if (result.verified !== true) {
      const nextChallengeType = issueBiometricChallenge(req);
      if (!req.session.adaptiveAuth?.biometric_attempts) {
        req.session.adaptiveAuth.biometric_attempts = 0;
      }
      req.session.adaptiveAuth.biometric_attempts += 1;

      return res.status(403).send(
        renderBiometricCapturePage({
          title: "Étape biométrique requise",
          message:
            "La vérification biométrique a échoué. Refais les 2 captures correctement.",
          action: "/adaptive-biometric-verify",
          buttonLabel: "Capturer l’étape 1",
          activeLiveness: true,
          challengeType: nextChallengeType,
          infoHtml: `
            <p><b>Similarity primary:</b> ${result.similarity_primary ?? "n/a"}</p>
            <p><b>Similarity challenge:</b> ${result.similarity_challenge ?? "n/a"}</p>
            <p><b>Cross-capture similarity:</b> ${result.cross_capture_similarity ?? "n/a"}</p>
            <p><b>Liveness passed:</b> ${result.liveness_passed ? "yes" : "no"}</p>
            <p><b>Liveness reason:</b> ${result.liveness_reason || "n/a"}</p>
            <p><b>Yaw primary:</b> ${result.yaw_primary ?? "n/a"}</p>
            <p><b>Yaw challenge:</b> ${result.yaw_challenge ?? "n/a"}</p>
            <p><b>Roll delta:</b> ${result.roll_delta ?? "n/a"}</p>
            <p><b>Center shift:</b> ${result.center_shift ?? "n/a"}</p>
            <p><b>Scale delta:</b> ${result.scale_delta ?? "n/a"}</p>
            <p><b>Motion delta:</b> ${result.motion_delta ?? "n/a"}</p>
            <p><b>Detected faces primary:</b> ${result.quality_checks_primary?.detected_faces ?? "n/a"}</p>
            <p><b>Detected faces challenge:</b> ${result.quality_checks_challenge?.detected_faces ?? "n/a"}</p>
            <p><b>Attempts:</b> ${req.session.adaptiveAuth.biometric_attempts}</p>
          `,
          errorMessage: result.reason || "Visage non validé.",
        })
      );
    }

    const previousAdaptive = req.session.adaptiveAuth || {};
    req.session.adaptiveAuth = {
      ...previousAdaptive,
      requested_decision:
        previousAdaptive.requested_decision ||
        previousAdaptive.decision ||
        "STEP_UP_BIOMETRIC",
      requested_required_factor:
        previousAdaptive.requested_required_factor ||
        previousAdaptive.required_factor ||
        "FACE_RECOGNITION",
      requested_auth_path:
        previousAdaptive.requested_auth_path ||
        previousAdaptive.auth_path ||
        "BIOMETRIC_FACTOR",
      requested_policy_reason:
        previousAdaptive.requested_policy_reason ||
        previousAdaptive.policy_reason ||
        "step_up_biometric_requested",
      decision: "ALLOW",
      required_factor: "NONE",
      auth_path: "MFA_COMPLETED",
      policy_reason: "adaptive_biometric_verified",
      completed: true,
      completed_at: new Date().toISOString(),
      completed_factor: "FACE_RECOGNITION",
      biometric_similarity_primary: result.similarity_primary,
      biometric_similarity_challenge: result.similarity_challenge,
      biometric_cross_capture_similarity: result.cross_capture_similarity,
      biometric_threshold: result.threshold,
      biometric_reason: result.reason || "face_verified",
      liveness_passed: result.liveness_passed,
      liveness_reason: result.liveness_reason,
      challenge_type: result.challenge_type,
      yaw_primary: result.yaw_primary,
      yaw_challenge: result.yaw_challenge,
      roll_primary: result.roll_primary,
      roll_challenge: result.roll_challenge,
      roll_delta: result.roll_delta,
      center_shift: result.center_shift,
      scale_delta: result.scale_delta,
      motion_delta: result.motion_delta,
    };

    return res.redirect("/");
  } catch (e) {
    const nextChallengeType = issueBiometricChallenge(req);
    console.error("[portal] biometric verify error:", e);
    return res.status(400).send(
      renderBiometricCapturePage({
        title: "Étape biométrique requise",
        message:
          "La vérification biométrique a échoué. Reprends les 2 captures.",
        action: "/adaptive-biometric-verify",
        buttonLabel: "Capturer l’étape 1",
        activeLiveness: true,
        challengeType: nextChallengeType,
        infoHtml: `
          <p><b>Risk label:</b> ${adaptive.risk_label || "unknown"}</p>
          <p><b>Policy reason:</b> ${adaptive.policy_reason || "n/a"}</p>
          <p><b>Risk score:</b> ${formatRiskScore(adaptive.risk_score)}</p>
        `,
        errorMessage: e?.message || "Erreur de vérification biométrique.",
      })
    );
  }
});

app.get("/adaptive-blocked", (req, res) => {
  if (!req.session.user) return res.redirect("/login");

  const adaptive = req.session.adaptiveAuth || {};

  return renderAdaptiveDecision(
    res,
    "Accès temporairement bloqué",
    "Le niveau de risque a été jugé critique. L’ouverture de session applicative est suspendue.",
    `
      <div class="badge">${adaptive.decision || "BLOCK_REVIEW"}</div>
      <p><b>Risk label:</b> ${adaptive.risk_label || "critical"}</p>
      <p><b>Required factor:</b> ${adaptive.required_factor || "ADMIN_REVIEW"}</p>
      <p><b>Policy reason:</b> ${adaptive.policy_reason || "n/a"}</p>
      <p><b>Risk score:</b> ${formatRiskScore(adaptive.risk_score)}</p>
      <p class="small">Dans la version finale, cette étape pourra être reliée à une validation administrative ou à une politique de sécurité plus stricte.</p>
    `,
    `<a href="/logout" class="btn btn-logout">Logout</a>`
  );
});

app.get("/protected", (req, res) => {
  if (!req.session.user) return res.redirect("/login");

  const username =
    req.session.user.preferred_username || req.session.user.email || "user";

  res.send(
    htmlPage(
      "Portal - Protected",
      `
        <p>Bienvenue <b>${username}</b></p>
        <p>Cette page n’est accessible qu’après validation du contrôle adaptatif.</p>
        <a href="/" class="btn btn-secondary">Home</a>
        <a href="/logout" class="btn btn-logout">Logout</a>
      `
    )
  );
});

app.get("/logout", (req, res) => {
  const logoutContext = selectLogoutContext(req);

  req.session.destroy((err) => {
    if (err) {
      console.error("[portal] Session destroy error:", err);
    }

    res.clearCookie(SESSION_COOKIE_NAME, SESSION_COOKIE_OPTIONS);

    res.redirect(buildLogoutUrl(logoutContext));
  });
});

app.post("/change-password", async (req, res) => {
  const { password } = req.body || {};

  if (!password || typeof password !== "string" || password.trim().length === 0) {
    return res.status(400).json({ error: "Le mot de passe est requis." });
  }

  try {
    const check = await fetch(CHECK_PASSWORD_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password }),
    });

    if (!check.ok) {
      const text = await check.text();
      console.error("[Portal] check-password returned", check.status, text);
      return res.status(502).json({ error: "Erreur de validation du mot de passe." });
    }

    const result = await check.json();

    if (result.pwned) {
      return res.status(400).json({
        error: `Ce mot de passe a été exposé ${result.exposure_count} fois. Choisissez-en un autre.`,
      });
    }

    return res.json({ ok: true, message: "Mot de passe valide." });
  } catch (err) {
    console.error("[Portal] /change-password error", err);
    return res.status(500).json({
      error: "Impossible de vérifier le mot de passe pour le moment.",
    });
  }
});

app.listen(PORT, () => console.log(`Portal running on ${APP_BASE_URL}`));
