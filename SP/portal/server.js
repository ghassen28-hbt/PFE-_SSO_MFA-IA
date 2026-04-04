const express = require("express");
const session = require("express-session");
const dotenv = require("dotenv");
const { Issuer } = require("openid-client");

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

function buildFreshLoginUrl(oidcClient, extraParams = {}) {
  return oidcClient.authorizationUrl({
    scope: "openid profile email",
    prompt: "login",
    max_age: 0,
    ...extraParams,
  });
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
    "/logout",
    "/adaptive-stepup",
    "/adaptive-blocked",
    "/adaptive-biometric-verify",
    "/security/setup-face",
    "/security/setup-face/capture",
    "/security/manage-keycloak-otp",
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
    if (decision === "STEP_UP_TOTP" || decision === "STEP_UP_BIOMETRIC") {
      return res.redirect("/adaptive-stepup");
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

  let biometricStatus = { enrolled: false };
  try {
    biometricStatus = await getBiometricProfileStatus(req.session.user);
  } catch (e) {
    console.error("[portal] biometric status error:", e?.message || e);
  }

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
        ${totpInfo}
        ${biometricInfo}
        
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

    const params = portalClient.callbackParams(req);
    const tokenSet = await portalClient.callback(REDIRECT_URI, params);
    const userinfo = await portalClient.userinfo(tokenSet.access_token);

    const roles = extractRealmRoles(tokenSet.access_token);

    let adaptiveDecision = {
      risk_score: null,
      risk_label: "unknown",
      decision: "ALLOW",
      required_factor: "NONE",
      auth_path: "SSO_ONLY",
      policy_reason: "assess_fallback_allow",
      completed: true,
    };

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
      await sendAppSessionStartedEvent({
        userinfo,
        req,
        sessionId: req.sessionID,
      });
    } catch (e) {
      console.error("[portal] Event collector error:", e);
    }

    req.session.user = { ...userinfo, roles };
    req.session.tokens = {
      access_token: tokenSet.access_token,
      refresh_token: tokenSet.refresh_token,
      id_token: tokenSet.id_token,
      expires_at: tokenSet.expires_at,
    };
    req.session.adaptiveAuth = adaptiveDecision;

    if (adaptiveDecision.decision === "ALLOW") {
      return res.redirect("/");
    }

    if (adaptiveDecision.decision === "STEP_UP_TOTP") {
      req.session.pendingStepup = {
        type: "KEYCLOAK_TOTP",
        created_at: new Date().toISOString(),
      };

      return res.redirect(
        buildFreshLoginUrl(stepupTotpClient)
      );
    }

    if (adaptiveDecision.decision === "STEP_UP_BIOMETRIC") {
      return res.redirect("/adaptive-stepup");
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
    req.session.adaptiveAuth = {
      ...(req.session.adaptiveAuth || {}),
      decision: "STEP_UP_TOTP",
      required_factor: "KEYCLOAK_TOTP",
      auth_path: "KEYCLOAK_NATIVE_OTP",
      policy_reason: "adaptive_keycloak_totp_verified",
      completed: true,
      completed_at: new Date().toISOString(),
    };

    return res.redirect("/");
  } catch (e) {
    console.error("[portal] callback-stepup-totp error:", e);
    return res.status(500).send(`Step-up callback error: ${e?.message || "unknown"}`);
  }
});

app.get("/security/setup-face", async (req, res) => {
  if (!req.session.user) return res.redirect("/login");

  const adaptive = req.session.adaptiveAuth || {};
  if (adaptive.completed === false && adaptive.decision !== "ALLOW") {
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

app.get("/adaptive-stepup", async (req, res) => {
  if (!req.session.user) return res.redirect("/login");

  const adaptive = req.session.adaptiveAuth || {};
  const username =
    req.session.user.preferred_username || req.session.user.email || "user";

  if (adaptive.completed === true || adaptive.decision === "ALLOW") {
    return res.redirect("/");
  }

  if (adaptive.decision === "STEP_UP_TOTP") {
    return res.send(
      htmlPage(
        "Redirection vers Keycloak OTP",
        `
          <p>Le niveau de risque est modéré. La vérification OTP native Keycloak est requise.</p>
          <p><b>Policy reason:</b> ${adaptive.policy_reason || "n/a"}</p>
          <p><b>Risk score:</b> ${formatRiskScore(adaptive.risk_score)}</p>
          <p class="small">Clique ci-dessous pour poursuivre la vérification OTP gérée par Keycloak.</p>
          <a href="/login" class="btn btn-success">Recommencer le parcours</a>
          <a href="/logout" class="btn btn-logout">Logout</a>
        `
      )
    );
  }

  if (adaptive.decision === "STEP_UP_BIOMETRIC") {
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
        challengeType: "turn_left",
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
  const challengeType = String(req.body.challenge_type || "turn_left").trim();
  const adaptive = req.session.adaptiveAuth || {};

  if (!primaryImageBase64 || !challengeImageBase64) {
    return res.status(400).send(
      renderBiometricCapturePage({
        title: "Étape biométrique requise",
        message:
          "Deux captures sont requises pour finaliser la vérification biométrique active.",
        action: "/adaptive-biometric-verify",
        buttonLabel: "Capturer l’étape 1",
        activeLiveness: true,
        challengeType,
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
          challengeType,
          infoHtml: `
            <p><b>Similarity primary:</b> ${result.similarity_primary ?? "n/a"}</p>
            <p><b>Similarity challenge:</b> ${result.similarity_challenge ?? "n/a"}</p>
            <p><b>Liveness passed:</b> ${result.liveness_passed ? "yes" : "no"}</p>
            <p><b>Liveness reason:</b> ${result.liveness_reason || "n/a"}</p>
            <p><b>Yaw primary:</b> ${result.yaw_primary ?? "n/a"}</p>
            <p><b>Yaw challenge:</b> ${result.yaw_challenge ?? "n/a"}</p>
            <p><b>Motion delta:</b> ${result.motion_delta ?? "n/a"}</p>
            <p><b>Attempts:</b> ${req.session.adaptiveAuth.biometric_attempts}</p>
          `,
          errorMessage: result.reason || "Visage non validé.",
        })
      );
    }

    req.session.adaptiveAuth = {
      ...(req.session.adaptiveAuth || {}),
      decision: "STEP_UP_BIOMETRIC",
      required_factor: "FACE_RECOGNITION",
      auth_path: "BIOMETRIC_FACTOR",
      policy_reason: "adaptive_biometric_verified",
      completed: true,
      completed_at: new Date().toISOString(),
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
      motion_delta: result.motion_delta,
    };

    return res.redirect("/");
  } catch (e) {
    console.error("[portal] biometric verify error:", e);
    return res.status(400).send(
      renderBiometricCapturePage({
        title: "Étape biométrique requise",
        message:
          "La vérification biométrique a échoué. Reprends les 2 captures.",
        action: "/adaptive-biometric-verify",
        buttonLabel: "Capturer l’étape 1",
        activeLiveness: true,
        challengeType,
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
  const idToken =
    req.session.stepupTokens?.id_token || req.session.tokens?.id_token;

  req.session.destroy((err) => {
    if (err) {
      console.error("[portal] Session destroy error:", err);
    }

    res.clearCookie(SESSION_COOKIE_NAME, SESSION_COOKIE_OPTIONS);

    if (!idToken) {
      return res.redirect(`${APP_BASE_URL}/`);
    }

    const logoutUrl = `${KC_PUBLIC_URL}/realms/${KC_REALM}/protocol/openid-connect/logout`;
    const postRedirect = encodeURIComponent(`${APP_BASE_URL}/`);
    const url = `${logoutUrl}?id_token_hint=${encodeURIComponent(
      idToken
    )}&post_logout_redirect_uri=${postRedirect}&client_id=${encodeURIComponent(
      CLIENT_ID
    )}`;

    res.redirect(url);
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
