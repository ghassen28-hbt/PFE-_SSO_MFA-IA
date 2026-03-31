const express = require("express");
const session = require("express-session");
const dotenv = require("dotenv");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const fs = require("fs");
const path = require("path");
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

app.set("trust proxy", 1);

app.use((req, res, next) => {
  const ch =
    "Sec-CH-UA, Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version, Sec-CH-UA-Full-Version-List";
  res.setHeader("Accept-CH", ch);
  res.setHeader("Critical-CH", ch);
  res.setHeader(
    "Permissions-Policy",
    'ch-ua=(self), ch-ua-platform=(self), ch-ua-platform-version=(self), ch-ua-full-version-list=(self)'
  );
  next();
});

const KC_BASE_URL = (process.env.KC_BASE_URL || "http://localhost:8081").trim().replace(/\/+$/, "");
const KC_PUBLIC_URL = (process.env.KC_PUBLIC_URL || KC_BASE_URL).trim().replace(/\/+$/, "");
const KC_REALM = (process.env.KC_REALM || "PFE-SSO").trim();

const CLIENT_ID = (process.env.PORTAL_CLIENT_ID || "portal-client-5").trim();
const CLIENT_SECRET = (process.env.PORTAL_CLIENT_SECRET || "").trim();

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
).trim().replace(/\/+$/, "");

const APP_BASE_URL = (
  process.env.PORTAL_BASE_URL || `http://localhost:${PORT}`
).trim().replace(/\/+$/, "");

const REDIRECT_URI = `${APP_BASE_URL}/callback`;

const SHARED_DATA_DIR = process.env.SHARED_DATA_DIR?.trim()
  ? path.resolve(process.env.SHARED_DATA_DIR.trim())
  : path.join(__dirname, "..", "shared-data");

const TOTP_STORE_PATH = process.env.TOTP_STORE_PATH?.trim()
  ? path.resolve(process.env.TOTP_STORE_PATH.trim())
  : path.join(SHARED_DATA_DIR, "totp-store.json");

fs.mkdirSync(SHARED_DATA_DIR, { recursive: true });

if (!CLIENT_SECRET) {
  console.error("[portal] PORTAL_CLIENT_SECRET missing in .env");
  process.exit(1);
}

app.use(
  session({
    secret: process.env.SESSION_SECRET || "change_me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
    },
  })
);

let client;
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

async function buildClient({
  kcBaseUrl,
  realm,
  clientId,
  clientSecret,
  redirectUri,
}) {
  const issuer = await Issuer.discover(
    `${kcBaseUrl}/realms/${realm}`
  );

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

function loadTotpStoreFromDisk() {
  try {
    if (!fs.existsSync(TOTP_STORE_PATH)) {
      return new Map();
    }

    const raw = fs.readFileSync(TOTP_STORE_PATH, "utf8");
    if (!raw.trim()) return new Map();

    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return new Map();

    return new Map(Object.entries(parsed));
  } catch (err) {
    console.error("[portal] unable to load TOTP store:", err);
    return new Map();
  }
}

function persistTotpStore() {
  try {
    const payload = Object.fromEntries(appTotpStore.entries());
    const tmpPath = `${TOTP_STORE_PATH}.tmp`;

    fs.writeFileSync(tmpPath, JSON.stringify(payload, null, 2), "utf8");
    fs.renameSync(tmpPath, TOTP_STORE_PATH);
  } catch (err) {
    console.error("[portal] unable to persist TOTP store:", err);
  }
}

const appTotpStore = loadTotpStoreFromDisk();

function getClientIp(req) {
  return (
    req.headers["cf-connecting-ip"] ||
    req.headers["x-forwarded-for"]?.split(",")[0].trim() ||
    req.headers["x-real-ip"] ||
    req.ip ||
    req.socket?.remoteAddress ||
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

function getUserTotpRecord(user) {
  const key = user?.sub;
  if (!key) return null;
  return appTotpStore.get(key) || null;
}

function setUserTotpRecord(user, record) {
  const key = user?.sub;
  if (!key) return;

  appTotpStore.set(key, record);
  persistTotpStore();
}

function requirePortalAccess(req, res, next) {
  const publicPaths = [
    "/login",
    "/callback",
    "/logout",
    "/adaptive-stepup",
    "/adaptive-blocked",
    "/adaptive-totp-verify",
    "/adaptive-biometric-verify",
    "/security/setup-totp",
    "/security/setup-totp/verify",
    "/security/setup-face",
    "/security/setup-face/capture",
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
      max-width: 560px;
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
    .qr-wrap {
      margin: 16px 0 20px 0;
    }
    img.qr {
      max-width: 220px;
      width: 100%;
      height: auto;
      border: 1px solid #e5e7eb;
      border-radius: 8px;
      padding: 10px;
      background: #fff;
    }
    code.secret {
      display: block;
      padding: 10px;
      background: #f3f4f6;
      border-radius: 6px;
      word-break: break-all;
      margin: 12px 0 16px 0;
    }
  </style>
`;

app.use(requirePortalAccess);

(async () => {
  try {
    const built = await buildClient({
      kcBaseUrl: KC_BASE_URL,
      realm: KC_REALM,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      redirectUri: REDIRECT_URI,
    });

    client = built.client;
    issuerUrl = built.issuerUrl;

    console.log(`[portal] ready: ${APP_BASE_URL}`);
    console.log(`[portal] issuerUrl: ${issuerUrl}`);
    console.log(`[portal] redirectUri: ${REDIRECT_URI}`);
    console.log(`[portal] shared TOTP store: ${TOTP_STORE_PATH}`);
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
  const totp = getUserTotpRecord(req.session.user);

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
      <p><b>Risk score:</b> ${adaptive.risk_score ?? "n/a"}</p>
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
    <p><b>TOTP app setup:</b> ${totp?.verified ? "configured" : "not configured"}</p>
    ${
      totp?.verified
        ? `<p class="small">Dernière configuration TOTP : ${totp.enrolled_at || "n/a"}</p>`
        : ""
    }
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
        <a href="/security/setup-totp" class="btn btn-success">Configurer TOTP</a>
        <a href="/security/setup-face" class="btn btn-success">Configurer biométrie faciale</a>
        <a href="/protected" class="btn btn-secondary">Page protégée</a>
        <a href="/logout" class="btn btn-logout">Logout</a>
      `
    )
  );
});

app.get("/login", (req, res) => {
  if (!client) return res.status(503).send("OIDC client not ready, retry.");
  res.redirect(
    client.authorizationUrl({
      scope: "openid profile email",
    })
  );
});

async function sendAppSessionStartedEvent({ userinfo, ip, ua, ch, sessionId }) {
  const payload = {
    type: "APP_SESSION_STARTED",
    realm: KC_REALM,
    clientId: CLIENT_ID,
    userId: userinfo.sub,
    error: "",
    details: {
      username: userinfo.preferred_username || userinfo.email || "",
    },
    ipAddress: ip,
    http_x_forwarded_for: ip,
    http_user_agent: ua,
    sessionId,
    http_sec_ch_ua: ch.http_sec_ch_ua,
    http_sec_ch_ua_platform: ch.http_sec_ch_ua_platform,
    http_sec_ch_ua_platform_version: ch.http_sec_ch_ua_platform_version,
    http_sec_ch_ua_full_version_list: ch.http_sec_ch_ua_full_version_list,
    http_accept_language: ch.http_accept_language,
  };

  const eventRes = await fetch(EVENT_COLLECTOR_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-forwarded-for": ip,
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

async function assessAdaptiveRisk({ userinfo, ip, ua, ch }) {
  const payload = {
    realm: KC_REALM,
    clientId: CLIENT_ID,
    userId: userinfo.sub,
    details: {
      username: userinfo.preferred_username || userinfo.email || "",
    },
    ipAddress: ip,
    http_x_forwarded_for: ip,
    http_user_agent: ua,
    http_sec_ch_ua: ch.http_sec_ch_ua,
    http_sec_ch_ua_platform: ch.http_sec_ch_ua_platform,
    http_sec_ch_ua_platform_version: ch.http_sec_ch_ua_platform_version,
    http_sec_ch_ua_full_version_list: ch.http_sec_ch_ua_full_version_list,
    http_accept_language: ch.http_accept_language,
  };

  const assessRes = await fetch(ASSESS_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-forwarded-for": ip,
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

async function buildTotpSetupPage(user, { forceReset = false } = {}) {
  const username = user.preferred_username || user.email || user.sub || "user";
  let record = getUserTotpRecord(user);

  if (record?.base32 && record.verified === true && !forceReset && !record.pending_base32) {
    return htmlPage(
      "TOTP déjà configuré",
      `
        <p>Le second facteur TOTP est déjà configuré pour cet utilisateur.</p>
        <p><b>Utilisateur :</b> ${username}</p>
        <p><b>Date d’enrôlement :</b> ${record.enrolled_at || "n/a"}</p>
        <p class="small">Le secret TOTP est maintenant stocké de façon persistante dans un store partagé entre toutes les apps.</p>
        <a href="/security/setup-totp?reset=1" class="btn btn-secondary">Réinitialiser le TOTP</a>
        <a href="/" class="btn btn-success">Retour à l’accueil</a>
        <a href="/logout" class="btn btn-logout">Logout</a>
      `
    );
  }

  if (forceReset || !record || !record.pending_base32) {
    const secret = speakeasy.generateSecret({
      name: `PFE-SSO (${username})`,
      issuer: "PFE-SSO",
      length: 20,
    });

    record = {
      pending_base32: secret.base32,
      pending_otpauth_url: secret.otpauth_url,
      verified: false,
      created_at: new Date().toISOString(),
    };

    setUserTotpRecord(user, record);
  }

  const qrDataUrl = await QRCode.toDataURL(record.pending_otpauth_url);

  return htmlPage(
    "Configuration TOTP",
    `
      <p>Configure ton second facteur dans un contexte sûr avant d’utiliser le step-up adaptatif.</p>
      <div class="qr-wrap">
        <img class="qr" src="${qrDataUrl}" alt="QR Code TOTP" />
      </div>
      <p class="small">Secret manuel :</p>
      <code class="secret">${record.pending_base32}</code>

      <form method="post" action="/security/setup-totp/verify">
        <input class="field" type="text" name="token" maxlength="6" placeholder="Entre le code TOTP à 6 chiffres" required />
        <button type="submit" class="btn btn-success">Valider la configuration TOTP</button>
      </form>

      <a href="/" class="btn btn-secondary">Retour</a>
      <a href="/logout" class="btn btn-logout">Logout</a>
    `
  );
}

function renderTotpVerifyPage(errorMessage = "", adaptive = {}) {
  return htmlPage(
    "Second facteur requis",
    `
      <p>Le niveau de risque est modéré. Un second facteur réel de type TOTP est demandé.</p>
      <p><b>Policy reason:</b> ${adaptive.policy_reason || "n/a"}</p>
      <p><b>Risk score:</b> ${adaptive.risk_score ?? "n/a"}</p>
      ${errorMessage ? `<p class="error">${errorMessage}</p>` : ""}
      <form method="post" action="/adaptive-totp-verify">
        <input class="field" type="text" name="token" maxlength="6" placeholder="Entrez le code TOTP à 6 chiffres" required />
        <button type="submit" class="btn btn-success">Vérifier le code TOTP</button>
      </form>
      <a href="/logout" class="btn btn-logout">Logout</a>
    `
  );
}

function renderTotpNotEnrolledPage(user, adaptive = {}) {
  const username = user?.preferred_username || user?.email || "user";

  return htmlPage(
    "Second facteur non initialisé",
    `
      <p>Le niveau de risque est modéré et un second facteur TOTP est requis.</p>
      <div class="info-box">
        <p><b>Utilisateur :</b> ${username}</p>
        <p><b>Problème :</b> aucun TOTP partagé n’a été préalablement configuré.</p>
        <p><b>Policy reason:</b> ${adaptive.policy_reason || "n/a"}</p>
        <p><b>Risk score:</b> ${adaptive.risk_score ?? "n/a"}</p>
        <p class="small">
          Configure d’abord le TOTP depuis une session normale et de confiance.
        </p>
      </div>
      <a href="/" class="btn btn-secondary">Retour</a>
      <a href="/logout" class="btn btn-logout">Logout</a>
    `
  );
}

app.get("/callback", async (req, res) => {
  try {
    if (!client) return res.status(503).send("OIDC client not ready, retry.");

    const params = client.callbackParams(req);
    const tokenSet = await client.callback(REDIRECT_URI, params);
    const userinfo = await client.userinfo(tokenSet.access_token);

    const roles = extractRealmRoles(tokenSet.access_token);
    const ip = getClientIp(req);
    const ua = req.headers["user-agent"] || "";
    const ch = getClientHints(req);

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
      const assess = await assessAdaptiveRisk({ userinfo, ip, ua, ch });

      adaptiveDecision = {
        risk_score: assess.risk_score ?? null,
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
        ip,
        ua,
        ch,
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

    if (
      adaptiveDecision.decision === "STEP_UP_TOTP" ||
      adaptiveDecision.decision === "STEP_UP_BIOMETRIC"
    ) {
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

app.get("/security/setup-totp", async (req, res) => {
  if (!req.session.user) return res.redirect("/login");

  const adaptive = req.session.adaptiveAuth || {};
  if (adaptive.completed === false && adaptive.decision !== "ALLOW") {
    return res.status(403).send(
      htmlPage(
        "Configuration refusée",
        `
          <p>La configuration TOTP n'est pas autorisée pendant une session jugée suspecte.</p>
          <p><b>Policy reason:</b> ${adaptive.policy_reason || "n/a"}</p>
          <p><b>Risk score:</b> ${adaptive.risk_score ?? "n/a"}</p>
          <p class="small">Reconnecte-toi dans un contexte normal, ou finalise d’abord le contrôle en cours.</p>
          <a href="/" class="btn btn-secondary">Retour</a>
          <a href="/logout" class="btn btn-logout">Logout</a>
        `
      )
    );
  }

  const forceReset = String(req.query.reset || "").trim() === "1";
  const page = await buildTotpSetupPage(req.session.user, { forceReset });
  return res.send(page);
});

app.post("/security/setup-totp/verify", (req, res) => {
  if (!req.session.user) return res.redirect("/login");

  const token = String(req.body.token || "").trim().replace(/\s+/g, "");
  const record = getUserTotpRecord(req.session.user);

  if (!record?.pending_base32) {
    if (record?.base32 && record.verified === true) {
      return res.redirect("/");
    }
    return res.redirect("/security/setup-totp");
  }

  const isValid = speakeasy.totp.verify({
    secret: record.pending_base32,
    encoding: "base32",
    token,
    window: 1,
  });

  if (!isValid) {
    return res.status(400).send(
      htmlPage(
        "Configuration TOTP",
        `
          <p class="error">Code TOTP invalide. Réessaie.</p>
          <a href="/security/setup-totp" class="btn btn-secondary">Réessayer</a>
          <a href="/logout" class="btn btn-logout">Logout</a>
        `
      )
    );
  }

  setUserTotpRecord(req.session.user, {
    base32: record.pending_base32,
    verified: true,
    enrolled_at: new Date().toISOString(),
  });

  return res.send(
    htmlPage(
      "TOTP configuré",
      `
        <p>Le second facteur TOTP est maintenant configuré avec succès.</p>
        <a href="/" class="btn btn-success">Retour à l’accueil</a>
        <a href="/logout" class="btn btn-logout">Logout</a>
      `
    )
  );
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
          <p><b>Risk score:</b> ${adaptive.risk_score ?? "n/a"}</p>
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
    const record = getUserTotpRecord(req.session.user);

    if (!record?.base32 || record.verified !== true) {
      return res.status(403).send(
        renderTotpNotEnrolledPage(req.session.user, adaptive)
      );
    }

    return res.send(renderTotpVerifyPage("", adaptive));
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
              <p><b>Risk score:</b> ${adaptive.risk_score ?? "n/a"}</p>
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
          <p><b>Risk score:</b> ${adaptive.risk_score ?? "n/a"}</p>
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

app.post("/adaptive-totp-verify", (req, res) => {
  if (!req.session.user) return res.redirect("/login");

  const token = String(req.body.token || "").trim().replace(/\s+/g, "");
  const record = getUserTotpRecord(req.session.user);

  if (!record?.base32 || record.verified !== true) {
    return res.status(403).send(
      renderTotpNotEnrolledPage(req.session.user, req.session.adaptiveAuth || {})
    );
  }

  const isValid = speakeasy.totp.verify({
    secret: record.base32,
    encoding: "base32",
    token,
    window: 1,
  });

  if (!isValid) {
    return res.status(400).send(
      renderTotpVerifyPage(
        "Code TOTP invalide. Réessaie.",
        req.session.adaptiveAuth || {}
      )
    );
  }

  req.session.adaptiveAuth = {
    ...(req.session.adaptiveAuth || {}),
    decision: "STEP_UP_TOTP",
    required_factor: "TOTP_OR_WEBAUTHN",
    auth_path: "SECOND_FACTOR",
    policy_reason: "adaptive_totp_verified",
    completed: true,
    completed_at: new Date().toISOString(),
  };

  return res.redirect("/");
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
          <p><b>Risk score:</b> ${adaptive.risk_score ?? "n/a"}</p>
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
          <p><b>Risk score:</b> ${adaptive.risk_score ?? "n/a"}</p>
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
      <p><b>Risk score:</b> ${adaptive.risk_score ?? "n/a"}</p>
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
  const idToken = req.session.tokens?.id_token;

  req.session.destroy((err) => {
    if (err) {
      console.error("[portal] Session destroy error:", err);
    }

    if (!idToken) {
      return res.redirect(`${APP_BASE_URL}/`);
    }

    const logoutUrl = `${KC_PUBLIC_URL}/realms/${KC_REALM}/protocol/openid-connect/logout`;
    const postRedirect = encodeURIComponent(`${APP_BASE_URL}/`);
    const url = `${logoutUrl}?id_token_hint=${encodeURIComponent(idToken)}&post_logout_redirect_uri=${postRedirect}`;

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