const express = require("express");
const session = require("express-session");
const dotenv = require("dotenv");
const { buildClient, extractRealmRoles } = require("../shared/oidc");

dotenv.config();

const app = express();
const PORT = 4002;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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

const KC_BASE_URL = (process.env.KC_BASE_URL || "http://localhost:8081").trim();
const KC_PUBLIC_URL = (process.env.KC_PUBLIC_URL || KC_BASE_URL).trim();
const KC_REALM = (process.env.KC_REALM || "PFE-SSO").trim();

const CLIENT_ID = (process.env.CRM_CLIENT_ID || "crm-client-2").trim();
const CLIENT_SECRET = process.env.CRM_CLIENT_SECRET?.trim();

const EVENT_COLLECTOR_URL = (
  process.env.EVENT_COLLECTOR_URL || "http://localhost:8088/events"
).trim();

const ASSESS_URL = (
  process.env.ASSESS_URL || "http://localhost:8088/assess"
).trim();

const CHECK_PASSWORD_URL = (
  process.env.CHECK_PASSWORD_URL || "http://localhost:8088/check-password"
).trim();

const APP_BASE_URL = (process.env.CRM_BASE_URL || "http://localhost:4002").trim();
const REDIRECT_URI = `${APP_BASE_URL}/callback`;
const SESSION_COOKIE_NAME =
  process.env.CRM_SESSION_COOKIE_NAME || "pfe_crm_sid";
const SESSION_COOKIE_OPTIONS = {
  path: "/",
  httpOnly: true,
  secure: false,
  sameSite: "lax",
};

if (!CLIENT_SECRET) {
  console.error("CRM_CLIENT_SECRET missing in .env");
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

let client;
let issuerUrl;

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
      console.error("[crm] Session destroy before login error:", err);
    }
    finishRedirect();
  });
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

// CRM autorisé: CEO, Manager, employee
function requireCrmAccess(req, res, next) {
  const publicPaths = [
    "/login",
    "/callback",
    "/logout",
    "/adaptive-stepup",
    "/adaptive-blocked",
    "/adaptive-complete",
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
      max-width: 420px;
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
  </style>
`;

app.use(requireCrmAccess);

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

    console.log(`[crm] ready: ${APP_BASE_URL}`);
    console.log(`[crm] issuerUrl: ${issuerUrl}`);
    console.log(`[crm] redirectUri: ${REDIRECT_URI}`);
  } catch (err) {
    console.error("[crm] OIDC init error full:", err);
    console.error("[crm] OIDC init error message:", err?.message || err);
  }
})();

app.get("/", (req, res) => {
  if (!req.session.user) {
    return res.send(
      htmlPage(
        "CRM",
        `<a href="/login" class="btn btn-login">Login</a>`
      )
    );
  }

  const username =
    req.session.user.preferred_username || req.session.user.email || "user";
  const roles = (req.session.user.roles || []).join(", ") || "none";

  const adaptive = req.session.adaptiveAuth || {};
  const adaptiveInfo = adaptive.decision
    ? `
      <p><b>Risk label:</b> ${adaptive.risk_label || "unknown"}</p>
      <p><b>Decision:</b> ${adaptive.decision}</p>
      <p><b>Required factor:</b> ${adaptive.required_factor || "NONE"}</p>
      <p><b>Auth path:</b> ${adaptive.auth_path || "SSO_ONLY"}</p>
      <p><b>Risk score:</b> ${formatRiskScore(adaptive.risk_score)}</p>
      <p><b>Adaptive auth completed:</b> ${adaptive.completed ? "yes" : "no"}</p>
    `
    : `<p><b>Adaptive auth:</b> not evaluated</p>`;

  res.send(
    htmlPage(
      "CRM",
      `
        <p>Connecté: <b>${username}</b></p>
        <p>Rôles: <b>${roles}</b></p>
        ${adaptiveInfo}
        <a href="/protected" class="btn btn-secondary">Page protégée</a>
        <a href="/logout" class="btn btn-logout">Logout</a>
      `
    )
  );
});

app.get("/login", (req, res) => {
  if (!client) return res.status(503).send("OIDC client not ready, retry.");
  redirectToFreshLogin(req, res, client);
});

async function sendLoginEvent({
  userinfo,
  ip,
  ua,
  ch,
  sessionId,
}) {
  const payload = {
    type: "LOGIN",
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
      `[crm] event-collector error: ${eventRes.status} ${eventRes.statusText} ${text}`.trim()
    );
  }

  return await eventRes.json().catch(() => ({}));
}

async function assessAdaptiveRisk({
  userinfo,
  ip,
  ua,
  ch,
}) {
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
      `[crm] assess error: ${assessRes.status} ${assessRes.statusText} ${text}`.trim()
    );
  }

  return await assessRes.json();
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
      completed: true,
    };

    try {
      const assess = await assessAdaptiveRisk({ userinfo, ip, ua, ch });

      adaptiveDecision = {
        risk_score: normalizeRiskScore(assess.risk_score),
        risk_label: assess.risk_label || "unknown",
        decision: assess.decision || "ALLOW",
        required_factor: assess.required_factor || "NONE",
        auth_path: assess.auth_path || "SSO_ONLY",
        completed: assess.decision === "ALLOW",
      };

      console.log("[crm] adaptive assess:", adaptiveDecision);
    } catch (e) {
      console.error("[crm] Adaptive assess error:", e);
      adaptiveDecision = {
        risk_score: null,
        risk_label: "unknown",
        decision: "ALLOW",
        required_factor: "NONE",
        auth_path: "SSO_ONLY",
        completed: true,
      };
    }

    try {
      await sendLoginEvent({
        userinfo,
        ip,
        ua,
        ch,
        sessionId: req.sessionID,
      });
    } catch (e) {
      console.error("[crm] Event collector error:", e);
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
    console.error("[crm] Callback error full:", e);
    console.error("[crm] Callback error message:", e?.message || e);
    console.error(
      "[crm] Callback error response:",
      e?.response?.data || e?.response?.body || ""
    );
    res.status(500).send(`Callback error: ${e?.message || "unknown"}`);
  }
});

app.get("/adaptive-stepup", (req, res) => {
  if (!req.session.user) return res.redirect("/login");

  const adaptive = req.session.adaptiveAuth || {};
  const username =
    req.session.user.preferred_username || req.session.user.email || "user";

  if (adaptive.completed === true || adaptive.decision === "ALLOW") {
    return res.redirect("/");
  }

  let title = "Vérification supplémentaire requise";
  let message =
    "Votre tentative d’accès nécessite une vérification supplémentaire avant l’ouverture complète de la session.";
  let details = `
    <div class="badge">${adaptive.decision || "STEP_UP_REQUIRED"}</div>
    <p><b>Utilisateur:</b> ${username}</p>
    <p><b>Risk label:</b> ${adaptive.risk_label || "unknown"}</p>
    <p><b>Required factor:</b> ${adaptive.required_factor || "UNKNOWN"}</p>
    <p><b>Risk score:</b> ${formatRiskScore(adaptive.risk_score)}</p>
    <p class="small">Cette page représente la passerelle MFA adaptative. Dans la suite du projet, elle sera reliée au vrai facteur demandé.</p>
  `;

  if (adaptive.decision === "STEP_UP_BIOMETRIC") {
    title = "Étape biométrique requise";
    message =
      "Le niveau de risque est élevé. La session doit être renforcée par une vérification biométrique.";
  } else if (adaptive.decision === "STEP_UP_TOTP") {
    title = "Second facteur requis";
    message =
      "Le niveau de risque est modéré. Un second facteur de type TOTP/WebAuthn est demandé.";
  }

  return res.send(
    htmlPage(
      title,
      `
        <p>${message}</p>
        ${details}
        <form method="post" action="/adaptive-complete">
          <button type="submit" class="btn btn-success">Simuler la validation du facteur</button>
        </form>
        <a href="/logout" class="btn btn-logout">Logout</a>
      `
    )
  );
});

app.post("/adaptive-complete", (req, res) => {
  if (!req.session.user) return res.redirect("/login");

  if (!req.session.adaptiveAuth) {
    req.session.adaptiveAuth = {
      decision: "ALLOW",
      required_factor: "NONE",
      auth_path: "SSO_ONLY",
      completed: true,
    };
  } else {
    req.session.adaptiveAuth.completed = true;
    req.session.adaptiveAuth.completed_at = new Date().toISOString();
  }

  return res.redirect("/");
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
      "CRM - Protected",
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

  req.session.destroy(() => {
    res.clearCookie(SESSION_COOKIE_NAME, SESSION_COOKIE_OPTIONS);
    const redirect = encodeURIComponent(`${APP_BASE_URL}/`);
    if (!idToken) return res.redirect(`${APP_BASE_URL}/`);

    const url =
      `${KC_PUBLIC_URL}/realms/${KC_REALM}/protocol/openid-connect/logout` +
      `?id_token_hint=${encodeURIComponent(idToken)}` +
      `&post_logout_redirect_uri=${redirect}` +
      `&client_id=${encodeURIComponent(CLIENT_ID)}`;

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
      console.error("[CRM] check-password returned", check.status, text);
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
    console.error("[CRM] /change-password error", err);
    return res.status(500).json({
      error: "Impossible de vérifier le mot de passe pour le moment.",
    });
  }
});

app.listen(PORT, () => console.log(`CRM running on ${APP_BASE_URL}`));
