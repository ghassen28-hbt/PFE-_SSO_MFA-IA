const express = require("express");
const session = require("express-session");
const dotenv = require("dotenv");
const { buildClient, extractRealmRoles } = require("../shared/oidc");
const {
  readPortalSecurityState,
  writePortalSecurityState,
} = require("../shared/portal-security-state");

dotenv.config();

const app = express();
const PORT = 4001;

const KC_BASE_URL = process.env.KC_BASE_URL || "http://localhost:8081";
const KC_REALM = process.env.KC_REALM || "PFE-SSO";
const KC_ADMIN_REALM = process.env.KC_ADMIN_REALM || "master";
const KC_ADMIN_CLIENT_ID = process.env.KC_ADMIN_CLIENT_ID || "admin-cli";
const KC_ADMIN_USERNAME =
  process.env.KC_ADMIN_USERNAME || process.env.KEYCLOAK_ADMIN || "admin";
const KC_ADMIN_PASSWORD =
  process.env.KC_ADMIN_PASSWORD || process.env.KEYCLOAK_ADMIN_PASSWORD || "admin";
const ADMIN_BOOTSTRAP_APPROVAL_HOURS = Math.max(
  1,
  Number(process.env.PORTAL_ADMIN_BOOTSTRAP_APPROVAL_HOURS || 24)
);

const CLIENT_ID = process.env.ADMIN_CLIENT_ID || "admin-console-client-1";
const CLIENT_SECRET = process.env.ADMIN_CLIENT_SECRET;
const REDIRECT_URI = `http://localhost:${PORT}/callback`;
const SESSION_COOKIE_NAME =
  process.env.ADMIN_SESSION_COOKIE_NAME || "pfe_admin_sid";
const SESSION_COOKIE_OPTIONS = {
  path: "/",
  httpOnly: true,
  secure: false,
  sameSite: "lax",
};
// event-collector (FastAPI) attendu: POST /events
const EVENT_COLLECTOR_URL = (process.env.EVENT_COLLECTOR_URL || "http://localhost:8088/events").trim();

if (!CLIENT_SECRET) {
  console.error("ADMIN_CLIENT_SECRET missing in .env");
  process.exit(1);
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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
let keycloakAdminTokenCache = {
  token: null,
  expiresAt: 0,
};

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
      console.error("[admin] Session destroy before login error:", err);
    }
    finishRedirect();
  });
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
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
      `[admin] keycloak admin token error: ${response.status} ${response.statusText} ${text}`.trim()
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

async function listRealmUsers() {
  const adminToken = await fetchKeycloakAdminToken();
  const users = [];
  const pageSize = 100;
  let first = 0;

  while (true) {
    const response = await fetch(
      `${KC_BASE_URL}/admin/realms/${KC_REALM}/users?first=${first}&max=${pageSize}`,
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
        `[admin] keycloak users list error: ${response.status} ${response.statusText} ${text}`.trim()
      );
    }

    const batch = await response.json();
    users.push(...batch);

    if (!Array.isArray(batch) || batch.length < pageSize) {
      break;
    }
    first += batch.length;
  }

  return users;
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
      `[admin] keycloak user read error: ${response.status} ${response.statusText} ${text}`.trim()
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
      `[admin] keycloak user update error: ${response.status} ${response.statusText} ${text}`.trim()
    );
  }

  return nextState;
}

async function listPendingBootstrapApprovals() {
  const users = await listRealmUsers();
  return users
    .map((user) => ({
      user,
      state: readPortalSecurityState(user.attributes),
    }))
    .filter(({ state }) => state.admin_bootstrap.status === "pending")
    .sort((left, right) => {
      const leftTime = Date.parse(left.state.admin_bootstrap.requested_at || "");
      const rightTime = Date.parse(right.state.admin_bootstrap.requested_at || "");
      return (rightTime || 0) - (leftTime || 0);
    });
}

(async () => {
  const built = await buildClient({
    kcBaseUrl: KC_BASE_URL,
    realm: KC_REALM,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    redirectUri: REDIRECT_URI,
  });
  client = built.client;
  issuerUrl = built.issuerUrl;
})();

// ---------------- UI styles ----------------
const styles = `
  <style>
    body {
      margin: 0;
      height: 100vh;
      display: flex;
      justify-content: center;
      align-items: center;
      background-color: #f4f7f6;
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
    .admin-container {
      background-color: #ffffff;
      padding: 40px;
      border-radius: 12px;
      box-shadow: 0 8px 16px rgba(0, 0, 0, 0.1);
      text-align: center;
      width: 100%;
      max-width: 380px;
    }
    h2 {
      color: #2c3e50;
      margin-top: 0;
      margin-bottom: 16px;
      font-size: 24px;
    }
    p {
      color: #555;
      font-size: 16px;
      margin-bottom: 18px;
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
    }
    .btn:last-child { margin-bottom: 0; }
    .btn-login { background-color: #007bff; }
    .btn-login:hover { background-color: #0056b3; transform: translateY(-2px); }
    .btn-secondary { background-color: #6c757d; }
    .btn-secondary:hover { background-color: #5a6268; transform: translateY(-2px); }
    .btn-success { background-color: #28a745; border: none; cursor: pointer; }
    .btn-success:hover { background-color: #218838; transform: translateY(-2px); }
    .btn-danger { background-color: #fd7e14; border: none; cursor: pointer; }
    .btn-danger:hover { background-color: #e86b00; transform: translateY(-2px); }
    .btn-logout { background-color: #dc3545; }
    .btn-logout:hover { background-color: #c82333; transform: translateY(-2px); }
    .approval-container {
      background-color: #ffffff;
      padding: 32px;
      border-radius: 12px;
      box-shadow: 0 8px 16px rgba(0, 0, 0, 0.08);
      width: min(960px, calc(100vw - 40px));
      max-height: calc(100vh - 40px);
      overflow: auto;
    }
    .approval-card {
      border: 1px solid #d9dee4;
      border-radius: 10px;
      padding: 20px;
      margin-bottom: 16px;
      text-align: left;
      background: #f9fbfc;
    }
    .approval-card:last-child { margin-bottom: 0; }
    .badge {
      display: inline-block;
      padding: 8px 14px;
      border-radius: 999px;
      background: #e9f4ff;
      color: #1f4f7a;
      font-weight: 700;
      margin-bottom: 12px;
    }
    .small {
      font-size: 14px;
      color: #5f6b76;
    }
    .approval-actions {
      display: grid;
      gap: 10px;
      margin-top: 16px;
    }
    input[type="text"] {
      width: 100%;
      padding: 10px 12px;
      border: 1px solid #cfd7df;
      border-radius: 8px;
      box-sizing: border-box;
      margin-bottom: 10px;
    }
  </style>
`;

// ---------------- Message "pas d'accès" ----------------
function renderForbidden(res, username, roles) {
  return res.status(403).send(`
    ${styles}
    <div class="admin-container">
      <h2>Accès refusé</h2>
      <p>Désolé <b>${username || "utilisateur"}</b>, tu n'as pas accès à cette application.</p>
      <p>Rôle(s) détecté(s) : <b>${roles?.length ? roles.join(", ") : "aucun"}</b></p>
      <a href="/logout" class="btn btn-logout">Logout</a>
    </div>
  `);
}

// ---------------- RBAC GLOBAL: App Admin = CEO ONLY ----------------
function requireCeoForAdminApp(req, res, next) {
  // routes publiques nécessaires au flow OIDC
  const publicPaths = ["/login", "/callback", "/logout"];
  if (publicPaths.includes(req.path)) return next();

  // si pas connecté -> on autorise "/" pour afficher le bouton login
  if (!req.session.user) return next();

  // connecté -> vérifier le rôle CEO
  const roles = req.session?.user?.roles || [];
  if (!roles.includes("CEO")) {
    const username =
      req.session.user.preferred_username || req.session.user.email || "user";
    return renderForbidden(res, username, roles);
  }

  next();
}

// Active la protection globale
app.use(requireCeoForAdminApp);

// ---------------- Routes ----------------
app.get("/", (req, res) => {
  // Non connecté
  if (!req.session.user) {
    return res.send(`
      ${styles}
      <div class="admin-container">
        <h2>Admin</h2>
        <p>Application réservée au <b>CEO</b></p>
        <a href="/login" class="btn btn-login">Login</a>
      </div>
    `);
  }

  // Connecté (ici forcément CEO grâce au middleware)
  const username =
    req.session.user.preferred_username || req.session.user.email || "user";
  const roles = (req.session.user.roles || []).join(", ") || "none";

  res.send(`
    ${styles}
    <div class="admin-container">
      <h2>Admin</h2>
      <p>Connecté: <b>${username}</b></p>
      <p>Rôles: <b>${roles}</b></p>
      <a href="/protected" class="btn btn-secondary">Page protégée</a>
      <a href="/logout" class="btn btn-logout">Logout</a>
    </div>
  `);
});

app.get("/login", (req, res) => {
  if (!client) return res.status(503).send("OIDC client not ready, retry.");
  redirectToFreshLogin(req, res, client);
});

app.get("/callback", async (req, res) => {
  if (!client) return res.status(503).send("OIDC client not ready, retry.");

  const params = client.callbackParams(req);
  const tokenSet = await client.callback(REDIRECT_URI, params);
  const userinfo = await client.userinfo(tokenSet.access_token);

  const roles = extractRealmRoles(tokenSet.access_token);

  req.session.user = { ...userinfo, roles };
  req.session.tokens = {
    access_token: tokenSet.access_token,
    refresh_token: tokenSet.refresh_token,
    id_token: tokenSet.id_token,
  };

  const tokenPayload = JSON.parse(
    Buffer.from(tokenSet.access_token.split(".")[1], "base64").toString("utf8")
  );
  console.log("TOKEN realm_access:", tokenPayload.realm_access);
  console.log("TOKEN resource_access:", tokenPayload.resource_access);
  console.log("EXTRACTED ROLES:", roles);

  // Send LOGIN event to event-collector to persist features
  try {
    const ip =
      req.headers["x-forwarded-for"]?.split(",")[0].trim() ||
      req.headers["x-real-ip"] ||
      req.socket.remoteAddress;

    const ua = req.headers["user-agent"] || "";

    const eventPayload = {
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
      sessionId: req.sessionID,
    };

    await fetch(EVENT_COLLECTOR_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-forwarded-for": ip,
      },
      body: JSON.stringify(eventPayload),
    });
  } catch (e) {
    console.error("[admin] Event collector error:", e);
  }

  // après login, s'il n'est pas CEO -> le middleware affichera le message d'erreur
  res.redirect("/");
});

// même si ce n'est pas nécessaire, on garde /protected (CEO only via middleware global)
app.get("/protected", (req, res) => {
  const username = req.session.user?.preferred_username || "user";
  res.send(`
    ${styles}
    <div class="admin-container">
      <h2>Admin - Protégé</h2>
      <p>Bienvenue <b>${username}</b>, accès autorisé (CEO).</p>
      <a href="/" class="btn btn-secondary">Retour</a>
      <a href="/logout" class="btn btn-logout">Logout</a>
    </div>
  `);
});

app.get("/mfa-approvals", async (req, res) => {
  if (!req.session.user) {
    return res.redirect("/login");
  }

  const pendingRequests = await listPendingBootstrapApprovals();
  const flashStatus = String(req.query.status || "").trim();
  const flashUser = String(req.query.user || "").trim();
  const flashMessage = flashStatus
    ? `<div class="approval-card"><div class="badge">Operation</div><p>${escapeHtml(
        flashStatus
      )}${flashUser ? ` pour <b>${escapeHtml(flashUser)}</b>` : ""}</p></div>`
    : "";

  const cards = pendingRequests.length
    ? pendingRequests
        .map(({ user, state }) => {
          const displayName =
            user.username || user.email || user.firstName || user.id || "user";
          const requestIp = state.admin_bootstrap.request_ip || "n/a";
          const riskScore =
            state.admin_bootstrap.requested_risk_score == null
              ? "n/a"
              : Number(state.admin_bootstrap.requested_risk_score).toFixed(4);
          return `
            <div class="approval-card">
              <div class="badge">Bootstrap pending</div>
              <p><b>Utilisateur:</b> ${escapeHtml(displayName)}</p>
              <p><b>User ID:</b> ${escapeHtml(user.id || "n/a")}</p>
              <p><b>Requested by:</b> ${escapeHtml(
                state.admin_bootstrap.requested_by || "n/a"
              )}</p>
              <p><b>Requested at:</b> ${escapeHtml(
                state.admin_bootstrap.requested_at || "n/a"
              )}</p>
              <p><b>Requested decision:</b> ${escapeHtml(
                state.admin_bootstrap.requested_decision || "n/a"
              )}</p>
              <p><b>Policy reason:</b> ${escapeHtml(
                state.admin_bootstrap.requested_policy_reason || "n/a"
              )}</p>
              <p><b>Risk label:</b> ${escapeHtml(
                state.admin_bootstrap.requested_risk_label || "n/a"
              )}</p>
              <p><b>Risk score:</b> ${escapeHtml(riskScore)}</p>
              <p><b>Request IP:</b> ${escapeHtml(requestIp)}</p>
              <p class="small">Validation defendable: l'admin n'ouvre pas directement l'app. Il autorise seulement une fenetre d'onboarding MFA limitee dans le temps.</p>
              <div class="approval-actions">
                <form method="post" action="/mfa-approvals/${encodeURIComponent(
                  user.id
                )}/approve">
                  <button type="submit" class="btn btn-success">Approuver le bootstrap limite</button>
                </form>
                <form method="post" action="/mfa-approvals/${encodeURIComponent(
                  user.id
                )}/reject">
                  <input type="text" name="reason" placeholder="Motif du refus (optionnel)" />
                  <button type="submit" class="btn btn-danger">Refuser</button>
                </form>
              </div>
            </div>
          `;
        })
        .join("")
    : `
        <div class="approval-card">
          <div class="badge">No pending request</div>
          <p>Aucune validation MFA en attente pour le moment.</p>
        </div>
      `;

  return res.send(`
    ${styles}
    <div class="approval-container">
      <h2>Validations MFA</h2>
      <p>Cette page sert a approuver ou refuser le bootstrap MFA d'un premier acces juge trop risqué pour etre laisse en self-service.</p>
      ${flashMessage}
      ${cards}
      <a href="/" class="btn btn-secondary">Retour</a>
      <a href="/logout" class="btn btn-logout">Logout</a>
    </div>
  `);
});

app.post("/mfa-approvals/:userId/approve", async (req, res) => {
  if (!req.session.user) {
    return res.redirect("/login");
  }

  const approver =
    req.session.user.preferred_username ||
    req.session.user.email ||
    req.session.user.sub ||
    "admin";
  const approvalHours = ADMIN_BOOTSTRAP_APPROVAL_HOURS;
  const approvedUntil = new Date(Date.now() + approvalHours * 60 * 60 * 1000).toISOString();
  const updatedState = await updateKeycloakUserState(req.params.userId, (state) => ({
    ...state,
    onboarding: {
      ...state.onboarding,
      required: true,
      required_since: state.onboarding?.required_since || new Date().toISOString(),
    },
    admin_bootstrap: {
      ...state.admin_bootstrap,
      status: "approved",
      approved_at: new Date().toISOString(),
      approved_by: approver,
      approved_until: approvedUntil,
      rejection_reason: null,
    },
  }));

  return res.redirect(
    `/mfa-approvals?status=${encodeURIComponent("approval recorded")}&user=${encodeURIComponent(
      updatedState.admin_bootstrap.requested_by || req.params.userId
    )}`
  );
});

app.post("/mfa-approvals/:userId/reject", async (req, res) => {
  if (!req.session.user) {
    return res.redirect("/login");
  }

  const reason = String(req.body.reason || "").trim() || "rejected_by_admin";
  const updatedState = await updateKeycloakUserState(req.params.userId, (state) => ({
    ...state,
    onboarding: {
      ...state.onboarding,
      required: true,
      required_since: state.onboarding?.required_since || new Date().toISOString(),
    },
    admin_bootstrap: {
      ...state.admin_bootstrap,
      status: "rejected",
      approved_at: null,
      approved_by: null,
      approved_until: null,
      rejection_reason: reason,
    },
  }));

  return res.redirect(
    `/mfa-approvals?status=${encodeURIComponent("rejection recorded")}&user=${encodeURIComponent(
      updatedState.admin_bootstrap.requested_by || req.params.userId
    )}`
  );
});

app.get("/logout", (req, res) => {
  const idToken = req.session.tokens?.id_token;

  req.session.destroy(() => {
    res.clearCookie(SESSION_COOKIE_NAME, SESSION_COOKIE_OPTIONS);
    const redirect = encodeURIComponent(`http://localhost:${PORT}/`);
    if (!idToken) return res.redirect(`http://localhost:${PORT}/`);

    const url =
      `${issuerUrl}/protocol/openid-connect/logout` +
      `?id_token_hint=${encodeURIComponent(idToken)}` +
      `&post_logout_redirect_uri=${redirect}` +
      `&client_id=${encodeURIComponent(CLIENT_ID)}`;

    res.redirect(url);
  });
});

// Dans server.js de tes apps, route changement de mot de passe
app.post('/change-password', async (req, res) => {
  const { password } = req.body;

  const check = await fetch('http://event-collector:8088/check-password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password })
  });
  const result = await check.json();

  if (result.pwned) {
    return res.status(400).json({
      error: `Ce mot de passe a été exposé ${result.exposure_count} fois. Choisissez-en un autre.`
    });
  }
  // continuer le changement...
});

app.listen(PORT, () => console.log(`Admin running on http://localhost:${PORT}`));
