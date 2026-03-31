const express = require("express");
const session = require("express-session");
const dotenv = require("dotenv");
const { buildClient, extractRealmRoles } = require("../shared/oidc");

dotenv.config();

const app = express();
const PORT = 4003;

const KC_BASE_URL = process.env.KC_BASE_URL || "http://localhost:8081";
const KC_REALM = process.env.KC_REALM || "PFE-SSO";

const CLIENT_ID = process.env.FINANCE_CLIENT_ID || "finance-client-3";
const CLIENT_SECRET = process.env.FINANCE_CLIENT_SECRET;
const REDIRECT_URI = `http://localhost:${PORT}/callback`;
// event-collector (FastAPI) attendu: POST /events
const EVENT_COLLECTOR_URL = (process.env.EVENT_COLLECTOR_URL || "http://localhost:8088/events").trim();

if (!CLIENT_SECRET) {
  console.error("FINANCE_CLIENT_SECRET missing in .env");
  process.exit(1);
}

app.use(
  session({
    secret: process.env.SESSION_SECRET || "change_me",
    resave: false,
    saveUninitialized: false,
  })
);

let client;
let issuerUrl;

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
  console.log(`[finance] ready: http://localhost:${PORT}`);
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
      max-width: 340px;
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
    .btn-logout { background-color: #dc3545; }
    .btn-logout:hover { background-color: #c82333; transform: translateY(-2px); }
  </style>
`;

// ---------------- Helpers RBAC ----------------
function renderForbidden(res, username, roles) {
  return res.status(403).send(`
    ${styles}
    <div class="admin-container">
      <h2>Accès refusé</h2>
      <p>Désolé <b>${username || "utilisateur"}</b>, tu n'as pas accès à cette application.</p>
      <p>Rôle(s): <b>${roles?.length ? roles.join(", ") : "aucun"}</b></p>
      <a href="/logout" class="btn btn-logout">Logout</a>
    </div>
  `);
}

// Finance autorisé: CEO, Manager, employee
function requireFinanceAccess(req, res, next) {
  const publicPaths = ["/login", "/callback", "/logout"];
  if (publicPaths.includes(req.path)) return next();

  // pas connecté -> laisser "/" afficher login
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

  next();
}

// Active la protection globale Finance
app.use(requireFinanceAccess);

// ---------------- Routes ----------------
app.get("/", (req, res) => {
  if (!req.session.user) {
    return res.send(`
      ${styles}
      <div class="admin-container">
        <h2>Finance</h2>
        <a href="/login" class="btn btn-login">Login</a>
      </div>
    `);
  }

  const username =
    req.session.user.preferred_username || req.session.user.email || "user";
  const roles = (req.session.user.roles || []).join(", ") || "none";

  res.send(`
    ${styles}
    <div class="admin-container">
      <h2>Finance</h2>
      <p>Connecté: <b>${username}</b></p>
      <p>Rôles: <b>${roles}</b></p>
      <a href="/protected" class="btn btn-secondary">Page protégée</a>
      <a href="/logout" class="btn btn-logout">Logout</a>
    </div>
  `);
});

app.get("/login", (req, res) => {
  if (!client) return res.status(503).send("OIDC client not ready, retry.");
  res.redirect(client.authorizationUrl({ scope: "openid profile email" }));
});

app.get("/callback", async (req, res) => {
  try {
    if (!client) return res.status(503).send("OIDC client not ready, retry.");

    const params = client.callbackParams(req);
    const tokenSet = await client.callback(REDIRECT_URI, params);
    const userinfo = await client.userinfo(tokenSet.access_token);

    // ✅ roles depuis access_token
    const roles = extractRealmRoles(tokenSet.access_token);

    req.session.user = { ...userinfo, roles };
    req.session.tokens = {
      access_token: tokenSet.access_token,
      refresh_token: tokenSet.refresh_token,
      id_token: tokenSet.id_token,
      expires_at: tokenSet.expires_at,
    };

    // Send LOGIN event to event-collector to persist features
    try {
      const ip =
        req.headers["x-forwarded-for"]?.split(",")[0].trim() ||
        req.headers["x-real-ip"] ||
        req.socket.remoteAddress;

      const ua = req.headers["user-agent"] || "";

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
        sessionId: req.sessionID,
      };

      await fetch(EVENT_COLLECTOR_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-forwarded-for": ip,
        },
        body: JSON.stringify(payload),
      });
    } catch (e) {
      console.error("[finance] Event collector error:", e);
    }

    res.redirect("/");
  } catch (e) {
    console.error("Callback error:", e);
    res.status(500).send("Callback error");
  }
});

app.get("/protected", (req, res) => {
  if (!req.session.user) return res.redirect("/login");

  const username =
    req.session.user.preferred_username || req.session.user.email || "user";

  res.send(`
    ${styles}
    <div class="admin-container">
      <h2>Finance - Protected</h2>
      <p>Bienvenue <b>${username}</b></p>
      <a href="/" class="btn btn-secondary">Home</a>
      <a href="/logout" class="btn btn-logout">Logout</a>
    </div>
  `);
});

app.get("/logout", (req, res) => {
  const idToken = req.session.tokens?.id_token;

  req.session.destroy(() => {
    const redirect = encodeURIComponent(`http://localhost:${PORT}/`);
    if (!idToken) return res.redirect(`http://localhost:${PORT}/`);

    const url =
      `${issuerUrl}/protocol/openid-connect/logout` +
      `?id_token_hint=${encodeURIComponent(idToken)}` +
      `&post_logout_redirect_uri=${redirect}`;

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

app.listen(PORT, () => console.log(`Finance running on http://localhost:${PORT}`));