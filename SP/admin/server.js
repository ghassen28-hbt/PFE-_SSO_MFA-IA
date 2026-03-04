const express = require("express");
const session = require("express-session");
const dotenv = require("dotenv");
const { buildClient, extractRealmRoles } = require("../shared/oidc");

dotenv.config();

const app = express();
const PORT = 4001;

const KC_BASE_URL = process.env.KC_BASE_URL || "http://localhost:8081";
const KC_REALM = process.env.KC_REALM || "PFE-SSO";

const CLIENT_ID = process.env.ADMIN_CLIENT_ID || "admin-console-client-1";
const CLIENT_SECRET = process.env.ADMIN_CLIENT_SECRET;
const REDIRECT_URI = `http://localhost:${PORT}/callback`;

if (!CLIENT_SECRET) {
  console.error("ADMIN_CLIENT_SECRET missing in .env");
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
    .btn-logout { background-color: #dc3545; }
    .btn-logout:hover { background-color: #c82333; transform: translateY(-2px); }
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
  res.redirect(client.authorizationUrl({ scope: "openid profile email" }));
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

  const payload = JSON.parse(Buffer.from(tokenSet.access_token.split(".")[1], "base64").toString("utf8"));
console.log("TOKEN realm_access:", payload.realm_access);
console.log("TOKEN resource_access:", payload.resource_access);
console.log("EXTRACTED ROLES:", roles);

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

app.listen(PORT, () => console.log(`Admin running on http://localhost:${PORT}`));