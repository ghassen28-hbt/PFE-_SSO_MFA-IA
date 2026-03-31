const { Issuer } = require("openid-client");

// --- helpers JWT (sans librairie) ---
function base64UrlDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = str.length % 4;
  if (pad) str += "=".repeat(4 - pad);
  return Buffer.from(str, "base64").toString("utf8");
}

function decodeJwtPayload(jwt) {
  if (!jwt || typeof jwt !== "string" || jwt.split(".").length < 2) return null;
  const payload = jwt.split(".")[1];
  try {
    return JSON.parse(base64UrlDecode(payload));
  } catch {
    return null;
  }
}

function extractRealmRoles(accessToken) {
  const payload = decodeJwtPayload(accessToken);
  const roles = payload?.realm_access?.roles;
  return Array.isArray(roles) ? roles : [];
}

// --- OIDC client builder ---
async function buildClient({ kcBaseUrl, realm, clientId, clientSecret, redirectUri }) {
  const issuerUrl = `${kcBaseUrl}/realms/${realm}`;
  const issuer = await Issuer.discover(`${issuerUrl}/.well-known/openid-configuration`);

  const client = new issuer.Client({
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uris: [redirectUri],
    response_types: ["code"],
  });

  return { client, issuerUrl };
}

module.exports = { buildClient, extractRealmRoles };