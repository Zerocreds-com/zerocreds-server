'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const https = require('https');

const AGENT_TOKENS_DIR = path.join(os.homedir(), 'agent-tokens');

// ── local_file ────────────────────────────────────────────────────────────────
// destination: { type: "local_file", uid: "123", filename: "github" }
// Writes JSON to ~/agent-tokens/{uid}/{filename}
async function saveLocalFile(destination, fields) {
  const { uid, filename } = destination;
  if (!uid || !filename) throw new Error('local_file: missing uid or filename');
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(filename)) throw new Error('local_file: invalid filename');
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(String(uid))) throw new Error('local_file: invalid uid');

  const dir = path.join(AGENT_TOKENS_DIR, String(uid));
  fs.mkdirSync(dir, { recursive: true });
  const data = Object.keys(fields).length === 1 && fields[Object.keys(fields)[0]] !== undefined
    ? { value: fields[Object.keys(fields)[0]], ...fields }
    : fields;
  fs.writeFileSync(path.join(dir, filename), JSON.stringify(data, null, 2), { mode: 0o600 });
}

// ── gcp_secret_manager ────────────────────────────────────────────────────────
// destination: { type: "gcp_secret_manager", secret: "projects/P/secrets/S",
//                credentials: "<base64 SA key JSON>" }
// Uses secretVersionAdder role — write-only by IAM design.
// The SA key is embedded in the destination config so the calling agent controls which key.
async function saveGcpSecret(destination, fields) {
  const { secret, credentials } = destination;
  if (!secret || !credentials) throw new Error('gcp_secret_manager: missing secret or credentials');

  const keyJson = JSON.parse(Buffer.from(credentials, 'base64').toString());
  const token = await getGcpAccessToken(keyJson);

  const payload = Buffer.from(JSON.stringify(fields)).toString('base64');
  const url = `https://secretmanager.googleapis.com/v1/${secret}:addVersion`;

  await httpPost(url, { payload: { data: payload } }, token);
}

// Minimal JWT-based GCP token — no SDK dependency
function getGcpAccessToken(keyJson) {
  return new Promise((resolve, reject) => {
    const now = Math.floor(Date.now() / 1000);
    const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
    const claim = Buffer.from(JSON.stringify({
      iss: keyJson.client_email,
      scope: 'https://www.googleapis.com/auth/cloud-platform',
      aud: 'https://oauth2.googleapis.com/token',
      iat: now,
      exp: now + 3600,
    })).toString('base64url');

    const { createSign } = require('crypto');
    const sign = createSign('RSA-SHA256');
    sign.update(`${header}.${claim}`);
    const sig = sign.sign(keyJson.private_key, 'base64url');
    const jwt = `${header}.${claim}.${sig}`;

    const body = `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`;
    const req = https.request({
      hostname: 'oauth2.googleapis.com',
      path: '/token',
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) },
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const d = JSON.parse(data);
          if (!d.access_token) return reject(new Error('GCP auth failed: ' + data));
          resolve(d.access_token);
        } catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.end(body);
  });
}

// ── aws_secrets_manager ───────────────────────────────────────────────────────
// destination: { type: "aws_secrets_manager", secret_id: "arn:aws:...",
//                region: "us-east-1",
//                access_key_id: "...", secret_access_key: "..." }
// Uses PutSecretValue — pair with IAM policy that omits GetSecretValue.
async function saveAwsSecret(destination, fields) {
  const { secret_id, region, access_key_id, secret_access_key } = destination;
  if (!secret_id || !region || !access_key_id || !secret_access_key) {
    throw new Error('aws_secrets_manager: missing required fields');
  }
  const { createHmac, createHash } = require('crypto');

  const body = JSON.stringify({ SecretId: secret_id, SecretString: JSON.stringify(fields) });
  const service = 'secretsmanager';
  const host = `${service}.${region}.amazonaws.com`;
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:\-]|\.\d{3}/g, '').slice(0, 15) + 'Z';
  const dateStamp = amzDate.slice(0, 8);

  const canonicalHeaders = `content-type:application/x-amz-json-1.1\nhost:${host}\nx-amz-date:${amzDate}\nx-amz-target:secretsmanager.PutSecretValue\n`;
  const signedHeaders = 'content-type;host;x-amz-date;x-amz-target';
  const payloadHash = createHash('sha256').update(body).digest('hex');
  const canonicalRequest = `POST\n/\n\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`;

  const algorithm = 'AWS4-HMAC-SHA256';
  const credScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = `${algorithm}\n${amzDate}\n${credScope}\n${createHash('sha256').update(canonicalRequest).digest('hex')}`;

  const sign = (key, msg) => createHmac('sha256', key).update(msg).digest();
  const sigKey = sign(sign(sign(sign('AWS4' + secret_access_key, dateStamp), region), service), 'aws4_request');
  const signature = createHmac('sha256', sigKey).update(stringToSign).digest('hex');

  const authorization = `${algorithm} Credential=${access_key_id}/${credScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  await httpPost(`https://${host}/`, JSON.parse(body), null, {
    'Content-Type': 'application/x-amz-json-1.1',
    'X-Amz-Date': amzDate,
    'X-Amz-Target': 'secretsmanager.PutSecretValue',
    Authorization: authorization,
  });
}

// ── vault ─────────────────────────────────────────────────────────────────────
// destination: { type: "vault", address: "https://vault.example.com",
//                path: "secret/data/myapp", token: "hvs.xxx" }
// Vault policy should allow create+update but NOT read.
async function saveVault(destination, fields) {
  const { address, path: vaultPath, token: vaultToken } = destination;
  if (!address || !vaultPath || !vaultToken) throw new Error('vault: missing address, path, or token');

  await httpPost(
    `${address}/v1/${vaultPath.replace(/^\//, '')}`,
    { data: fields },
    null,
    { 'X-Vault-Token': vaultToken },
  );
}

// ── http_post ─────────────────────────────────────────────────────────────────
// destination: { type: "http_post", url: "https://example.com/store-creds" }
// POSTs fields as JSON to the given URL. HTTPS only.
async function saveHttpPost(destination, fields) {
  const { url } = destination;
  if (!url) throw new Error('http_post: missing url');
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:') throw new Error('http_post: url must use https');
  await httpPost(url, fields);
}

// ── dispatcher ────────────────────────────────────────────────────────────────
async function saveToDestination(destination, fields) {
  switch (destination.type) {
    case 'local_file':          return saveLocalFile(destination, fields);
    case 'http_post':           return saveHttpPost(destination, fields);
    case 'gcp_secret_manager':  return saveGcpSecret(destination, fields);
    case 'aws_secrets_manager': return saveAwsSecret(destination, fields);
    case 'vault':               return saveVault(destination, fields);
    default: throw new Error(`Unknown destination type: ${destination.type}`);
  }
}

// ── helpers ───────────────────────────────────────────────────────────────────
function httpPost(url, bodyObj, bearerToken, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(bodyObj);
    const parsed = new URL(url);
    const headers = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body),
      ...extraHeaders,
    };
    if (bearerToken) headers['Authorization'] = `Bearer ${bearerToken}`;

    const req = https.request({
      hostname: parsed.hostname,
      port: parsed.port || 443,
      path: parsed.pathname + parsed.search,
      method: 'POST',
      headers,
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        if (res.statusCode >= 400) return reject(new Error(`HTTP ${res.statusCode}: ${data}`));
        resolve(data);
      });
    });
    req.on('error', reject);
    req.end(body);
  });
}

module.exports = { saveToDestination };
