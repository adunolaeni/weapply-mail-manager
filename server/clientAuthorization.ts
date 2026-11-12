/**
 * Client self-service mailbox authorization.
 * Entirely separate from existing staff login, admin OAuth callbacks and polling.
 * A short-lived, one-use invitation only permits connection of its assigned mailbox.
 */
import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { Router } from "express";
import { query, withTransaction } from "./db.js";

const GOOGLE_SCOPE = "https://www.googleapis.com/auth/gmail.readonly";
const MICROSOFT_SCOPE = "offline_access User.Read Mail.Read";
const MAX_ATTEMPTS = 10;
const INVITE_LIFETIME_MS = 24 * 60 * 60 * 1000;
const OAUTH_LIFETIME_MS = 10 * 60 * 1000;
const HASH_PATTERN = /^[a-f0-9]{64}$/;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
type MailProvider = "google" | "microsoft";

const hash = (s: string) => createHash("sha256").update(s).digest("hex");
const secret = () => randomBytes(32).toString("base64url");
const normalizeEmail = (s: string) => s.trim().toLowerCase();
function isProvider(v: unknown): v is MailProvider { return v === "google" || v === "microsoft"; }

function baseUrl() {
  const raw = process.env.CLIENT_AUTH_BASE_URL || process.env.RENDER_EXTERNAL_URL;
  if (!raw) throw new Error("CLIENT_AUTH_BASE_URL or RENDER_EXTERNAL_URL is required.");
  const origin = new URL(raw).origin;
  if (process.env.NODE_ENV === "production" && !origin.startsWith("https://")) {
    throw new Error("Client authorization requires HTTPS in production.");
  }
  return origin;
}
function callbackUrl(provider: MailProvider) {
  return `${baseUrl()}/api/client-connect/${provider}/callback`;
}
function pgErrorMessage(err: any): string {
  // Errors are logged server-side without OAuth codes, access or refresh tokens.
  return typeof err?.message === "string" ? err.message.slice(0, 220) : "unknown";
}
function noStore(res: any) {
  res.setHeader("Cache-Control", "no-store, max-age=0");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Content-Type-Options", "nosniff");
}
function sameOrigin(req: any) {
  const origin = req.get("origin");
  if (!origin) return true; // Non-browser clients have no ambient user credentials.
  try { return new URL(origin).origin === baseUrl(); } catch { return false; }
}
const publicRate = new Map<string, { count: number; until: number }>();
function rateLimit(req: any, res: any, next: any) {
  const key = String(req.ip || "unknown");
  const now = Date.now();
  if (publicRate.size > 3000) {
    for (const [k, v] of publicRate) if (v.until < now) publicRate.delete(k);
  }
  const r = publicRate.get(key);
  if (!r || r.until < now) { publicRate.set(key, {count: 1, until: now + 60_000}); return next(); }
  if (r.count >= 60) return res.status(429).json({error: "Too many requests. Try again shortly."});
  r.count++;
  next();
}

async function getInvitation(token: string) {
  // Never store or list the raw invitation token in PostgreSQL.
  if (token.length < 32 || token.length > 128 || !/^[A-Za-z0-9_-]+$/.test(token)) return null;
  const result = await query(
    `SELECT * FROM client_authorization_invites WHERE token_hash = $1 LIMIT 1`, [hash(token)]
  );
  return result.rows[0] || null;
}
function invitationStatus(inv: any) {
  if (inv.status === "pending" && new Date(inv.expires_at).getTime() <= Date.now()) return "expired";
  return inv.status;
}
function cleanInvitation(inv: any) {
  return {
    id: inv.id, client_name: inv.client_name, email: inv.assigned_email,
    provider: inv.provider, status: invitationStatus(inv),
    created_at: inv.created_at, expires_at: inv.expires_at,
    completed_at: inv.completed_at || null, mailbox_status: inv.mailbox_status || null,
  };
}
function eligibleExisting(existing: any, provider: MailProvider) {
  // Never silently replace a Google account with Microsoft, or vice versa.
  if (!existing) return true;
  if (existing.provider === provider && existing.auth_type === "oauth") return true;
  // Authorized migration from the old Microsoft password/IMAP connection only.
  if (provider === "microsoft" && existing.auth_type === "imap" &&
    ["other", "hotmail", "outlook", "microsoft"].includes(existing.provider)) return true;
  return false;
}

function startAuthorizeUrl(provider: MailProvider, email: string, state: string, challenge: string) {
  if (provider === "google") {
    if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) throw new Error("Google OAuth isn't configured.");
    return "https://accounts.google.com/o/oauth2/v2/auth?" + new URLSearchParams({
      client_id: process.env.GOOGLE_CLIENT_ID,
      redirect_uri: callbackUrl("google"),
      response_type: "code", scope: GOOGLE_SCOPE, access_type: "offline",
      prompt: "consent select_account", login_hint: email,
      state, code_challenge: challenge, code_challenge_method: "S256",
    }).toString();
  }
  if (!process.env.MICROSOFT_CLIENT_ID || !process.env.MICROSOFT_CLIENT_SECRET) throw new Error("Microsoft OAuth isn't configured.");
  return "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize?" + new URLSearchParams({
    client_id: process.env.MICROSOFT_CLIENT_ID,
    redirect_uri: callbackUrl("microsoft"),
    response_type: "code", response_mode: "query", scope: MICROSOFT_SCOPE,
    prompt: "select_account", login_hint: email,
    state, code_challenge: challenge, code_challenge_method: "S256",
  }).toString();
}

async function exchangeAndVerify(provider: MailProvider, code: string, verifier: string) {
  const isGoogle = provider === "google";
  const tokenEndpoint = isGoogle ? "https://oauth2.googleapis.com/token" :
    "https://login.microsoftonline.com/consumers/oauth2/v2.0/token";
  const body = new URLSearchParams({
    client_id: (isGoogle ? process.env.GOOGLE_CLIENT_ID : process.env.MICROSOFT_CLIENT_ID) || "",
    client_secret: (isGoogle ? process.env.GOOGLE_CLIENT_SECRET : process.env.MICROSOFT_CLIENT_SECRET) || "",
    redirect_uri: callbackUrl(provider),
    grant_type: "authorization_code", code, code_verifier: verifier,
  });
  const tokenResponse = await fetch(tokenEndpoint, {
    method: "POST", headers: {"Content-Type": "application/x-www-form-urlencoded"}, body,
    signal: AbortSignal.timeout(20_000),
  });
  if (!tokenResponse.ok) throw new Error(`${provider} rejected authorization (${tokenResponse.status}).`);
  const tokens = await tokenResponse.json() as any;
  if (!tokens.access_token || !tokens.refresh_token || !Number(tokens.expires_in)) {
    throw new Error("The email provider did not return renewable mailbox access. Please retry authorization.");
  }
  let identity: string;
  let displayName: string;
  if (isGoogle) {
    // Gmail's own profile endpoint proves both account identity and Gmail API access.
    const profileResponse = await fetch("https://gmail.googleapis.com/gmail/v1/users/me/profile", {
      headers: {Authorization: `Bearer ${tokens.access_token}`},
      signal: AbortSignal.timeout(20_000),
    });
    if (!profileResponse.ok) throw new Error("Google did not confirm Gmail read access.");
    const profile = await profileResponse.json() as any;
    identity = normalizeEmail(String(profile.emailAddress || ""));
    displayName = identity.split("@")[0];
    // Confirm message-read access as well as the account identity.
    const messagesResponse = await fetch("https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=1", {
      headers: {Authorization: `Bearer ${tokens.access_token}`},
      signal: AbortSignal.timeout(20_000),
    });
    if (!messagesResponse.ok) throw new Error("Google did not confirm mailbox message-read access.");
  } else {
    const profileResponse = await fetch("https://graph.microsoft.com/v1.0/me?$select=id,displayName,mail,userPrincipalName", {
      headers: {Authorization: `Bearer ${tokens.access_token}`},
      signal: AbortSignal.timeout(20_000),
    });
    if (!profileResponse.ok) throw new Error("Microsoft did not confirm the account identity.");
    const profile = await profileResponse.json() as any;
    identity = normalizeEmail(String(profile.mail || profile.userPrincipalName || ""));
    displayName = String(profile.displayName || identity.split("@")[0]);
    // Verify access to mail, rather than inferring it from a successful sign-in.
    const mailboxResponse = await fetch("https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages?$top=1&$select=id", {
      headers: {Authorization: `Bearer ${tokens.access_token}`},
      signal: AbortSignal.timeout(20_000),
    });
    if (!mailboxResponse.ok) throw new Error("Microsoft did not confirm mailbox read access.");
  }
  if (!EMAIL_PATTERN.test(identity)) throw new Error("The provider did not return a valid mailbox address.");
  return {
    email: identity, name: displayName.slice(0, 150), accessToken: String(tokens.access_token),
    refreshToken: String(tokens.refresh_token),
    expires: new Date(Date.now() + Number(tokens.expires_in) * 1000),
  };
}

async function saveAuthorizedMailbox(inv: any, mailbox: Awaited<ReturnType<typeof exchangeAndVerify>>) {
  if (mailbox.email !== inv.assigned_email) {
    throw new Error("The authorized email address does not match the assigned invitation.");
  }
  await withTransaction(async (tx) => {
    // Lock invitation and recheck after the remote OAuth exchange; an admin may have revoked it.
    const stillValid = await tx.query(
      `SELECT id, status, expires_at, existing_client_id FROM client_authorization_invites WHERE id = $1 FOR UPDATE`,
      [inv.id]
    );
    if (!stillValid.rows.length || stillValid.rows[0].status !== "pending" ||
      new Date(stillValid.rows[0].expires_at).getTime() <= Date.now()) {
      throw new Error("This invitation is no longer available.");
    }
    const match = await tx.query(
      "SELECT id, provider, auth_type, email FROM clients WHERE LOWER(email) = $1 FOR UPDATE",
      [mailbox.email]
    );
    const existing = match.rows[0];
    if (existing && (!eligibleExisting(existing, inv.provider) ||
      (inv.existing_client_id && inv.existing_client_id !== existing.id))) {
      throw new Error("Mailbox is already assigned to a different connection.");
    }
    if (inv.existing_client_id && !existing) {
      throw new Error("The original mailbox connection has changed. Request a new link.");
    }
    let clientId: string;
    if (existing) {
      clientId = existing.id;
      await tx.query(
        `UPDATE clients SET provider = $1, auth_type = 'oauth',
          imap_host = NULL, imap_port = NULL, encrypted_password = NULL, iv = NULL,
          oauth_access_token = $2, oauth_refresh_token = $3, oauth_token_expiry = $4,
          status = 'connected', last_synced_at = NOW()
         WHERE id = $5`,
        [inv.provider, mailbox.accessToken, mailbox.refreshToken, mailbox.expires, clientId]
      );
    } else {
      clientId = `client_${randomUUID()}`;
      await tx.query(
        `INSERT INTO clients (id, client_name, email, provider, auth_type,
           oauth_access_token, oauth_refresh_token, oauth_token_expiry, status)
         VALUES ($1, $2, $3, $4, 'oauth', $5, $6, $7, 'connected')`,
        [clientId, inv.client_name, mailbox.email, inv.provider,
          mailbox.accessToken, mailbox.refreshToken, mailbox.expires]
      );
    }
    await tx.query(
      `UPDATE client_authorization_invites
       SET status = 'connected', completed_at = NOW(), existing_client_id = $2,
           oauth_state_hash = NULL, code_verifier = NULL, attempt_expires_at = NULL
       WHERE id = $1`, [inv.id, clientId]
    );
  });
}

function finish(res: any, status: "success" | "failed", reason?: string) {
  noStore(res);
  const params = new URLSearchParams({status});
  if (reason) params.set("reason", reason);
  res.redirect(303, `/connect/result?${params.toString()}`);
}

export function registerClientAuthorizationRoutes(router: Router, authenticateToken: any, requireAdmin: any) {
  // Deployment safety: feature is OFF until explicitly enabled in Render.
  const enabled = process.env.CLIENT_AUTH_ENABLED === "true";
  router.get("/client-authorization/feature", authenticateToken, requireAdmin, (_req, res) => {
    noStore(res);
    res.json({enabled});
  });
  if (!enabled) return;

  // Admin creates an invitation; no client ever receives a staff session.
  router.post("/client-authorization/invitations", authenticateToken, requireAdmin, async (req: any, res) => {
    noStore(res);
    const clientName = typeof req.body?.client_name === "string" ? req.body.client_name.trim() : "";
    const email = typeof req.body?.email === "string" ? normalizeEmail(req.body.email) : "";
    const provider = req.body?.provider;
    if (!clientName || clientName.length > 150 || email.length > 254 || !EMAIL_PATTERN.test(email) || !isProvider(provider)) {
      return res.status(400).json({error: "Enter a valid client name, email and provider."});
    }
    try {
      const current = await query("SELECT id, provider, auth_type FROM clients WHERE LOWER(email) = $1", [email]);
      const existing = current.rows[0];
      if (!eligibleExisting(existing, provider)) {
        return res.status(409).json({error: "This mailbox uses a different provider. Its existing connection was not changed."});
      }
      const token = secret();
      const id = randomUUID();
      const expiry = new Date(Date.now() + INVITE_LIFETIME_MS);
      await query(
        `INSERT INTO client_authorization_invites
           (id, token_hash, client_name, assigned_email, provider, existing_client_id,
            created_by, status, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', $8)`,
        [id, hash(token), clientName, email, provider, existing?.id || null, req.user.id, expiry]
      );
      // Invalidate earlier unused links for the same address and provider.
      await query(
        `UPDATE client_authorization_invites SET status = 'revoked', oauth_state_hash = NULL,
             code_verifier = NULL, attempt_expires_at = NULL
         WHERE assigned_email = $1 AND provider = $2 AND status = 'pending' AND id <> $3`,
        [email, provider, id]
      );
      return res.status(201).json({
        invitation: {id, client_name: clientName, email, provider, status: "pending", expires_at: expiry.toISOString()},
        link: `${baseUrl()}/connect/${token}`,
      });
    } catch (err) {
      console.error("[Client authorization] Failed to create invitation:", pgErrorMessage(err));
      return res.status(500).json({error: "Unable to create the authorization link."});
    }
  });

  router.get("/client-authorization/invitations", authenticateToken, requireAdmin, async (_req, res) => {
    noStore(res);
    try {
      const data = await query(
        `SELECT i.id, i.client_name, i.assigned_email, i.provider, i.status,
                i.created_at, i.expires_at, i.completed_at, c.status AS mailbox_status
         FROM client_authorization_invites i
         LEFT JOIN clients c ON c.id = i.existing_client_id
         ORDER BY i.created_at DESC LIMIT 100`
      );
      return res.json(data.rows.map(cleanInvitation));
    } catch (err) {
      console.error("[Client authorization] List error:", pgErrorMessage(err));
      return res.status(500).json({error: "Unable to retrieve authorization requests."});
    }
  });

  router.post("/client-authorization/invitations/:id/revoke", authenticateToken, requireAdmin, async (req, res) => {
    noStore(res);
    if (!/^[0-9a-f-]{36}$/i.test(req.params.id)) return res.status(400).json({error: "Invalid invitation."});
    try {
      const updated = await query(
        `UPDATE client_authorization_invites
         SET status = 'revoked', oauth_state_hash = NULL, code_verifier = NULL, attempt_expires_at = NULL
         WHERE id = $1 AND status = 'pending' RETURNING id`, [req.params.id]
      );
      if (!updated.rows.length) return res.status(409).json({error: "This invitation is no longer pending."});
      return res.json({revoked: true});
    } catch { return res.status(500).json({error: "Unable to revoke the invitation."}); }
  });

  router.get("/client-authorization/invitation/:token", rateLimit, async (req, res) => {
    noStore(res);
    try {
      const inv = await getInvitation(req.params.token);
      if (!inv) return res.status(404).json({error: "This invitation link is invalid."});
      return res.json({client_name: inv.client_name, email: inv.assigned_email,
        provider: inv.provider, status: invitationStatus(inv), expires_at: inv.expires_at});
    } catch { return res.status(503).json({error: "Unable to verify the invitation right now."}); }
  });

  router.post("/client-authorization/invitation/:token/start", rateLimit, async (req, res) => {
    noStore(res);
    if (!sameOrigin(req)) return res.status(403).json({error: "This request must come from the authorization page."});
    if (req.body?.consent !== true) return res.status(400).json({error: "Please review and accept the access request."});
    try {
      const inv = await getInvitation(req.params.token);
      if (!inv || invitationStatus(inv) !== "pending") return res.status(410).json({error: "This invitation has expired or is no longer active."});
      if (inv.attempts >= MAX_ATTEMPTS) return res.status(429).json({error: "Too many attempts. Ask your administrator for a new link."});
      const state = secret();
      const codeVerifier = secret();
      const challenge = createHash("sha256").update(codeVerifier).digest("base64url");
      const url = startAuthorizeUrl(inv.provider, inv.assigned_email, state, challenge);
      const updated = await query(
        `UPDATE client_authorization_invites
           SET oauth_state_hash = $1, code_verifier = $2,
               attempt_expires_at = $3, attempts = attempts + 1,
               consented_at = COALESCE(consented_at, NOW())
         WHERE id = $4 AND status = 'pending' AND expires_at > NOW() AND attempts < $5 RETURNING id`,
        [hash(state), codeVerifier, new Date(Date.now() + OAUTH_LIFETIME_MS), inv.id, MAX_ATTEMPTS]
      );
      if (!updated.rows.length) return res.status(410).json({error: "This invitation is no longer available."});
      return res.json({url});
    } catch (err) {
      console.error("[Client authorization] Start error:", pgErrorMessage(err));
      return res.status(503).json({error: "Unable to start authorization. Please try again."});
    }
  });

  for (const provider of ["google", "microsoft"] as const) {
    router.get(`/client-connect/${provider}/callback`, async (req, res) => {
      noStore(res);
      const state = typeof req.query.state === "string" ? req.query.state : "";
      const code = typeof req.query.code === "string" ? req.query.code : "";
      if (state.length < 32 || state.length > 128 || !/^[A-Za-z0-9_-]+$/.test(state)) {
        return finish(res, "failed", "invalid");
      }
      try {
        // Atomically consume the OAuth state before exchanging tokens (replay protection).
        const match = await withTransaction(async (tx) => {
          const claim = await tx.query(
            `SELECT id, client_name, assigned_email, provider, existing_client_id, code_verifier
             FROM client_authorization_invites
             WHERE oauth_state_hash = $1 AND provider = $2 AND status = 'pending'
               AND expires_at > NOW() AND attempt_expires_at > NOW()
             FOR UPDATE`,
            [hash(state), provider]
          );
          if (!claim.rows.length) return claim;
          await tx.query(
            `UPDATE client_authorization_invites
             SET oauth_state_hash = NULL, code_verifier = NULL, attempt_expires_at = NULL
             WHERE id = $1`, [claim.rows[0].id]
          );
          return claim;
        });
        if (!match.rows.length || !code) return finish(res, "failed", code ? "invalid" : "cancelled");
        const inv = match.rows[0];
        if (!inv.code_verifier) return finish(res, "failed", "retry");
        const verified = await exchangeAndVerify(provider, code, inv.code_verifier);
        await saveAuthorizedMailbox(inv, verified);
        return finish(res, "success");
      } catch (err) {
        console.error("[Client authorization] OAuth callback error:", pgErrorMessage(err));
        return finish(res, "failed", "retry");
      }
    });
  }
}
