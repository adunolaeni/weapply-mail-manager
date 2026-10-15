/**
 * Microsoft personal mailboxes (Hotmail / Outlook / Live) via Microsoft Graph.
 * This module is deliberately separate from existing Google OAuth and IMAP code.
 * Microsoft Graph Mail.Read allows reading without changing isRead.
 */
import { randomUUID } from "node:crypto";
import type { Router } from "express";
import jwt from "jsonwebtoken";
import { simpleParser } from "mailparser";
import { query, logAudit } from "./db.js";
import { extractAuthArtifacts } from "./extraction.js";

const MICROSOFT_TENANT = "consumers"; // Hotmail / Outlook.com personal accounts
const MICROSOFT_SCOPES = "offline_access User.Read Mail.Read";
const MICROSOFT_TOKEN_ENDPOINT = `https://login.microsoftonline.com/${MICROSOFT_TENANT}/oauth2/v2.0/token`;
const GRAPH = "https://graph.microsoft.com/v1.0";

function config() {
  const clientId = process.env.MICROSOFT_CLIENT_ID;
  const clientSecret = process.env.MICROSOFT_CLIENT_SECRET;
  const redirectUri = process.env.MICROSOFT_REDIRECT_URI;
  if (!clientId || !clientSecret || !redirectUri) {
    throw new Error("Microsoft mailbox OAuth is not configured on this server.");
  }
  return { clientId, clientSecret, redirectUri };
}

function microsoftStateSecret(): string {
  // Dedicated server-side signing key derived from an already-required Microsoft secret.
  return `weapply4u-microsoft-oauth-state:${config().clientSecret}`;
}

async function exchangeMicrosoftToken(parameters: Record<string, string>) {
  const { clientId, clientSecret, redirectUri } = config();
  const response = await fetch(MICROSOFT_TOKEN_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
      ...parameters,
    }),
  });
  const payload = await response.json() as any;
  if (!response.ok || !payload.access_token) {
    const reason = typeof payload.error === "string" ? payload.error : "token_exchange_failed";
    const error: Error & { oauthError?: string } = new Error(`Microsoft authentication rejected the request (${reason}).`);
    error.oauthError = reason;
    throw error;
  }
  return payload;
}

function safeRedirect(res: any, success: boolean) {
  return res.redirect(success ? "/?oauth-client=success" : "/?oauth-client=error");
}

/** Add routes without changing existing Google authentication or login routes. */
export function registerMicrosoftMailboxRoutes(router: Router, authenticateToken: any, requireAdmin: any) {
  router.get("/clients/microsoft/oauth-link", authenticateToken, requireAdmin, (req: any, res) => {
    try {
      const { clientId, redirectUri } = config();
      const state = jwt.sign(
        { purpose: "microsoft-mailbox-connect", adminId: req.user.id, nonce: randomUUID() },
        microsoftStateSecret(),
        { expiresIn: "10m" }
      );
      const url = "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize?" +
        new URLSearchParams({
          client_id: clientId,
          response_type: "code",
          redirect_uri: redirectUri,
          response_mode: "query",
          scope: MICROSOFT_SCOPES,
          state,
        }).toString();
      res.json({ url });
    } catch {
      res.status(503).json({ error: "Microsoft email connection has not been configured yet." });
    }
  });

  router.get("/clients/microsoft/callback", async (req, res) => {
    const code = typeof req.query.code === "string" ? req.query.code : "";
    const state = typeof req.query.state === "string" ? req.query.state : "";
    if (!code || !state) return safeRedirect(res, false);

    try {
      const claims = jwt.verify(state, microsoftStateSecret()) as { purpose?: string; adminId?: string };
      if (claims.purpose !== "microsoft-mailbox-connect" || typeof claims.adminId !== "string") {
        return safeRedirect(res, false);
      }
      const admin = await query("SELECT id, email FROM users WHERE id = $1 AND role = 'ADMIN'", [claims.adminId]);
      if (!admin.rows.length) return safeRedirect(res, false);

      const tokens = await exchangeMicrosoftToken({ code, grant_type: "authorization_code", scope: MICROSOFT_SCOPES });
      if (!tokens.refresh_token || typeof tokens.refresh_token !== "string") {
        throw new Error("Microsoft did not provide an offline refresh token for this mailbox.");
      }

      const profileResponse = await fetch(`${GRAPH}/me?$select=id,displayName,mail,userPrincipalName`, {
        headers: { Authorization: `Bearer ${tokens.access_token}`, Accept: "application/json" },
      });
      if (!profileResponse.ok) throw new Error(`Microsoft profile request failed (${profileResponse.status}).`);
      const profile = await profileResponse.json() as any;
      const mailbox = String(profile.mail || profile.userPrincipalName || "").trim().toLowerCase();
      if (!mailbox.includes("@")) throw new Error("Microsoft did not return a valid mailbox address.");
      const displayName = String(profile.displayName || mailbox.split("@")[0]).slice(0, 255);
      const expiry = new Date(Date.now() + Number(tokens.expires_in || 3600) * 1000);

      // Do not turn a Google OAuth mailbox into a Microsoft mailbox by accident.
      const existing = await query("SELECT id, provider, auth_type FROM clients WHERE LOWER(email) = $1", [mailbox]);
      if (existing.rows.length) {
        if (existing.rows[0].provider === "google" && existing.rows[0].auth_type === "oauth") {
          throw new Error("This address is already connected through Google OAuth.");
        }
        await query(
          `UPDATE clients
           SET provider = 'microsoft', auth_type = 'oauth',
               imap_host = NULL, imap_port = NULL, encrypted_password = NULL, iv = NULL,
               oauth_access_token = $1, oauth_refresh_token = $2,
               oauth_token_expiry = $3, status = 'connected', last_synced_at = NOW()
           WHERE id = $4`,
          [tokens.access_token, tokens.refresh_token, expiry, existing.rows[0].id]
        );
      } else {
        await query(
          `INSERT INTO clients
            (id, client_name, email, provider, auth_type, oauth_access_token, oauth_refresh_token, oauth_token_expiry, status)
           VALUES ($1, $2, $3, 'microsoft', 'oauth', $4, $5, $6, 'connected')`,
          [`client_${randomUUID()}`, displayName, mailbox, tokens.access_token, tokens.refresh_token, expiry]
        );
      }
      // An audit-log collision must not falsely report a successful mailbox connection as a failure.
      await logAudit(admin.rows[0].email, "ADMIN", `Connected Microsoft mailbox: ${mailbox}`, "SUCCESS")
        .catch((err) => console.warn("[Microsoft] Connection audit write failed:", err?.message));
      return safeRedirect(res, true);
    } catch (err: any) {
      // Never log Microsoft credentials, auth codes or refresh tokens.
      console.error("[Microsoft] Mailbox connection failed:", err?.message || "Unknown error");
      return safeRedirect(res, false);
    }
  });
}

/** Refresh Microsoft access tokens when close to expiry, persist rotated refresh tokens. */
async function getMicrosoftAccessToken(client: any): Promise<string> {
  if (client.status === "reauth_required") return "";
  const expires = client.oauth_token_expiry ? new Date(client.oauth_token_expiry).getTime() : 0;
  if (client.oauth_access_token && Date.now() + 5 * 60_000 < expires) return client.oauth_access_token;
  if (!client.oauth_refresh_token) {
    await query("UPDATE clients SET status = 'reauth_required' WHERE id = $1", [client.id]);
    return "";
  }
  try {
    const data = await exchangeMicrosoftToken({
      grant_type: "refresh_token", refresh_token: client.oauth_refresh_token, scope: MICROSOFT_SCOPES,
    });
    const expiry = new Date(Date.now() + Number(data.expires_in || 3600) * 1000);
    await query(
      `UPDATE clients SET oauth_access_token = $1,
        oauth_refresh_token = COALESCE($2, oauth_refresh_token), oauth_token_expiry = $3,
        status = 'connected' WHERE id = $4`,
      [data.access_token, data.refresh_token || null, expiry, client.id]
    );
    return data.access_token;
  } catch (err: any) {
    if (err?.oauthError === "invalid_grant" || err?.oauthError === "interaction_required") {
      await query("UPDATE clients SET status = 'reauth_required', oauth_access_token = NULL WHERE id = $1", [client.id]);
      return "";
    }
    throw err;
  }
}

/** Uses the same separate duplicate-tracking table and 30-minute retention as Gmail. */
async function saveMicrosoftMessage(client: any, message: any): Promise<boolean> {
  if (!message?.id || !message.receivedDateTime) return false;
  const receivedAt = new Date(message.receivedDateTime);
  if (Number.isNaN(receivedAt.getTime())) return false;
  const expiresAt = new Date(receivedAt.getTime() + 30 * 60_000);
  if (expiresAt.getTime() <= Date.now()) return false;
  const marker = `microsoft:${message.id}`;
  const known = await query(
    "SELECT 1 FROM synchronized_messages WHERE client_id = $1 AND provider_message_id = $2",
    [client.id, marker]
  );
  if (known.rows.length) return false;

  const content = String(message.body?.content || "");
  const isHtml = String(message.body?.contentType || "").toLowerCase() === "html";
  // Mailparser gives the OTP classifier readable text, retaining URLs from HTML anchors.
  const parsed = await simpleParser(
    `MIME-Version: 1.0\r\nContent-Type: ${isHtml ? "text/html" : "text/plain"}; charset=utf-8\r\n\r\n${content}`
  );
  const bodyText = parsed.text || content;
  const bodyHtml = isHtml ? content : (parsed.html && typeof parsed.html === "string" ? parsed.html : content);
  const senderEmail = String(message.from?.emailAddress?.address || "");
  const senderName = String(message.from?.emailAddress?.name || "");
  const sender = senderName ? `${senderName} <${senderEmail}>` : (senderEmail || "Unknown Sender");
  const subject = String(message.subject || "(No Subject)");
  const recipient = client.email;
  const artifact = extractAuthArtifacts(subject, bodyText, senderEmail);

  // Existing rows are checked first to support switching a previously-added IMAP mailbox to Graph.
  const sameEmail = await query(
    `SELECT id FROM emails WHERE client_id = $1 AND sender = $2
       AND recipient_email = $3 AND subject = $4 AND received_at = $5 LIMIT 1`,
    [client.id, sender, recipient, subject, receivedAt.toISOString()]
  );
  if (sameEmail.rows.length) {
    await query(
      "INSERT INTO synchronized_messages (client_id, provider_message_id) VALUES ($1,$2) ON CONFLICT DO NOTHING",
      [client.id, marker]
    );
    return false;
  }

  const saved = await query(
    `WITH new_message AS (
       INSERT INTO synchronized_messages (client_id, provider_message_id)
       VALUES ($1,$2) ON CONFLICT DO NOTHING RETURNING client_id
     )
     INSERT INTO emails
       (id, client_id, sender, recipient_email, subject, full_body_html,
        full_body_text, otp_code, verification_link, received_at, expires_at,
        classification_status, visibility_level)
     SELECT $3, client_id, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14
     FROM new_message RETURNING id`,
    [client.id, marker, `email_${randomUUID()}`, sender, recipient, subject,
      bodyHtml, bodyText, artifact.otp_code, artifact.verification_link,
      receivedAt.toISOString(), expiresAt.toISOString(),
      artifact.classification_status, artifact.visibility_level]
  );
  return (saved.rowCount || 0) > 0;
}

/** Graph GET calls are read-only: no PATCH, no isRead updates. */
export async function syncMicrosoftClient(client: any): Promise<void> {
  const accessToken = await getMicrosoftAccessToken(client);
  if (!accessToken) return; // Reauthorization needed; stop retrying rejected tokens.
  const since = new Date(Date.now() - 60 * 60_000).toISOString();
  let processed = 0;
  for (const folder of ["inbox", "junkemail"]) {
    const params = new URLSearchParams({
      "$filter": `receivedDateTime ge ${since}`,
      "$orderby": "receivedDateTime desc",
      "$select": "id,subject,receivedDateTime,from,body,toRecipients",
      "$top": "50",
    });
    let next: string | null = `${GRAPH}/me/mailFolders/${folder}/messages?${params.toString()}`;
    let pages = 0;
    while (next && pages++ < 10) {
      // Do not follow arbitrary URLs supplied by the server or message contents.
      if (!next.startsWith(`${GRAPH}/me/`)) throw new Error("Unexpected Microsoft Graph pagination URL.");
      const response = await fetch(next, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: "application/json",
          Prefer: 'IdType="ImmutableId"',
        },
      });
      if (response.status === 401) {
        // Access token was rejected unexpectedly. Refresh on the next sync.
        await query("UPDATE clients SET oauth_token_expiry = NOW() WHERE id = $1", [client.id]);
        throw new Error("Microsoft Graph denied access; token will be renewed on next poll.");
      }
      if (!response.ok) {
        throw new Error(`Microsoft Graph mailbox fetch failed (${response.status}) for ${folder}.`);
      }
      const payload = await response.json() as any;
      for (const message of payload.value || []) {
        if (await saveMicrosoftMessage(client, message)) processed++;
      }
      next = typeof payload["@odata.nextLink"] === "string" ? payload["@odata.nextLink"] : null;
    }
  }
  await query(
    `UPDATE clients SET last_synced_at = NOW(), total_emails_processed = total_emails_processed + $1,
       status = 'connected' WHERE id = $2`,
    [processed, client.id]
  );
  if (processed) {
    await logAudit("SYSTEM", "DAEMON", `Microsoft mailbox synchronized: ${client.email}; ${processed} new emails.`, "SUCCESS")
      .catch((err) => console.warn("[Microsoft] Sync audit write failed:", err?.message));
  }
}
