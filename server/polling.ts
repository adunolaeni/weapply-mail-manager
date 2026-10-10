import dns from "dns";
import { randomUUID } from "node:crypto";
dns.setDefaultResultOrder("ipv4first");

import { ImapFlow } from "imapflow";
import { simpleParser } from "mailparser";
import { query, logAudit } from "./db.js";
import { decrypt } from "./crypto.js";
import { extractAuthArtifacts } from "./extraction.js";

// Keep track of exponential backoffs per client in milliseconds
// backoff levels: 90s -> 180s -> 360s -> max 600s
const backoffStates: Record<number, { current: number; nextAllowedTime: number }> = {};

function getBackoffState(clientId: number) {
  if (!backoffStates[clientId]) {
    backoffStates[clientId] = {
      current: 90000,
      nextAllowedTime: 0,
    };
  }
  return backoffStates[clientId];
}

function handleSuccess(clientId: number) {
  const state = getBackoffState(clientId);
  state.current = 90000;
  state.nextAllowedTime = Date.now() + 90000;
}

function handleFailure(clientId: number, error: any) {
  const state = getBackoffState(clientId);
  const errMsg = error?.message || String(error);
  const isNetworkError =
    errMsg.includes("ENOTFOUND") ||
    errMsg.includes("ECONNRESET") ||
    errMsg.includes("ETIMEDOUT") ||
    errMsg.includes("EAI_AGAIN") ||
    error?.code === "ENOTFOUND" ||
    error?.code === "ECONNRESET" ||
    error?.code === "ETIMEDOUT" ||
    error?.code === "EAI_AGAIN";

  if (isNetworkError) {
    console.log(`[Polling] Network error detected for client ${clientId}. Increasing backoff...`);
    // Backoff transitions: 90s (90000) -> 180s (180000) -> 360s (360000) -> max 600s (600000)
    state.current = Math.min(600000, state.current * 2);
    state.nextAllowedTime = Date.now() + state.current;
    console.log(`[Polling] Next sync allowed for client ${clientId} in ${state.current / 1000}s`);
  } else {
    // If it's an authorization error, keep it at 90s but mark client with proper status
    state.current = 90000;
    state.nextAllowedTime = Date.now() + 90000;
    console.warn(`[Polling] Authentication or processing error for client ${clientId}:`, error);
  }
}

// Auto-refresh OAuth tokens if near expiry
async function refreshOAuthTokenIfNeeded(client: any): Promise<string> {
  // Convert database timestamp to milliseconds epoch for comparison
  const expiry = client.oauth_token_expiry 
    ? new Date(client.oauth_token_expiry).getTime() 
    : 0;
  
  // If token expires in less than 5 minutes (300,000 ms), refresh it
  if (Date.now() + 300000 >= expiry && client.oauth_refresh_token) {
    console.log(`[OAuth] Refreshing token for client ${client.id} (${client.email})...`);
    try {
      const res = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: process.env.GOOGLE_CLIENT_ID || "",
          client_secret: process.env.GOOGLE_CLIENT_SECRET || "",
          refresh_token: client.oauth_refresh_token,
          grant_type: "refresh_token",
        }),
      });

      if (!res.ok) {
        const errText = await res.text();
        
        // If refresh fails with 401, refresh token is invalid - mark for reauth
        if (res.status === 401) {
          await query(
            `UPDATE clients SET status = 'reauth_required', oauth_access_token = NULL WHERE id = $1`,
            [client.id]
          );
          throw new Error(`Refresh token invalid. Client ${client.id} requires re-authentication.`);
        }
        
        throw new Error(`Google token refresh failed: ${res.status} ${errText}`);
      }

      const data = await res.json();
      const newAccessToken = data.access_token;
      const expiresIn = data.expires_in || 3600;
      // Store as Date object for PostgreSQL TIMESTAMPTZ compatibility
      const newExpiryTime = new Date(Date.now() + expiresIn * 1000);

      // Update in db
      await query(
        `UPDATE clients 
         SET oauth_access_token = $1, oauth_token_expiry = $2, status = 'connected' 
         WHERE id = $3`,
        [newAccessToken, newExpiryTime, client.id]
      );

      console.log(`[OAuth] Successfully refreshed token for client ${client.id}.`);
      return newAccessToken;
    } catch (err: any) {
      console.error(`[OAuth] Error refreshing token for client ${client.id}:`, err);
      throw err;
    }
  }

  return client.oauth_access_token || "";
}

// Recursively find Gmail body content
function getGmailBody(payload: any): { html: string; text: string } {
  let html = "";
  let text = "";

  if (!payload) return { html, text };

  if (payload.body && payload.body.data) {
    const data = Buffer.from(payload.body.data, "base64").toString("utf-8");
    if (payload.mimeType === "text/html") {
      html = data;
    } else {
      text = data;
    }
  }

  if (payload.parts) {
    for (const part of payload.parts) {
      const parsed = getGmailBody(part);
      if (parsed.html) html += parsed.html;
      if (parsed.text) text += parsed.text;
    }
  }

  return { html, text };
}

// Message IDs are retained independently of the 30-minute email-content policy.
// Insertion of the marker and email is atomic, so a failed insertion can be retried.
async function storeIfNew(clientId: string, providerMessageId: string, email: {
  sender: string; recipient: string; subject: string; bodyHtml: string;
  bodyText: string; receivedISO: string; expiresAt: string;
  otpCode: string | null; verificationLink: string | null;
  classificationStatus: string; visibilityLevel: string;
}): Promise<boolean> {
  // Preserve existing rows when first deploying the tracking table.
  const existing = await query(
    `SELECT id FROM emails WHERE client_id = $1 AND sender = $2
       AND recipient_email = $3 AND subject = $4 AND received_at = $5 LIMIT 1`,
    [clientId, email.sender, email.recipient, email.subject, email.receivedISO]
  );
  if (existing.rows.length) {
    await query(
      `INSERT INTO synchronized_messages (client_id, provider_message_id)
       VALUES ($1, $2) ON CONFLICT DO NOTHING`,
      [clientId, providerMessageId]
    );
    return false;
  }

  const result = await query(
    `WITH new_message AS (
       INSERT INTO synchronized_messages (client_id, provider_message_id)
       VALUES ($1, $2) ON CONFLICT DO NOTHING
       RETURNING client_id
     )
     INSERT INTO emails
       (id, client_id, sender, recipient_email, subject, full_body_html,
        full_body_text, otp_code, verification_link, received_at, expires_at,
        classification_status, visibility_level)
     SELECT $3, client_id, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14
     FROM new_message RETURNING id`,
    [clientId, providerMessageId, `email_${randomUUID()}`,
     email.sender, email.recipient, email.subject, email.bodyHtml,
     email.bodyText, email.otpCode, email.verificationLink,
     email.receivedISO, email.expiresAt, email.classificationStatus,
     email.visibilityLevel]
  );
  return (result.rowCount || 0) > 0;
}

// Fetch via Gmail API
async function syncGmailClient(client: any) {
  let token = await refreshOAuthTokenIfNeeded(client);
  if (!token) {
    throw new Error("No access token available for Gmail OAuth synchronization.");
  }

  // Search recent messages regardless of Gmail read status.
  const qStr = encodeURIComponent("newer_than:1h -is:trash");
  const listUrl = `https://gmail.googleapis.com/gmail/v1/users/me/messages?q=${qStr}&includeSpamTrash=true&maxResults=100`;
  
  let res = await fetch(listUrl, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
    },
  });

  // If 401, try refresh once and retry
  if (res.status === 401 && client.oauth_refresh_token) {
    console.log(`[OAuth] Access token expired, attempting refresh for client ${client.id}...`);
    token = await refreshOAuthTokenIfNeeded(client);
    
    res = await fetch(listUrl, {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/json",
      },
    });
  }

  if (!res.ok) {
    if (res.status === 401) {
      await query("UPDATE clients SET status = 'unauthorized' WHERE id = $1", [client.id]);
    }
    const errText = await res.text();
    throw new Error(`Gmail API List failed: ${res.status} ${errText}`);
  }

  const listData = await res.json();
  let page = listData;
  let processedCount = 0;

  // Follow Gmail pagination to avoid missing messages when volume is high.
  while (page) {
    for (const msgSummary of page.messages || []) {
      const msgId = String(msgSummary.id);
      const providerMessageId = `gmail:${msgId}`;
      const alreadyTracked = await query(
        `SELECT 1 FROM synchronized_messages WHERE client_id = $1 AND provider_message_id = $2`,
        [client.id, providerMessageId]
      );
      if (alreadyTracked.rows.length) continue;

      // Gmail GET is read-only: do NOT call messages.modify or change UNREAD.
      const msgRes = await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${encodeURIComponent(msgId)}?format=full`, {
        headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
      });
      if (!msgRes.ok) {
        console.warn(`[Gmail] Could not fetch message ${msgId}: ${msgRes.status}`);
        continue;
      }
      const msg = await msgRes.json();
      const headers = msg.payload?.headers || [];
      const subject = headers.find((h: any) => h.name?.toLowerCase() === "subject")?.value || "(No Subject)";
      const sender = headers.find((h: any) => h.name?.toLowerCase() === "from")?.value || "Unknown Sender";
      const recipient = headers.find((h: any) => h.name?.toLowerCase() === "to")?.value || client.email;
      const dateStr = headers.find((h: any) => h.name?.toLowerCase() === "date")?.value;
      const receivedAt = msg.internalDate ? new Date(Number(msg.internalDate)) : (dateStr ? new Date(dateStr) : new Date());
      if (Number.isNaN(receivedAt.getTime())) continue;
      const receivedISO = receivedAt.toISOString();
      const expiresAt = new Date(receivedAt.getTime() + 30 * 60 * 1000).toISOString();
      // Do not resurrect already-expired content on a later poll.
      if (Date.parse(expiresAt) <= Date.now()) continue;
      const bodyParts = getGmailBody(msg.payload);
      const bodyHtml = bodyParts.html || bodyParts.text || "No HTML content";
      const bodyText = bodyParts.text || bodyParts.html || "No plaintext content";
      const extract = extractAuthArtifacts(subject, bodyText);
      if (await storeIfNew(String(client.id), providerMessageId, {
        sender, recipient, subject, bodyHtml, bodyText, receivedISO, expiresAt,
        otpCode: extract.otp_code, verificationLink: extract.verification_link,
        classificationStatus: extract.classification_status, visibilityLevel: extract.visibility_level,
      })) processedCount++;
    }
    if (!page.nextPageToken) break;
    const nextUrl = `${listUrl}&pageToken=${encodeURIComponent(page.nextPageToken)}`;
    const nextRes = await fetch(nextUrl, { headers: { Authorization: `Bearer ${token}`, Accept: "application/json" } });
    if (!nextRes.ok) throw new Error(`Gmail pagination failed: ${nextRes.status}`);
    page = await nextRes.json();
  }

  // Update client last synchronized stats
  await query(
    `UPDATE clients 
     SET last_synced_at = NOW(), total_emails_processed = total_emails_processed + $1, status = 'connected' 
     WHERE id = $2`,
    [processedCount, client.id]
  );

  if (processedCount > 0) {
    await logAudit(
      "SYSTEM",
      "DAEMON",
      `Engine synchronized Google Client ${client.email}: processed ${processedCount} new emails.`,
      "SUCCESS"
    );
  }
}

// Fetch via IMAP Fallback
async function syncImapClient(client: any) {
  if (!client.imap_host || !client.imap_port || !client.encrypted_password || !client.iv) {
    throw new Error("Incomplete IMAP credentials config details.");
  }

  const decryptedPassword = decrypt(client.encrypted_password, client.iv);
  if (!decryptedPassword) {
    throw new Error("Failed to decrypt client password for IMAP connection.");
  }

  console.log(`[IMAP] Connecting to ${client.imap_host}:${client.imap_port} for ${client.email}...`);

  const imapClient = new ImapFlow({
    host: client.imap_host,
    port: client.imap_port,
    secure: client.imap_port === 993,
    auth: {
      user: client.email,
      pass: decryptedPassword,
    },
    logger: false,
    connectionTimeout: 10000,
    greetingTimeout: 5000,
  });

  await imapClient.connect();
  let processedCount = 0;

  try {
    // Discover INBOX and scan list to find any Spam or Junk mailbox paths
    const foldersToPoll = ["INBOX"];
    try {
      const foldersList = await imapClient.list();
      for (const folder of foldersList) {
        const path = folder.path;
        const lowerPath = path.toLowerCase();
        const isSpam = folder.specialUse === "\\Spam" || 
                       folder.specialUse === "\\Junk" || 
                       lowerPath.includes("spam") || 
                       lowerPath.includes("junk");
        if (isSpam && !foldersToPoll.includes(path)) {
          foldersToPoll.push(path);
        }
      }
    } catch (listErr) {
      console.warn(`[IMAP] Could not list folders for discovery, falling back to INBOX only:`, listErr);
    }

    for (const folderPath of foldersToPoll) {
      let folderLock;
      try {
        folderLock = await imapClient.getMailboxLock(folderPath, { readOnly: true });
        
        // Search recent messages, not unread messages. UID remains stable within UIDVALIDITY.
        const searchResult = await imapClient.search({ since: new Date(Date.now() - 60 * 60 * 1000) }, { uid: true });
        const uidValidity = String(imapClient.mailbox && imapClient.mailbox.uidValidity ? imapClient.mailbox.uidValidity : "unknown");
        if (searchResult && Array.isArray(searchResult)) {
          for (const uid of searchResult) {
            const providerMessageId = `imap:${folderPath}:${uidValidity}:${uid}`;
            const alreadyTracked = await query(
              `SELECT 1 FROM synchronized_messages WHERE client_id = $1 AND provider_message_id = $2`,
              [client.id, providerMessageId]
            );
            if (alreadyTracked.rows.length) continue;

            // Read-only mailbox plus PEEK-style source fetching leaves \Seen unchanged.
            const fetchResult = await imapClient.fetchOne(uid, { source: true, envelope: true }, { uid: true });
            if (!fetchResult || !fetchResult.source) continue;
            const parsed = await simpleParser(fetchResult.source);
            const subject = parsed.subject || "(No Subject)";
            const senderObj = parsed.from?.value?.[0];
            const sender = senderObj ? `${senderObj.name || ""} <${senderObj.address || ""}>`.trim() : "Unknown Sender";
            const recipient = client.email;
            const receivedAt = parsed.date ? new Date(parsed.date) : new Date();
            if (Number.isNaN(receivedAt.getTime())) continue;
            const receivedISO = receivedAt.toISOString();
            const expiresAt = new Date(receivedAt.getTime() + 30 * 60 * 1000).toISOString();
            if (Date.parse(expiresAt) <= Date.now()) continue;
            const bodyHtml = typeof parsed.html === "string" ? parsed.html : (parsed.text || "No HTML content");
            const bodyText = parsed.text || (typeof parsed.html === "string" ? parsed.html : "No plaintext content");
            const extract = extractAuthArtifacts(subject, bodyText);
            if (await storeIfNew(String(client.id), providerMessageId, {
              sender, recipient, subject, bodyHtml, bodyText, receivedISO, expiresAt,
              otpCode: extract.otp_code, verificationLink: extract.verification_link,
              classificationStatus: extract.classification_status, visibilityLevel: extract.visibility_level,
            })) processedCount++;
          }
        }
      } catch (folderErr) {
        console.error(`[IMAP] Failed during scanning folder ${folderPath} for client ${client.email}:`, folderErr);
      } finally {
        if (folderLock) {
          folderLock.release();
        }
      }
    }
  } finally {
    await imapClient.logout();
  }

  // Update client status
  await query(
    `UPDATE clients 
     SET last_synced_at = NOW(), total_emails_processed = total_emails_processed + $1, status = 'connected' 
     WHERE id = $2`,
    [processedCount, client.id]
  );

  if (processedCount > 0) {
    await logAudit(
      "SYSTEM",
      "DAEMON",
      `Engine synchronized IMAP client ${client.email}: processed ${processedCount} emails.`,
      "SUCCESS"
    );
  }
}

// Single database cleanup and synchronization tick
export async function runPollingTick() {
  try {
    // 1. Retention policy cleanup:
    const deleteRes = await query("DELETE FROM emails WHERE expires_at < NOW()");
    if (deleteRes.rowCount && deleteRes.rowCount > 0) {
      console.log(`[Retention] Hard deleted ${deleteRes.rowCount} expired emails from system.`);
    }

    // 2. Fetch all clients
    const clientsResult = await query("SELECT * FROM clients");
    const clients = clientsResult.rows;

    for (const client of clients) {
      const state = getBackoffState(client.id);
      
      // Verify if client is allowed to be synchronized based on backoff
      if (Date.now() < state.nextAllowedTime) {
        continue; // Backed off right now
      }

      console.log(`[Polling] Synchronizing Client ${client.id} (${client.email})...`);

      try {
        if (client.auth_type === "oauth" && client.provider === "google") {
          await syncGmailClient(client);
        } else if (client.auth_type === "imap") {
          await syncImapClient(client);
        }
        
        // Reset backoff on successful execution
        handleSuccess(client.id);
      } catch (err: any) {
        console.error(`[Polling] Failed polling for Client ${client.id}:`, err?.message || err);
        handleFailure(client.id, err);
      }
    }
  } catch (globalErr) {
    console.error("[Polling] Critical global error during polling tick:", globalErr);
  }
}

let pollingInterval: NodeJS.Timeout | null = null;

export function startPollingDaemon() {
  console.log("[Daemon] Starting WeApply4U Mail Manager Polling Daemon (90s tick interval as requested)...");
  
  // Trigger immediately on startup
  runPollingTick().catch(err => console.error("Initial polling tick failed:", err));

  // Run subsequent ticks every 90 seconds (90000ms) as requested
  pollingInterval = setInterval(() => {
    runPollingTick().catch(err => console.error("Scheduling tick error:", err));
  }, 90000); 
}

export function stopPollingDaemon() {
  if (pollingInterval) {
    clearInterval(pollingInterval);
    pollingInterval = null;
    console.log("[Daemon] Polling daemon stopped.");
  }
}