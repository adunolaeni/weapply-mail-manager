import pg from "pg";
import crypto from "crypto";
import { UserRole, AuditLog } from "../src/types";

export interface DBUser {
  id: string;
  name: string;
  email: string;
  password_hash: string;
  role: UserRole;
  is_2fa_enabled: boolean;
  created_at: string;
}

export interface DBClientAccount {
  id: string;
  clientName: string;
  email: string;
  provider: "google" | "microsoft";
  auth_type: "imap" | "oauth";
  imap_host?: string | null;
  imap_port?: number | null;
  encrypted_password?: string | null;
  iv?: string | null;
  oauth_access_token?: string | null;
  oauth_refresh_token?: string | null;
  oauth_token_expiry?: string | null;
  status: "connected" | "syncing" | "expired" | "disconnected";
  connectedAt: string;
  lastSyncedAt: string;
  assignedWorkers: string[];
  totalEmailsProcessed: number;
}

export class DatabaseService {                
  private pool: pg.Pool | null = null;

  constructor() {
    const dbUrl = process.env.DATABASE_URL;
    if (!dbUrl) {
      throw new Error("DATABASE_URL is required. No fallback allowed.");
    }

    console.log("DATABASE_URL found. Initializing PostgreSQL pool...");

    this.pool = new pg.Pool({
      connectionString: dbUrl,
      ssl: {
        rejectUnauthorized: false
      }
    });
  }

  async init() {
    try {
      const client = await this.pool!.connect();
      console.log("CONNECTED to real PostgreSQL database! Setting up schemas...");
      
      // 1. Create Users
      await client.query(`
        CREATE TABLE IF NOT EXISTS users (
          id VARCHAR(100) PRIMARY KEY,
          name VARCHAR(255) NOT NULL,
          email VARCHAR(255) UNIQUE NOT NULL,
          password_hash VARCHAR(255) NOT NULL,
          role VARCHAR(50) NOT NULL DEFAULT 'WORKER',
          is_2fa_enabled BOOLEAN DEFAULT FALSE,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);

      // 2. Create Clients
      await client.query(`
        CREATE TABLE IF NOT EXISTS clients (
          id VARCHAR(100) PRIMARY KEY,
          client_name VARCHAR(255) NOT NULL,
          email VARCHAR(255) UNIQUE NOT NULL,
          provider VARCHAR(50) NOT NULL,
          auth_type VARCHAR(20) NOT NULL DEFAULT 'imap',
          imap_host VARCHAR(255) NULL,
          imap_port INTEGER NULL,
          encrypted_password TEXT NULL,
          iv VARCHAR(100) NULL,
          oauth_access_token TEXT NULL,
          oauth_refresh_token TEXT NULL,
          oauth_token_expiry TIMESTAMP NULL,
          status VARCHAR(50) NOT NULL DEFAULT 'connected',
          connected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          last_synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          total_emails_processed INTEGER DEFAULT 0
        )
      `);

      // 3. Create Assignments
      await client.query(`
        CREATE TABLE IF NOT EXISTS worker_assignments (
          id SERIAL PRIMARY KEY,
          worker_id VARCHAR(100) REFERENCES users(id) ON DELETE CASCADE,
          client_id VARCHAR(100) REFERENCES clients(id) ON DELETE CASCADE,
          assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(worker_id, client_id)
        )
      `);

      // 4. Create Emails Table
      await client.query(`
        CREATE TABLE IF NOT EXISTS emails (
          id VARCHAR(100) PRIMARY KEY,
          client_id VARCHAR(100) REFERENCES clients(id) ON DELETE CASCADE,
          sender VARCHAR(255) NOT NULL,
          subject VARCHAR(500) NOT NULL,
          recipient_email VARCHAR(255) NULL,
          full_body_html TEXT NOT NULL,
          full_body_text TEXT NOT NULL,
          otp_code VARCHAR(32) NULL,
          verification_link TEXT NULL,
          received_at TIMESTAMP NOT NULL,
          expires_at TIMESTAMP NOT NULL,
          classification_status VARCHAR(50) NOT NULL,
          visibility_level VARCHAR(20) NOT NULL
        )
      `);

      // Synchronization metadata is separate from short-lived email bodies.
      // Stable provider IDs prevent refetching after 30-minute content deletion.
      await client.query(`
        CREATE TABLE IF NOT EXISTS synchronized_messages (
          client_id VARCHAR(100) NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
          provider_message_id TEXT NOT NULL,
          synchronized_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          PRIMARY KEY (client_id, provider_message_id)
        )
      `);

      // 5. Create Audit Log
      await client.query(`
        CREATE TABLE IF NOT EXISTS audit_logs (
          id VARCHAR(100) PRIMARY KEY,
          timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          actor VARCHAR(255) NOT NULL,
          role VARCHAR(50) NOT NULL,
          action TEXT NOT NULL,
          status VARCHAR(50) NOT NULL,
          ip_address VARCHAR(100) NULL
        )
      `);

      // Seed/update main admin purely via Render Environment Variable
      const adminSecret = process.env.OASEK_ADMIN_PASSWORD;
      if (!adminSecret) {
        throw new Error("CRITICAL CONFIG ERROR: OASEK_ADMIN_PASSWORD environment variable is missing on Render!");
      }

      const checkAdminRes = await client.query("SELECT * FROM users WHERE email = $1", ["admin@weapplying4u.com"]);
      const bcrypt = await import("bcrypt");
      const reqAdminHash = await bcrypt.hash(adminSecret, 10);
      
      if (checkAdminRes.rows.length === 0) {
        console.log("Seeding requested admin account...");
        const maxIdRes = await client.query("SELECT id FROM users WHERE id LIKE 'admin_%' ORDER BY id DESC LIMIT 1");
        let nextIdNum = 1;
        if (maxIdRes.rows.length > 0) {
          const lastId = maxIdRes.rows[0].id;
          const match = lastId.match(/admin_(\d+)/);
          if (match) {
            nextIdNum = parseInt(match[1], 10) + 1;
          }
        }
        const generatedId = `admin_${nextIdNum}`;
        await client.query(`
          INSERT INTO users (id, name, email, password_hash, role, is_2fa_enabled) VALUES
          ($1, 'Admin', 'admin@weapplying4u.com', $2, 'ADMIN', false)
        `, [generatedId, reqAdminHash]);
      } else {
        console.log("Updating admin metadata and hashing secure credentials...");
        await client.query(`
          UPDATE users SET password_hash = $1, role = 'ADMIN' WHERE email = 'admin@weapplying4u.com'
        `, [reqAdminHash]);
      }

      // Dynamic provisioning list (No fallback passwords stored here)
      const tier2Users = [
        { name: "Washington Ade", email: "washington.ade@oasek.com" },
        { name: "Samuel Odogbo", email: "samuel.odogbo@oasek.com" },
        { name: "Vero Obi", email: "vero.obi@weapplying4u.com" },
        { name: "Oasek Admin", email: "admin@oasek.com" },
      ];

      for (const tUser of tier2Users) {
        const checkUserRes = await client.query("SELECT * FROM users WHERE email = $1", [tUser.email]);
        
        if (checkUserRes.rows.length === 0) {
          console.log(`Provisioning blank user profile for self-service password creation: ${tUser.email}...`);
          
          // Generate an un-loggable randomized placeholder hash so account is secure until they create a real password
          const lockedAccountString = `LOCKED_UNSET_${crypto.randomBytes(16).toString("hex")}`;
          const lockedHash = await bcrypt.hash(lockedAccountString, 10);

          const maxIdRes = await client.query("SELECT id FROM users WHERE id LIKE 'worker_%' ORDER BY id DESC LIMIT 1");
          let nextIdNum = 1;
          if (maxIdRes.rows.length > 0) {
            const lastId = maxIdRes.rows[0].id;
            const match = lastId.match(/worker_(\d+)/);
            if (match) {
              nextIdNum = parseInt(match[1], 10) + 1;
            }
          }
          const generatedId = `worker_${nextIdNum}`;
          await client.query(`
            INSERT INTO users (id, name, email, password_hash, role, is_2fa_enabled) VALUES
            ($1, $2, $3, $4, 'WORKER', false)
          `, [generatedId, tUser.name, tUser.email, lockedHash]);
        } else {
          // Keep existing user passwords intact so you never overwrite their customized self-service passwords
          console.log(`Skipping password rewrite; updating active metadata for: ${tUser.email}`);
          await client.query(`
            UPDATE users SET name = $1, role = 'WORKER' WHERE email = $2
          `, [tUser.name, tUser.email]);
        }
      }

      client.release();
      console.log("PostgreSQL setup completed successfully!");
    } catch (err) {
      console.error("Error setting up PostgreSQL schemas.", err);
      process.exit(1);
    }
  }

  // --- DATABASE HELPERS ---

  async query(sql: string, params?: any[]) {
    return await this.pool!.query(sql, params);
  }

  async updateClientOAuthTokens(id: string, accessToken: string, expiryDate?: string | null): Promise<void> {
    if (expiryDate) {
      await this.pool!.query(
        "UPDATE clients SET oauth_access_token = $1, oauth_token_expiry = $2 WHERE id = $3",
        [accessToken, new Date(expiryDate), id]
      );
    } else {
      await this.pool!.query(
        "UPDATE clients SET oauth_access_token = $1 WHERE id = $2",
        [accessToken, id]
      );
    }
  }

  async updateClientSyncStats(id: string, emailCountIncrement = 1): Promise<void> {
    await this.pool!.query(`
      UPDATE clients 
      SET total_emails_processed = total_emails_processed + $1, last_synced_at = CURRENT_TIMESTAMP
      WHERE id = $2
    `, [emailCountIncrement, id]);
  }

  async addAuditLog(log: Omit<AuditLog, "id">): Promise<void> {
    const id = "log_" + Math.floor(Math.random() * 100000);
    await this.pool!.query(`
      INSERT INTO audit_logs (id, timestamp, actor, role, action, status, ip_address)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
    `, [
      id,
      new Date(log.timestamp),
      log.actor,
      log.role,
      log.action,
      log.status,
      log.ip_address || null
    ]);
  }
}

export const db = new DatabaseService();

export async function initDb() {
  await db.init();
}

export async function query(sql: string, params?: any[]) {
  return await db.query(sql, params);
}

export async function logAudit(
  actor: string,
  role: string,
  action: string,
  status: string,
  ipAddress?: string
) {
  await db.addAuditLog({
    timestamp: new Date().toISOString(),
    actor,
    role,
    action,
    status,
    ip_address: ipAddress || null
  });
}