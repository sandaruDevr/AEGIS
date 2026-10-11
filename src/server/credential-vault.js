// Credential Vault — sample test credentials per website, used to give scans
// authenticated access. Enterprise handling rules:
//   - Encrypted at rest (AES-256-GCM); key from CREDENTIALS_SECRET env, or an
//     auto-generated key file when not configured
//   - Plaintext secrets never leave this module: the API returns masked
//     status only, logs contain no secrets, prompts never include credentials
//   - The scan session is signed in server-side before testing starts — the
//     agent never sees the credentials themselves
//   - One credential set per asset (a sample/demo account the owner provides)

import { readFile, writeFile, mkdir } from 'fs/promises';
import { existsSync } from 'fs';
import { join } from 'path';
import { randomUUID, randomBytes, scryptSync, createCipheriv, createDecipheriv } from 'crypto';

const ALGO = 'aes-256-gcm';
const KEY_LEN = 32;
const IV_LEN = 16;

function deriveKey(secret) {
  return scryptSync(String(secret), 'AEGIS-credential-vault', KEY_LEN);
}

function encrypt(key, plaintext) {
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv(ALGO, key, iv);
  const enc = Buffer.concat([cipher.update(String(plaintext), 'utf-8'), cipher.final()]);
  return `${iv.toString('hex')}:${cipher.getAuthTag().toString('hex')}:${enc.toString('hex')}`;
}

function decrypt(key, blob) {
  const [ivHex, tagHex, dataHex] = String(blob).split(':');
  const decipher = createDecipheriv(ALGO, key, Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  return Buffer.concat([decipher.update(Buffer.from(dataHex, 'hex')), decipher.final()]).toString('utf-8');
}

export class CredentialVault {
  constructor(dataDir) {
    this.dataDir = dataDir;
    this.filePath = join(dataDir, 'credentials.json');
    this.keyPath = join(dataDir, '.vault-key');
    this.store = {}; // assetId → { label, username, password(enc), loginUrl, updatedAt }
    this.key = null;
  }

  async init() {
    await mkdir(this.dataDir, { recursive: true });
    // Key: env secret preferred; otherwise generate once and keep locally.
    if (process.env.CREDENTIALS_SECRET) {
      this.key = deriveKey(process.env.CREDENTIALS_SECRET);
    } else if (existsSync(this.keyPath)) {
      this.key = Buffer.from(await readFile(this.keyPath, 'utf-8'), 'hex');
    } else {
      this.key = randomUUID().replace(/-/g, '').slice(0, 32);
      this.key = scryptSync(this.key, 'AEGIS-local-key', KEY_LEN);
      await writeFile(this.keyPath, this.key.toString('hex'), 'utf-8');
      console.log('[Vault] Generated local encryption key (set CREDENTIALS_SECRET to control it).');
    }
    if (existsSync(this.filePath)) {
      try {
        const parsed = JSON.parse(await readFile(this.filePath, 'utf-8'));
        this.store = parsed.credentials || {};
      } catch (err) {
        console.warn(`[Vault] Failed to load store: ${err.message}`);
        this.store = {};
      }
    }
  }

  async _save() {
    await writeFile(this.filePath, JSON.stringify({ credentials: this.store }, null, 2), 'utf-8');
  }

  async set(assetId, { label, username, password, loginUrl } = {}) {
    if (!assetId) throw new Error('A website is required.');
    const existing = this.store[assetId];
    const user = username !== undefined && String(username).trim()
      ? String(username).trim().slice(0, 200)
      : existing?.username;
    if (!user) throw new Error('Username or email is required.');
    // Password: required on first save; on updates, empty = keep the stored one.
    let passEnc;
    if (password && String(password).trim()) {
      passEnc = encrypt(this.key, String(password));
    } else if (existing) {
      passEnc = existing.password;
    } else {
      throw new Error('Password is required.');
    }
    const entry = {
      label: String(label || existing?.label || 'Test account').slice(0, 80),
      username: user,
      password: passEnc,
      loginUrl: loginUrl !== undefined && String(loginUrl).trim()
        ? String(loginUrl).trim().slice(0, 500)
        : (existing?.loginUrl ?? null),
      updatedAt: Date.now(),
    };
    this.store[assetId] = entry;
    await this._save();
    return this.status(assetId);
  }

  // Decrypted — internal use only (scan session sign-in). Never serialized
  // to the client, logs or prompts.
  get(assetId) {
    const entry = this.store[assetId];
    if (!entry) return null;
    try {
      return {
        label: entry.label,
        username: entry.username,
        password: decrypt(this.key, entry.password),
        loginUrl: entry.loginUrl,
      };
    } catch (err) {
      console.warn('[Vault] Decrypt failed — credentials may have been written with a different key.');
      return null;
    }
  }

  has(assetId) {
    return Boolean(this.store[assetId]);
  }

  // Client-facing status — masked, never includes the password.
  status(assetId) {
    const entry = this.store[assetId];
    if (!entry) return { has: false };
    const u = entry.username;
    const at = u.indexOf('@');
    const masked = at > 1
      ? `${u.slice(0, 2)}••••${u.slice(at)}`
      : `${u.slice(0, 2)}••••`;
    return {
      has: true,
      label: entry.label,
      username: masked,
      loginUrl: entry.loginUrl,
      updatedAt: entry.updatedAt,
    };
  }

  async remove(assetId) {
    if (!this.store[assetId]) return false;
    delete this.store[assetId];
    await this._save();
    return true;
  }
}
