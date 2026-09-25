/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { BaseTokenStorage } from './base-token-storage';
import type { OAuthCredentials } from './types';
import { logToFile } from '../../utils/logger';
import {
  ENCRYPTED_TOKEN_PATH,
  ENCRYPTION_MASTER_KEY_PATH,
} from '../../utils/paths';

export class FileTokenStorage extends BaseTokenStorage {
  private readonly tokenFilePath: string;
  private readonly hostnamesFilePath: string;
  private readonly encryptionKey: Buffer;
  private readonly masterKey: Buffer;

  private constructor(serviceName: string, masterKey: Buffer) {
    super(serviceName);
    this.tokenFilePath = ENCRYPTED_TOKEN_PATH;
    this.hostnamesFilePath = path.join(
      path.dirname(this.tokenFilePath),
      '.gemini-cli-workspace-hostnames',
    );
    this.masterKey = masterKey;
    this.encryptionKey = this.deriveEncryptionKey();
  }

  static async create(serviceName: string): Promise<FileTokenStorage> {
    const masterKey = await this.loadMasterKey();
    return new FileTokenStorage(serviceName, masterKey);
  }

  private static async loadMasterKey(): Promise<Buffer> {
    try {
      const masterKey = await fs.readFile(ENCRYPTION_MASTER_KEY_PATH);
      return masterKey;
    } catch (error) {
      const err = error as NodeJS.ErrnoException;
      if (err.code === 'ENOENT') {
        const newKey = crypto.randomBytes(32);
        await fs.writeFile(ENCRYPTION_MASTER_KEY_PATH, newKey, { mode: 0o600 });
        return newKey;
      }
      throw error;
    }
  }

  /**
   * Derives the current (stable) encryption key.
   *
   * The salt intentionally does NOT include os.hostname(): on machines whose
   * hostname changes at runtime (e.g. a Mac that reports a different name
   * depending on whether Tailscale's MagicDNS name or the LAN name wins the
   * race, or a DHCP lease rename), a hostname-salted key made a token file
   * written under one hostname undecryptable under another, surfacing as a
   * spurious "Token file corrupted" and forcing re-consent. See
   * `getLegacyKeyCandidates()` for the migration path off the old salt.
   */
  private deriveEncryptionKey(): Buffer {
    const salt = `${os.userInfo().username}-gemini-cli-workspace-v2`;
    return this.deriveKeyFromSalt(salt);
  }

  private deriveKeyFromSalt(salt: string): Buffer {
    return crypto.scryptSync(this.masterKey, salt, 32);
  }

  /**
   * Best-effort read of a `scutil --get <key>` value. Returns null (never
   * throws) when scutil is unavailable (non-darwin) or the call fails for
   * any reason -- legacy-salt probing must never be able to crash the
   * server.
   */
  private tryScutil(key: string): string | null {
    try {
      const result = execFileSync('scutil', ['--get', key], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
      });
      const trimmed = result.trim();
      return trimmed.length > 0 ? trimmed : null;
    } catch {
      return null;
    }
  }

  /**
   * Best-effort read of the append-only hostname sidecar (one hostname per
   * line). Never throws: a missing or unreadable sidecar just yields no
   * extra candidates.
   */
  private async readHostnameSidecar(): Promise<string[]> {
    try {
      const data = await fs.readFile(this.hostnamesFilePath, 'utf-8');
      return data
        .split('\n')
        .map((line) => line.trim())
        .filter((line) => line.length > 0);
    } catch {
      return [];
    }
  }

  /**
   * Appends os.hostname() to the sidecar if it isn't already recorded.
   * Some long-running old-binary processes (e.g. a Cursor MCP server
   * started before this fix, and never restarted) keep saving token files
   * under whichever hostname they had when they started -- a hostname that
   * may be neither the *current* os.hostname() nor a scutil name (e.g. this
   * machine flips between an mDNS `.local` name and a Tailscale MagicDNS
   * name; other hostnames a stale process observed are not derivable from
   * scutil at all). Recording every hostname this process has ever seen
   * gives loadTokens() a durable list of legacy salts to fall back to. This
   * is best-effort bookkeeping and must never break token I/O.
   */
  private async recordCurrentHostname(): Promise<void> {
    try {
      const hostname = os.hostname();
      if (!hostname) {
        return;
      }
      const known = await this.readHostnameSidecar();
      if (known.includes(hostname)) {
        return;
      }
      await this.ensureDirectoryExists();
      await fs.appendFile(this.hostnamesFilePath, `${hostname}\n`, {
        mode: 0o600,
      });
    } catch {
      // Best effort only.
    }
  }

  /**
   * Legacy hostname-salted keys to try, in order, when the stable key fails
   * to decrypt an existing token file. Candidate hostnames:
   *   1. os.hostname() -- the pre-fix salt basis.
   *   2. darwin only: `scutil --get LocalHostName` + '.local'
   *   3. darwin only: `scutil --get ComputerName`
   *   4. darwin only: the bare `scutil --get LocalHostName` value
   *   5. every hostname recorded in the sidecar (see recordCurrentHostname)
   *      that isn't already covered above.
   * scutil calls tolerate failure (see tryScutil) so this never throws.
   */
  private async getLegacyKeyCandidates(): Promise<Buffer[]> {
    const username = os.userInfo().username;
    const hostCandidates: string[] = [os.hostname()];

    if (process.platform === 'darwin') {
      const localHostName = this.tryScutil('LocalHostName');
      if (localHostName) {
        hostCandidates.push(`${localHostName}.local`);
      }
      const computerName = this.tryScutil('ComputerName');
      if (computerName) {
        hostCandidates.push(computerName);
      }
      if (localHostName) {
        hostCandidates.push(localHostName);
      }
    }

    const sidecarHosts = await this.readHostnameSidecar();
    hostCandidates.push(...sidecarHosts);

    const seen = new Set<string>();
    const uniqueHosts = hostCandidates.filter((host) => {
      if (!host || seen.has(host)) {
        return false;
      }
      seen.add(host);
      return true;
    });

    return uniqueHosts.map((host) =>
      this.deriveKeyFromSalt(`${host}-${username}-gemini-cli-workspace`),
    );
  }

  private encrypt(text: string): string {
    return this.encryptWithKey(text, this.encryptionKey);
  }

  private encryptWithKey(text: string, key: Buffer): string {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    const authTag = cipher.getAuthTag();

    return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted;
  }

  private decrypt(encryptedData: string): string {
    return this.decryptWithKey(encryptedData, this.encryptionKey);
  }

  private decryptWithKey(encryptedData: string, key: Buffer): string {
    const parts = encryptedData.split(':');
    if (parts.length !== 3) {
      throw new Error('Invalid encrypted data format');
    }

    const iv = Buffer.from(parts[0], 'hex');
    const authTag = Buffer.from(parts[1], 'hex');
    const encrypted = parts[2];

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }

  /**
   * True when `error` looks like "wrong key" rather than a real fault: a
   * malformed envelope, a GCM auth-tag mismatch, or JSON.parse choking on
   * garbage plaintext that happened to pass GCM's own check.
   */
  private isDecryptError(error: unknown): boolean {
    if (error instanceof SyntaxError) {
      return true;
    }
    const message = (error as { message?: string })?.message ?? '';
    const lower = message.toLowerCase();
    return (
      message.includes('Invalid encrypted data format') ||
      message.includes('Unsupported state or unable to authenticate data') ||
      lower.includes('bad decrypt') ||
      lower.includes('unable to authenticate')
    );
  }

  private async ensureDirectoryExists(): Promise<void> {
    const dir = path.dirname(this.tokenFilePath);
    await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  }

  private async loadTokens(): Promise<Map<string, OAuthCredentials>> {
    await this.recordCurrentHostname();

    let data: string;
    try {
      data = await fs.readFile(this.tokenFilePath, 'utf-8');
    } catch (error: unknown) {
      const err = error as NodeJS.ErrnoException;
      if (err.code === 'ENOENT') {
        logToFile('Token file does not exist');
        return new Map<string, OAuthCredentials>();
      }
      throw error;
    }

    // Try the current, stable (hostname-independent) key first.
    try {
      const decrypted = this.decrypt(data);
      const tokens = JSON.parse(decrypted) as Record<string, OAuthCredentials>;
      return new Map(Object.entries(tokens));
    } catch (error: unknown) {
      if (!this.isDecryptError(error)) {
        throw error;
      }
    }

    // The stable key failed to authenticate the file -- it may have been
    // written before this fix, under a hostname-salted key. Probe the
    // legacy candidates in order; the first one that decrypts wins and the
    // file is immediately re-saved under the stable key so this only ever
    // happens once per token file.
    for (const legacyKey of await this.getLegacyKeyCandidates()) {
      try {
        const decrypted = this.decryptWithKey(data, legacyKey);
        const tokens = JSON.parse(decrypted) as Record<
          string,
          OAuthCredentials
        >;
        const migrated = new Map(Object.entries(tokens));
        logToFile('Token file migrated from legacy hostname salt');
        await this.saveTokens(migrated);
        return migrated;
      } catch (error: unknown) {
        if (!this.isDecryptError(error)) {
          throw error;
        }
        // Not this candidate -- try the next one.
      }
    }

    logToFile('Token file corrupted');
    return new Map<string, OAuthCredentials>();
  }

  private async saveTokens(
    tokens: Map<string, OAuthCredentials>,
  ): Promise<void> {
    await this.recordCurrentHostname();
    await this.ensureDirectoryExists();

    const data = Object.fromEntries(tokens);
    const json = JSON.stringify(data, null, 2);
    const encrypted = this.encrypt(json);

    // Write to a unique temp file and rename into place atomically so a
    // concurrent writer (or a crash mid-write) can never leave a
    // half-written, unparseable token file on disk.
    const tmpPath = `${this.tokenFilePath}.tmp-${process.pid}-${crypto
      .randomBytes(6)
      .toString('hex')}`;
    await fs.writeFile(tmpPath, encrypted, { mode: 0o600 });
    await fs.rename(tmpPath, this.tokenFilePath);
  }

  async getCredentials(serverName: string): Promise<OAuthCredentials | null> {
    const tokens = await this.loadTokens();
    const credentials = tokens.get(serverName);

    if (!credentials) {
      return null;
    }

    return credentials;
  }

  async setCredentials(credentials: OAuthCredentials): Promise<void> {
    this.validateCredentials(credentials);

    const tokens = await this.loadTokens();
    const updatedCredentials: OAuthCredentials = {
      ...credentials,
      updatedAt: Date.now(),
    };

    tokens.set(credentials.serverName, updatedCredentials);
    await this.saveTokens(tokens);
  }

  async deleteCredentials(serverName: string): Promise<void> {
    const tokens = await this.loadTokens();

    if (!tokens.has(serverName)) {
      throw new Error(`No credentials found for ${serverName}`);
    }

    tokens.delete(serverName);

    if (tokens.size === 0) {
      try {
        await fs.unlink(this.tokenFilePath);
      } catch (error: unknown) {
        const err = error as NodeJS.ErrnoException;
        if (err.code !== 'ENOENT') {
          throw error;
        }
      }
    } else {
      await this.saveTokens(tokens);
    }
  }

  async listServers(): Promise<string[]> {
    const tokens = await this.loadTokens();
    return Array.from(tokens.keys());
  }

  async getAllCredentials(): Promise<Map<string, OAuthCredentials>> {
    const tokens = await this.loadTokens();
    const result = new Map<string, OAuthCredentials>();

    for (const [serverName, credentials] of tokens) {
      try {
        this.validateCredentials(credentials);
        result.set(serverName, credentials);
      } catch (error) {
        console.error(`Skipping invalid credentials for ${serverName}:`, error);
      }
    }

    return result;
  }

  async clearAll(): Promise<void> {
    try {
      await fs.unlink(this.tokenFilePath);
    } catch (error: unknown) {
      const err = error as NodeJS.ErrnoException;
      if (err.code !== 'ENOENT') {
        throw error;
      }
    }
  }
}
