/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Regression coverage for the stable-salt fix: the encryption key used to be
 * salted with os.hostname(), so a token file written under one hostname
 * (e.g. a Mac's LAN name) could not be decrypted once the OS reported a
 * different hostname (e.g. after Tailscale's MagicDNS name won the race),
 * surfacing as a spurious "Token file corrupted" and forcing re-consent.
 *
 * These tests deliberately do NOT mock `node:os`: they use the real
 * hostname/username of the machine running the suite so the "legacy
 * hostname salt" constructed here is exactly what production code that
 * predates this fix would have produced. `node:child_process` is mocked so
 * `scutil` probing is deterministic (and exercised for its failure path).
 */
import {
  describe,
  it,
  expect,
  afterEach,
  jest,
} from '@jest/globals';
import * as crypto from 'node:crypto';
import * as os from 'node:os';
import * as path from 'node:path';
import { promises as fs } from 'node:fs';
import { FileTokenStorage } from '../../../auth/token-storage/file-token-storage';
import type { OAuthCredentials } from '../../../auth/token-storage/types';
import {
  ENCRYPTED_TOKEN_PATH,
  ENCRYPTION_MASTER_KEY_PATH,
} from '../../../utils/paths';
import { logToFile } from '../../../utils/logger';

const HOSTNAMES_SIDECAR_PATH = path.join(
  path.dirname(ENCRYPTED_TOKEN_PATH),
  '.gemini-cli-workspace-hostnames',
);

jest.mock('node:fs', () => ({
  promises: {
    readFile: jest.fn(),
    writeFile: jest.fn(),
    appendFile: jest.fn(),
    rename: jest.fn(),
    unlink: jest.fn(),
    mkdir: jest.fn(),
  },
  existsSync: jest.fn(() => true),
}));

// scutil is unavailable in the test environment; every legacy-salt probe
// must tolerate that and fall back to the next candidate.
jest.mock('node:child_process', () => ({
  execFileSync: jest.fn(() => {
    throw new Error('scutil not available in tests');
  }),
}));

jest.mock('../../../utils/logger', () => ({
  logToFile: jest.fn(),
}));

function encryptWithKey(plaintext: string, key: Buffer): string {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let ct = cipher.update(plaintext, 'utf8', 'hex');
  ct += cipher.final('hex');
  const tag = cipher.getAuthTag();
  return `${iv.toString('hex')}:${tag.toString('hex')}:${ct}`;
}

function decryptWithKey(encryptedData: string, key: Buffer): string {
  const [ivHex, tagHex, ctHex] = encryptedData.split(':');
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    key,
    Buffer.from(ivHex, 'hex'),
  );
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  let dec = decipher.update(ctHex, 'hex', 'utf8');
  dec += decipher.final('utf8');
  return dec;
}

describe('FileTokenStorage - stable salt migration', () => {
  const mockFs = fs as unknown as {
    readFile: ReturnType<typeof jest.fn>;
    writeFile: ReturnType<typeof jest.fn>;
    appendFile: ReturnType<typeof jest.fn>;
    rename: ReturnType<typeof jest.fn>;
    unlink: ReturnType<typeof jest.fn>;
    mkdir: ReturnType<typeof jest.fn>;
  };

  afterEach(() => {
    jest.clearAllMocks();
  });

  function mockDisk(
    masterKey: Buffer,
    tokenFileContents?: string,
    sidecarHostnames?: string[],
  ) {
    mockFs.readFile.mockImplementation(async (p: unknown) => {
      if (p === ENCRYPTION_MASTER_KEY_PATH) {
        return masterKey;
      }
      if (p === ENCRYPTED_TOKEN_PATH && tokenFileContents !== undefined) {
        return tokenFileContents;
      }
      if (p === HOSTNAMES_SIDECAR_PATH && sidecarHostnames !== undefined) {
        return `${sidecarHostnames.join('\n')}\n`;
      }
      const err: NodeJS.ErrnoException = new Error('not found');
      err.code = 'ENOENT';
      throw err;
    });
    mockFs.mkdir.mockResolvedValue(undefined);
    mockFs.writeFile.mockResolvedValue(undefined);
    mockFs.appendFile.mockResolvedValue(undefined);
    mockFs.rename.mockResolvedValue(undefined);
  }

  it('(1) round-trips tokens under the stable, hostname-independent salt', async () => {
    const masterKey = crypto.randomBytes(32);
    mockDisk(masterKey, undefined);

    const storage = await FileTokenStorage.create('test-storage');
    const credentials: OAuthCredentials = {
      serverName: 'server-a',
      token: { accessToken: 'tok-a', tokenType: 'Bearer' },
      updatedAt: Date.now(),
    };
    await storage.setCredentials(credentials);

    expect(mockFs.writeFile).toHaveBeenCalledTimes(1);
    const [tmpPath, encryptedOnDisk] = mockFs.writeFile.mock.calls[0] as [
      string,
      string,
    ];
    expect(tmpPath).toMatch(new RegExp(`^${ENCRYPTED_TOKEN_PATH}\\.tmp-`));
    expect(mockFs.rename).toHaveBeenCalledWith(tmpPath, ENCRYPTED_TOKEN_PATH);

    // Feed the bytes actually written back in as "what's on disk" and load
    // with a *fresh* storage instance -- proves the salt does not depend on
    // anything about the process/instance that wrote it, only on the
    // (stable) username.
    mockDisk(masterKey, encryptedOnDisk);
    const storage2 = await FileTokenStorage.create('test-storage');
    const result = await storage2.getCredentials('server-a');
    expect(result).toEqual(credentials);

    // And the salt really is hostname-independent: decrypting directly with
    // the documented stable-salt formula must also work.
    const stableSalt = `${os.userInfo().username}-gemini-cli-workspace-v2`;
    const stableKey = crypto.scryptSync(masterKey, stableSalt, 32);
    const decrypted = decryptWithKey(encryptedOnDisk, stableKey);
    expect(JSON.parse(decrypted)).toEqual({ 'server-a': credentials });
  });

  it('(2) migrates a file encrypted under the legacy hostname salt to the stable salt', async () => {
    const masterKey = crypto.randomBytes(32);
    const legacyHostname = os.hostname();
    const username = os.userInfo().username;
    const legacySalt = `${legacyHostname}-${username}-gemini-cli-workspace`;
    const legacyKey = crypto.scryptSync(masterKey, legacySalt, 32);

    const credentials: OAuthCredentials = {
      serverName: 'legacy-server',
      token: { accessToken: 'legacy-tok', tokenType: 'Bearer' },
      updatedAt: Date.now() - 5000,
    };
    const legacyEncrypted = encryptWithKey(
      JSON.stringify({ 'legacy-server': credentials }),
      legacyKey,
    );

    mockDisk(masterKey, legacyEncrypted);
    const storage = await FileTokenStorage.create('test-storage');
    const result = await storage.getCredentials('legacy-server');

    expect(result).toEqual(credentials);
    expect(logToFile).toHaveBeenCalledWith(
      'Token file migrated from legacy hostname salt',
    );

    // It must have been re-saved (atomically) under the stable key.
    expect(mockFs.writeFile).toHaveBeenCalledTimes(1);
    const [tmpPath, reEncrypted] = mockFs.writeFile.mock.calls[0] as [
      string,
      string,
    ];
    expect(tmpPath).toMatch(new RegExp(`^${ENCRYPTED_TOKEN_PATH}\\.tmp-`));
    expect(mockFs.rename).toHaveBeenCalledWith(tmpPath, ENCRYPTED_TOKEN_PATH);

    const stableSalt = `${username}-gemini-cli-workspace-v2`;
    const stableKey = crypto.scryptSync(masterKey, stableSalt, 32);
    const decrypted = decryptWithKey(reEncrypted, stableKey);
    expect(JSON.parse(decrypted)).toEqual({ 'legacy-server': credentials });

    // The legacy key must no longer be required to read it back.
    expect(() => decryptWithKey(reEncrypted, legacyKey)).toThrow();
  });

  it('(3) logs "Token file corrupted" and returns empty when no candidate key decrypts the file', async () => {
    const masterKey = crypto.randomBytes(32);
    // Encrypted with a key unrelated to the master key or any hostname
    // candidate -- no key this code tries can ever authenticate it.
    const unrelatedKey = crypto.randomBytes(32);
    const garbage = encryptWithKey('irrelevant plaintext', unrelatedKey);

    mockDisk(masterKey, garbage);
    const storage = await FileTokenStorage.create('test-storage');

    const result = await storage.listServers();

    expect(result).toEqual([]);
    expect(logToFile).toHaveBeenCalledWith('Token file corrupted');
    // Corruption must never trigger a "recovery" write.
    expect(mockFs.writeFile).not.toHaveBeenCalled();
  });

  it('(4) migrates a file encrypted under a hostname that only appears in the hostnames sidecar', async () => {
    const masterKey = crypto.randomBytes(32);
    const username = os.userInfo().username;
    // A hostname a long-running old-binary process started under -- it is
    // neither the current os.hostname() nor a scutil name (scutil is
    // mocked to throw in this suite), so the *only* way loadTokens() can
    // find this key is by consulting the hostnames sidecar.
    const staleHostname = 'old-binary-host.example';
    const legacySalt = `${staleHostname}-${username}-gemini-cli-workspace`;
    const legacyKey = crypto.scryptSync(masterKey, legacySalt, 32);

    const credentials: OAuthCredentials = {
      serverName: 'sidecar-only-server',
      token: { accessToken: 'sidecar-tok', tokenType: 'Bearer' },
      updatedAt: Date.now() - 9000,
    };
    const legacyEncrypted = encryptWithKey(
      JSON.stringify({ 'sidecar-only-server': credentials }),
      legacyKey,
    );

    mockDisk(masterKey, legacyEncrypted, [staleHostname]);
    const storage = await FileTokenStorage.create('test-storage');
    const result = await storage.getCredentials('sidecar-only-server');

    expect(result).toEqual(credentials);
    expect(logToFile).toHaveBeenCalledWith(
      'Token file migrated from legacy hostname salt',
    );

    // Re-saved atomically under the stable key, same as the other
    // migration paths.
    const tokenWriteCall = (
      mockFs.writeFile.mock.calls as [string, string, unknown][]
    ).find(([p]) => p.startsWith(`${ENCRYPTED_TOKEN_PATH}.tmp-`));
    expect(tokenWriteCall).toBeDefined();
    const [tmpPath, reEncrypted] = tokenWriteCall!;
    expect(mockFs.rename).toHaveBeenCalledWith(tmpPath, ENCRYPTED_TOKEN_PATH);

    const stableSalt = `${username}-gemini-cli-workspace-v2`;
    const stableKey = crypto.scryptSync(masterKey, stableSalt, 32);
    const decrypted = decryptWithKey(reEncrypted, stableKey);
    expect(JSON.parse(decrypted)).toEqual({
      'sidecar-only-server': credentials,
    });

    // The current machine's real hostname must be recorded into the
    // sidecar too (append-only, so future flips back to it still work).
    expect(mockFs.appendFile).toHaveBeenCalledWith(
      HOSTNAMES_SIDECAR_PATH,
      expect.stringContaining(os.hostname()),
      { mode: 0o600 },
    );
  });
});
