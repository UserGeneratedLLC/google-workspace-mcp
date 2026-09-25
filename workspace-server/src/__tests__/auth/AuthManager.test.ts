/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { promises as fsp } from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { AuthManager } from '../../auth/AuthManager';
import { OAuthCredentialStorage } from '../../auth/token-storage/oauth-credential-storage';
import { google } from 'googleapis';
import open from '../../utils/open-wrapper';
import { AUTH_LOCK_PATH } from '../../utils/paths';
import { shouldLaunchBrowser } from '../../utils/secure-browser-launcher';

// Mock dependencies
jest.mock('../../auth/token-storage/oauth-credential-storage');
jest.mock('googleapis');
jest.mock('../../utils/logger');
jest.mock('../../utils/secure-browser-launcher');
jest.mock('../../utils/open-wrapper');
// The sign-in lock lives in a per-run temp dir, never the repo root.
jest.mock('../../utils/paths', () => {
  const nodePath = jest.requireActual('node:path');
  const nodeOs = jest.requireActual('node:os');
  const dir = nodePath.join(
    nodeOs.tmpdir(),
    `gws-authmanager-test-${process.pid}`,
  );
  return {
    PROJECT_ROOT: dir,
    AUTH_LOCK_PATH: nodePath.join(dir, '.gemini-cli-workspace-auth.lock'),
  };
});

// Mock fetch globally for refreshToken tests
global.fetch = jest.fn();

describe('AuthManager', () => {
  let authManager: AuthManager;
  let mockOAuth2Client: any;

  beforeEach(() => {
    jest.clearAllMocks();

    // Setup mock OAuth2 client
    mockOAuth2Client = {
      setCredentials: jest.fn().mockImplementation((creds) => {
        mockOAuth2Client.credentials = creds;
      }),
      generateAuthUrl: jest.fn(),
      on: jest.fn(),
      refreshAccessToken: jest.fn(),
      credentials: {},
    };

    (google.auth.OAuth2 as unknown as jest.Mock).mockReturnValue(
      mockOAuth2Client,
    );

    authManager = new AuthManager(['scope1']);
  });

  it('should set up tokens event listener on client creation', async () => {
    (OAuthCredentialStorage.loadCredentials as jest.Mock).mockResolvedValue({
      access_token: 'old_token',
      refresh_token: 'old_refresh',
      scope: 'scope1',
    });

    await authManager.getAuthenticatedClient();

    // Verify 'on' was called for 'tokens'
    expect(mockOAuth2Client.on).toHaveBeenCalledWith(
      'tokens',
      expect.any(Function),
    );
  });

  it('should save credentials when tokens event is emitted', async () => {
    (OAuthCredentialStorage.loadCredentials as jest.Mock).mockResolvedValue({
      access_token: 'old_token',
      refresh_token: 'old_refresh',
      scope: 'scope1',
    });

    await authManager.getAuthenticatedClient();

    // Get the registered callback
    const tokensCallback = mockOAuth2Client.on.mock.calls.find(
      (call: any[]) => call[0] === 'tokens',
    )[1];
    expect(tokensCallback).toBeDefined();

    // Simulate tokens event
    const newTokens = {
      access_token: 'new_token',
      expiry_date: 123456789,
    };

    await tokensCallback(newTokens);

    // Verify saveCredentials was called with merged tokens
    // New tokens take precedence, but refresh_token is preserved from old credentials
    expect(OAuthCredentialStorage.saveCredentials).toHaveBeenCalledWith({
      access_token: 'new_token',
      refresh_token: 'old_refresh', // Preserved from old credentials
      expiry_date: 123456789,
      // Note: scope is NOT preserved because newTokens didn't include it
    });
  });

  it('should preserve refresh token during manual refresh if not returned', async () => {
    // Setup initial state with a refresh token
    (OAuthCredentialStorage.loadCredentials as jest.Mock).mockResolvedValue({
      access_token: 'old_token',
      refresh_token: 'old_refresh_token',
      scope: 'scope1',
    });

    // Initialize client to populate this.client
    await authManager.getAuthenticatedClient();

    // Mock fetch to simulate cloud function returning new tokens without refresh_token
    (global.fetch as jest.Mock).mockResolvedValue({
      ok: true,
      json: async () => ({
        access_token: 'new_access_token',
        expiry_date: 999999999,
      }),
    });

    await authManager.refreshToken();

    // Verify saveCredentials was called with BOTH new access token AND old refresh token
    expect(OAuthCredentialStorage.saveCredentials).toHaveBeenCalledWith(
      expect.objectContaining({
        access_token: 'new_access_token',
        refresh_token: 'old_refresh_token',
      }),
    );
  });

  it('should preserve refresh token when refreshAccessToken mutates credentials in-place', async () => {
    // Setup initial state with a refresh token
    (OAuthCredentialStorage.loadCredentials as jest.Mock).mockResolvedValue({
      access_token: 'old_token',
      refresh_token: 'old_refresh_token',
      scope: 'scope1',
    });

    // Initialize client to populate this.client
    await authManager.getAuthenticatedClient();

    // Mock fetch to simulate cloud function returning new tokens without refresh_token
    (global.fetch as jest.Mock).mockResolvedValue({
      ok: true,
      json: async () => ({
        access_token: 'new_access_token',
        expiry_date: 999999999,
      }),
    });

    await authManager.refreshToken();

    // This test verifies that the refresh_token is preserved even when
    // the cloud function doesn't return it in the response
    expect(OAuthCredentialStorage.saveCredentials).toHaveBeenCalledWith(
      expect.objectContaining({
        access_token: 'new_access_token',
        refresh_token: 'old_refresh_token',
      }),
    );
  });

  it('should preserve refresh token in tokens event handler', async () => {
    // Setup initial state with a refresh token in storage
    (OAuthCredentialStorage.loadCredentials as jest.Mock).mockResolvedValue({
      access_token: 'old_token',
      refresh_token: 'stored_refresh_token',
      scope: 'scope1',
    });

    await authManager.getAuthenticatedClient();

    // Get the registered callback
    const tokensCallback = mockOAuth2Client.on.mock.calls.find(
      (call: any[]) => call[0] === 'tokens',
    )[1];

    // Simulate automatic refresh that doesn't include refresh_token
    const newTokens = {
      access_token: 'auto_refreshed_token',
      expiry_date: 999999999,
      // Note: no refresh_token
    };

    await tokensCallback(newTokens);

    // Verify saveCredentials was called with BOTH new access token AND stored refresh token
    expect(OAuthCredentialStorage.saveCredentials).toHaveBeenCalledWith({
      access_token: 'auto_refreshed_token',
      expiry_date: 999999999,
      refresh_token: 'stored_refresh_token',
    });
  });

  it('should proactively refresh expired tokens before returning client', async () => {
    // Setup: Load credentials with expired token
    const expiredTime = Date.now() - 1000; // 1 second ago
    (OAuthCredentialStorage.loadCredentials as jest.Mock).mockResolvedValue({
      access_token: 'expired_token',
      refresh_token: 'valid_refresh',
      expiry_date: expiredTime,
      scope: 'scope1',
    });

    // Mock fetch to simulate cloud function returning fresh tokens
    (global.fetch as jest.Mock).mockResolvedValue({
      ok: true,
      json: async () => ({
        access_token: 'fresh_token',
        expiry_date: Date.now() + 3600000,
      }),
    });

    // First call: load expired credentials from storage, should trigger proactive refresh
    const firstClient = await authManager.getAuthenticatedClient();
    expect(firstClient).toBeDefined();

    // Verify fetch was called to refresh the token
    expect(global.fetch).toHaveBeenCalledWith(
      'https://google-workspace-extension.geminicli.com/refreshToken',
      expect.objectContaining({
        method: 'POST',
        body: expect.stringContaining('valid_refresh'),
      }),
    );

    // Verify new token was saved with preserved refresh_token
    expect(OAuthCredentialStorage.saveCredentials).toHaveBeenCalledWith(
      expect.objectContaining({
        access_token: 'fresh_token',
        refresh_token: 'valid_refresh',
      }),
    );
  });

  it('should proactively refresh tokens expiring within buffer (5 minutes)', async () => {
    // Setup: Load credentials with token expiring in 4 minutes (within 5 min buffer)
    const TEST_EXPIRY_WITHIN_BUFFER = 4 * 60 * 1000;
    const expiresIn4Minutes = Date.now() + TEST_EXPIRY_WITHIN_BUFFER;
    (OAuthCredentialStorage.loadCredentials as jest.Mock).mockResolvedValue({
      access_token: 'soon_expiring_token',
      refresh_token: 'valid_refresh',
      expiry_date: expiresIn4Minutes,
      scope: 'scope1',
    });

    // Mock fetch to simulate cloud function returning fresh tokens
    (global.fetch as jest.Mock).mockResolvedValue({
      ok: true,
      json: async () => ({
        access_token: 'fresh_token',
        expiry_date: Date.now() + 60 * 60 * 1000,
      }),
    });

    // Call getAuthenticatedClient
    const client = await authManager.getAuthenticatedClient();
    expect(client).toBeDefined();

    // Verify fetch was called to refresh the token because it was within buffer
    expect(global.fetch).toHaveBeenCalledWith(
      'https://google-workspace-extension.geminicli.com/refreshToken',
      expect.objectContaining({
        method: 'POST',
        body: expect.stringContaining('valid_refresh'),
      }),
    );
  });

  describe('durable credentials', () => {
    const HOUR = 60 * 60 * 1000;
    const FAST = {
      refreshTimeoutMs: 1_000,
      refreshRetryDelaysMs: [0, 0],
      loginTimeoutMs: 400,
      loginPollIntervalMs: 10,
    };
    // Phrasings a caller (Cosmos) reads as "only a browser sign-in fixes this".
    const AUTH_FAULT_RE =
      /Token refresh failed|invalid_grant|User is not authenticated|No browser available|Authentication timed out|Token file corrupted/;

    let stored: Record<string, unknown> | null;
    let manager: AuthManager;
    let authWithWeb: jest.SpyInstance;

    const creds = (refreshToken: string, expiresInMs: number) => ({
      access_token: `access-${refreshToken}`,
      refresh_token: refreshToken,
      scope: 'scope1',
      expiry_date: Date.now() + expiresInMs,
    });
    const reply = (status: number, body: unknown) => ({
      ok: status >= 200 && status < 300,
      status,
      json: async () => body,
      text: async () =>
        typeof body === 'string' ? body : JSON.stringify(body),
    });
    const invalidGrant = () =>
      reply(400, {
        error: 'invalid_grant',
        error_description: 'Token has been expired or revoked.',
      });
    const freshTokens = (tag: string) =>
      reply(200, {
        access_token: `refreshed-${tag}`,
        expiry_date: Date.now() + HOUR,
        scope: 'scope1',
        token_type: 'Bearer',
      });
    /** A browser sign-in that completes `afterMs` from now with `refreshToken`. */
    const browserCompletes = (refreshToken: string, afterMs: number) =>
      authWithWeb.mockImplementation(async (client: any) => ({
        authUrl: 'https://accounts.example.test/auth',
        loginCompletePromise: new Promise<void>((resolve) =>
          setTimeout(() => {
            client.setCredentials(creds(refreshToken, HOUR));
            resolve();
          }, afterMs),
        ),
      }));
    const writeLock = async (pid: number, startedAt: number) => {
      await fsp.mkdir(path.dirname(AUTH_LOCK_PATH), { recursive: true });
      await fsp.writeFile(AUTH_LOCK_PATH, JSON.stringify({ pid, startedAt }));
    };
    const lockExists = () =>
      fsp.access(AUTH_LOCK_PATH).then(
        () => true,
        () => false,
      );

    beforeEach(async () => {
      stored = null;
      (OAuthCredentialStorage.loadCredentials as jest.Mock).mockImplementation(
        async () => (stored ? { ...stored } : null),
      );
      (OAuthCredentialStorage.saveCredentials as jest.Mock).mockImplementation(
        async (c: Record<string, unknown>) => {
          stored = { ...c };
        },
      );
      (shouldLaunchBrowser as jest.Mock).mockReturnValue(false);
      authWithWeb = jest.spyOn(AuthManager.prototype as any, 'authWithWeb');
      await fsp.rm(AUTH_LOCK_PATH, { force: true });
      manager = new AuthManager(['scope1'], FAST);
    });

    afterEach(async () => {
      authWithWeb.mockRestore();
      await fsp.rm(AUTH_LOCK_PATH, { force: true });
    });

    afterAll(async () => {
      await fsp.rm(path.dirname(AUTH_LOCK_PATH), {
        recursive: true,
        force: true,
      });
    });

    it('keeps the stored grant when the refresh endpoint answers 5xx', async () => {
      stored = creds('r1', -1000);
      (global.fetch as jest.Mock).mockResolvedValue(reply(500, 'boom'));

      const failure = manager.getAuthenticatedClient();
      await expect(failure).rejects.toThrow(
        /temporarily unavailable \(HTTP 500\); stored credentials were kept/,
      );
      await expect(failure).rejects.not.toThrow(AUTH_FAULT_RE);

      expect(global.fetch).toHaveBeenCalledTimes(3);
      expect(OAuthCredentialStorage.clearCredentials).not.toHaveBeenCalled();
      expect(stored?.refresh_token).toBe('r1');
      expect((manager as any).client).not.toBeNull();

      // The next call recovers by itself once the endpoint is back.
      (global.fetch as jest.Mock).mockResolvedValue(freshTokens('r1'));
      const client = await manager.getAuthenticatedClient();
      expect(client.credentials.access_token).toBe('refreshed-r1');
      expect(open).not.toHaveBeenCalled();
    });

    it('keeps the stored grant when the refresh request never completes', async () => {
      stored = creds('r1', -1000);
      (global.fetch as jest.Mock).mockRejectedValue(
        Object.assign(new TypeError('fetch failed'), {
          cause: { code: 'ECONNREFUSED' },
        }),
      );

      await expect(manager.getAuthenticatedClient()).rejects.toThrow(
        /temporarily unavailable \(ECONNREFUSED\)/,
      );
      expect(global.fetch).toHaveBeenCalledTimes(3);
      expect(OAuthCredentialStorage.clearCredentials).not.toHaveBeenCalled();
      expect(stored?.refresh_token).toBe('r1');
    });

    it('falls to sign-in on invalid_grant without deleting anything', async () => {
      stored = creds('r1', -1000);
      (global.fetch as jest.Mock).mockResolvedValue(invalidGrant());

      await expect(manager.getAuthenticatedClient()).rejects.toThrow(
        /No browser available/,
      );
      expect(global.fetch).toHaveBeenCalledTimes(1);
      expect(OAuthCredentialStorage.clearCredentials).not.toHaveBeenCalled();
      expect(stored?.refresh_token).toBe('r1');
    });

    it('adopts a newer stored grant when its own grant is revoked', async () => {
      stored = creds('r1', HOUR);
      await manager.getAuthenticatedClient();

      // This process's token expires; another process meanwhile signed in
      // again and stored a new grant whose access token is also stale.
      mockOAuth2Client.credentials.expiry_date = Date.now() - 1000;
      stored = creds('r2', -1000);
      (global.fetch as jest.Mock).mockImplementation(
        async (_url: string, init: { body: string }) =>
          init.body.includes('"r1"') ? invalidGrant() : freshTokens('r2'),
      );

      const client = await manager.getAuthenticatedClient();
      expect(client.credentials.refresh_token).toBe('r2');
      expect(client.credentials.access_token).toBe('refreshed-r2');
      expect(shouldLaunchBrowser).not.toHaveBeenCalled();
      expect(open).not.toHaveBeenCalled();
    });

    it('adopts fresher stored credentials instead of refreshing', async () => {
      stored = creds('r1', HOUR);
      await manager.getAuthenticatedClient();

      mockOAuth2Client.credentials.expiry_date = Date.now() - 1000;
      stored = { ...creds('r1', HOUR), access_token: 'from-sibling' };

      const client = await manager.getAuthenticatedClient();
      expect(client.credentials.access_token).toBe('from-sibling');
      expect(global.fetch).not.toHaveBeenCalled();
    });

    it('opens one browser sign-in for concurrent callers', async () => {
      (shouldLaunchBrowser as jest.Mock).mockReturnValue(true);
      browserCompletes('r-new', 30);

      const [a, b] = await Promise.all([
        manager.getAuthenticatedClient(),
        manager.getAuthenticatedClient(),
      ]);

      expect(a).toBe(b);
      expect(authWithWeb).toHaveBeenCalledTimes(1);
      expect(open).toHaveBeenCalledTimes(1);
      expect(stored?.refresh_token).toBe('r-new');
      expect(await lockExists()).toBe(false);
    });

    it('waits for the process holding the sign-in lock and adopts its grant', async () => {
      (shouldLaunchBrowser as jest.Mock).mockReturnValue(true);
      browserCompletes('never-used', 0);
      await writeLock(process.ppid, Date.now());
      setTimeout(() => {
        stored = creds('r-other', HOUR);
      }, 50);

      const client = await manager.getAuthenticatedClient();

      expect(client.credentials.refresh_token).toBe('r-other');
      expect(authWithWeb).not.toHaveBeenCalled();
      expect(open).not.toHaveBeenCalled();
      // Someone else's lock is theirs to release.
      expect(await lockExists()).toBe(true);
    });

    it('takes over a lock whose holder is dead', async () => {
      (shouldLaunchBrowser as jest.Mock).mockReturnValue(true);
      browserCompletes('r-new', 5);
      const deadPid = spawnSync(process.execPath, ['-e', '0']).pid;
      await writeLock(deadPid, Date.now());

      const client = await manager.getAuthenticatedClient();

      expect(client.credentials.refresh_token).toBe('r-new');
      expect(open).toHaveBeenCalledTimes(1);
      expect(await lockExists()).toBe(false);
    });

    it('takes over a lock older than the stale window', async () => {
      (shouldLaunchBrowser as jest.Mock).mockReturnValue(true);
      browserCompletes('r-new', 5);
      await writeLock(process.ppid, Date.now() - 7 * 60 * 1000);

      const client = await manager.getAuthenticatedClient();

      expect(client.credentials.refresh_token).toBe('r-new');
      expect(open).toHaveBeenCalledTimes(1);
    });

    it('never deletes a stored token whose scopes fall short', async () => {
      stored = { ...creds('r1', HOUR), scope: 'some-other-scope' };

      await expect(manager.getAuthenticatedClient()).rejects.toThrow(
        /No browser available/,
      );
      expect(OAuthCredentialStorage.clearCredentials).not.toHaveBeenCalled();
      expect(stored?.refresh_token).toBe('r1');
    });

    it('saves a sign-in the user completes after the wait timed out', async () => {
      (shouldLaunchBrowser as jest.Mock).mockReturnValue(true);
      manager = new AuthManager(['scope1'], { ...FAST, loginTimeoutMs: 30 });
      browserCompletes('r-late', 120);

      await expect(manager.getAuthenticatedClient()).rejects.toThrow(
        /Authentication timed out/,
      );
      expect(OAuthCredentialStorage.saveCredentials).not.toHaveBeenCalled();

      await new Promise((resolve) => setTimeout(resolve, 200));
      expect(OAuthCredentialStorage.saveCredentials).toHaveBeenCalledWith(
        expect.objectContaining({ refresh_token: 'r-late' }),
      );
      // The next call finds it without another browser round trip.
      const client = await manager.getAuthenticatedClient();
      expect(client.credentials.refresh_token).toBe('r-late');
      expect(open).toHaveBeenCalledTimes(1);
    });
  });
});
