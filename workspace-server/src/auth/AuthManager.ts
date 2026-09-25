/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { google, Auth } from 'googleapis';
import crypto from 'node:crypto';
import * as http from 'node:http';
import * as net from 'node:net';
import * as url from 'node:url';
import { logToFile } from '../utils/logger';
import open from '../utils/open-wrapper';
import { shouldLaunchBrowser } from '../utils/secure-browser-launcher';
import { OAuthCredentialStorage } from './token-storage/oauth-credential-storage';
import { loadConfig } from '../utils/config';

const config = loadConfig();
const CLIENT_ID = config.clientId;
const CLOUD_FUNCTION_URL = config.cloudFunctionUrl;
const TOKEN_EXPIRY_BUFFER_MS = 5 * 60 * 1000; // 5 minutes

/** Timing knobs, overridable so tests do not wait out real network backoff. */
export interface AuthTiming {
  /** Per-attempt deadline for the cloud function refresh call. */
  refreshTimeoutMs: number;
  /** Waits between refresh attempts; one more attempt than entries. */
  refreshRetryDelaysMs: readonly number[];
}

const DEFAULT_TIMING: AuthTiming = {
  refreshTimeoutMs: 15_000,
  refreshRetryDelaysMs: [1_000, 4_000],
};

/**
 * Google answered the refresh with `invalid_grant`: the stored refresh token
 * is revoked or expired and only a new sign-in (or a newer grant another
 * process already stored) can replace it. Every other refresh failure is
 * transient and leaves the stored credentials alone.
 */
export class RefreshGrantRevokedError extends Error {
  constructor(
    message = 'Stored Google grant is no longer valid (invalid_grant); a new sign-in is required.',
  ) {
    super(message);
    this.name = 'RefreshGrantRevokedError';
  }
}

const sleep = (ms: number) =>
  new Promise<void>((resolve) => setTimeout(resolve, ms));

/**
 * An Authentication URL for updating the credentials of a Oauth2Client
 * as well as a promise that will resolve when the credentials have
 * been refreshed (or which throws error when refreshing credentials failed).
 */
interface OauthWebLogin {
  authUrl: string;
  loginCompletePromise: Promise<void>;
}

export class AuthManager {
  private client: Auth.OAuth2Client | null = null;
  private scopes: string[];
  private onStatusUpdate: ((message: string) => void) | null = null;
  private timing: AuthTiming;

  constructor(scopes: string[], timing: Partial<AuthTiming> = {}) {
    this.scopes = scopes;
    this.timing = { ...DEFAULT_TIMING, ...timing };
  }

  public setOnStatusUpdate(callback: (message: string) => void) {
    this.onStatusUpdate = callback;
  }

  private isTokenExpiringSoon(credentials: Auth.Credentials): boolean {
    return !!(
      credentials.expiry_date &&
      credentials.expiry_date < Date.now() + TOKEN_EXPIRY_BUFFER_MS
    );
  }

  private missingScopes(credentials: Auth.Credentials): string[] {
    const savedScopes = new Set(credentials.scope?.split(' ') ?? []);
    return this.scopes.filter((scope) => !savedScopes.has(scope));
  }

  /**
   * Adopt the stored credentials when they are already usable as-is: another
   * process sharing this token file may have refreshed (or signed in again)
   * since this one last looked, and its fresh access token saves a refresh
   * round trip — and never races it.
   */
  private async adoptStoredIfUsable(
    client: Auth.OAuth2Client,
  ): Promise<boolean> {
    const stored = await OAuthCredentialStorage.loadCredentials().catch(
      (error) => {
        logToFile(`Could not read stored credentials: ${error}`);
        return null;
      },
    );
    if (
      !stored?.refresh_token ||
      this.missingScopes(stored).length > 0 ||
      this.isTokenExpiringSoon(stored)
    ) {
      return false;
    }
    client.setCredentials(stored);
    logToFile('Adopted fresher stored credentials; no refresh needed');
    return true;
  }

  /**
   * Stored credentials carrying a grant other than `staleRefreshToken`, with
   * every required scope: what a sign-in in another process leaves behind.
   */
  private async loadNewerGrant(
    staleRefreshToken: string | null | undefined,
  ): Promise<Auth.Credentials | null> {
    const stored = await OAuthCredentialStorage.loadCredentials().catch(
      () => null,
    );
    if (
      !stored?.refresh_token ||
      stored.refresh_token === staleRefreshToken ||
      this.missingScopes(stored).length > 0
    ) {
      return null;
    }
    return stored;
  }

  /**
   * Put `credentials` on `client` and make sure its access token is live.
   * False when that grant is itself revoked; a transient failure throws.
   */
  private async adoptGrant(
    client: Auth.OAuth2Client,
    credentials: Auth.Credentials,
  ): Promise<boolean> {
    client.setCredentials(credentials);
    if (!this.isTokenExpiringSoon(credentials)) return true;
    try {
      await this.refreshClient(client);
      return true;
    } catch (error) {
      if (error instanceof RefreshGrantRevokedError) return false;
      throw error;
    }
  }

  /**
   * Bring an expiring client back to a live access token without a sign-in
   * whenever one is avoidable: adopt what storage already holds, else
   * refresh, else — the grant is revoked — adopt a newer grant another
   * process stored. False only when no usable grant is left; a transient
   * refresh failure throws and leaves client and storage untouched.
   */
  private async ensureFresh(client: Auth.OAuth2Client): Promise<boolean> {
    if (await this.adoptStoredIfUsable(client)) return true;

    const heldRefreshToken = client.credentials.refresh_token;
    try {
      await this.refreshClient(client);
      logToFile('Token refreshed successfully');
      return true;
    } catch (error) {
      logToFile(`Failed to refresh token: ${error}`);
      if (!(error instanceof RefreshGrantRevokedError)) throw error;
    }

    const newer = await this.loadNewerGrant(heldRefreshToken);
    if (!newer) return false;
    logToFile('Held grant is revoked; adopting the newer stored grant');
    return this.adoptGrant(client, newer);
  }

  private async loadCachedCredentials(
    client: Auth.OAuth2Client,
  ): Promise<boolean> {
    const credentials = await OAuthCredentialStorage.loadCredentials();

    if (credentials) {
      // Check if saved token has required scopes
      logToFile(`Cached token has scopes: ${credentials.scope ?? ''}`);
      logToFile(`Required scopes: ${this.scopes.join(', ')}`);

      const missingScopes = this.missingScopes(credentials);

      if (missingScopes.length > 0) {
        logToFile(
          `Token cache missing required scopes: ${missingScopes.join(', ')}`,
        );
        logToFile('Removing cached token to force re-authentication...');
        await OAuthCredentialStorage.clearCredentials();
        return false;
      } else {
        client.setCredentials(credentials);
        return true;
      }
    }

    return false;
  }

  public async getAuthenticatedClient(): Promise<Auth.OAuth2Client> {
    logToFile('getAuthenticatedClient called');

    // Check if we have a cached client with valid credentials
    if (
      this.client &&
      this.client.credentials &&
      this.client.credentials.refresh_token
    ) {
      logToFile('Returning existing cached client with valid credentials');
      logToFile(
        `Access token exists: ${!!this.client.credentials.access_token}`,
      );
      logToFile(`Expiry date: ${this.client.credentials.expiry_date}`);
      logToFile(`Current time: ${Date.now()}`);

      const isExpired = this.isTokenExpiringSoon(this.client.credentials);
      logToFile(`Token expired: ${isExpired}`);
      if (!isExpired) return this.client;

      // Proactively refresh. A transient failure throws and keeps the client
      // and the stored grant (the next call retries); only a revoked grant
      // with nothing newer stored falls through to a new sign-in, and even
      // then the stored credentials are left for that sign-in to replace.
      logToFile('Token is expired, refreshing proactively...');
      const held = this.client;
      if (await this.ensureFresh(held)) return held;
      this.client = null;
      return this.interactiveLogin(this.createOAuthClient());
    }

    const oAuth2Client = this.createOAuthClient();

    logToFile('No valid cached client, checking for saved credentials...');
    if (await this.loadCachedCredentials(oAuth2Client)) {
      logToFile('Loaded saved credentials, caching and returning client');
      this.client = oAuth2Client;

      const isExpired = this.isTokenExpiringSoon(oAuth2Client.credentials);
      logToFile(`Token expired: ${isExpired}`);
      if (!isExpired) return oAuth2Client;

      logToFile('Loaded token is expired, refreshing proactively...');
      if (await this.ensureFresh(oAuth2Client)) return oAuth2Client;
      this.client = null;
    }

    return this.interactiveLogin(oAuth2Client);
  }

  private createOAuthClient(): Auth.OAuth2Client {
    // Note: No clientSecret is provided here. The secret is only known by the cloud function.
    const options: Auth.OAuth2ClientOptions = {
      clientId: CLIENT_ID,
    };
    const oAuth2Client = new google.auth.OAuth2(options);

    oAuth2Client.on('tokens', async (tokens) => {
      logToFile('Tokens refreshed event received');
      if (tokens.refresh_token) {
        logToFile('New refresh token received in event');
      }

      try {
        // Create a copy to preserve refresh_token from storage
        const current = (await OAuthCredentialStorage.loadCredentials()) || {};
        const merged = {
          ...tokens,
          refresh_token: tokens.refresh_token || current.refresh_token,
        };
        await OAuthCredentialStorage.saveCredentials(merged);
        logToFile('Credentials saved after refresh');
      } catch (e) {
        logToFile(`Error saving refreshed credentials: ${e}`);
      }
    });

    return oAuth2Client;
  }

  private async interactiveLogin(
    oAuth2Client: Auth.OAuth2Client,
  ): Promise<Auth.OAuth2Client> {
    // Fail fast in headless environments instead of hanging for 5 minutes
    if (!shouldLaunchBrowser()) {
      throw new Error(
        'No browser available for authentication. ' +
          'Please run: node dist/headless-login.js\n' +
          '(from the workspace-server directory)\n' +
          'After authenticating, retry your request.',
      );
    }

    const webLogin = await this.authWithWeb(oAuth2Client);
    await open(webLogin.authUrl);
    const msg = 'Waiting for authentication... Check your browser.';
    logToFile(msg);
    if (this.onStatusUpdate) {
      this.onStatusUpdate(msg);
    }

    // Add timeout to prevent infinite waiting when browser tab gets stuck
    const authTimeout = 5 * 60 * 1000; // 5 minutes timeout
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => {
        reject(
          new Error(
            'User is not authenticated. Authentication timed out after 5 minutes. The user did not complete the login process in the browser. ' +
              'Please ask the user to check their browser and try again.',
          ),
        );
      }, authTimeout);
    });
    await Promise.race([webLogin.loginCompletePromise, timeoutPromise]);

    await OAuthCredentialStorage.saveCredentials(oAuth2Client.credentials);
    this.client = oAuth2Client;
    return this.client;
  }

  public async clearAuth(): Promise<void> {
    logToFile('Clearing authentication...');
    this.client = null;
    await OAuthCredentialStorage.clearCredentials();
    logToFile('Authentication cleared.');
  }

  public async refreshToken(): Promise<void> {
    logToFile('Manual token refresh triggered');
    if (!this.client) {
      logToFile('No client available to refresh, getting new client');
      this.client = await this.getAuthenticatedClient();
    }
    await this.refreshClient(this.client);
  }

  private async refreshClient(client: Auth.OAuth2Client): Promise<void> {
    try {
      const currentCredentials = { ...client.credentials };

      if (!currentCredentials.refresh_token) {
        throw new Error('No refresh token available');
      }

      const newTokens = await this.requestRefreshedTokens(
        currentCredentials.refresh_token,
      );

      // Merge new tokens with existing credentials, preserving refresh_token
      // Note: Google does NOT return a new refresh_token on refresh
      const mergedCredentials = {
        ...newTokens,
        refresh_token: currentCredentials.refresh_token, // Always preserve original
      };

      client.setCredentials(mergedCredentials);
      await OAuthCredentialStorage.saveCredentials(mergedCredentials);
      logToFile('Token refreshed and saved successfully via cloud function');
    } catch (error) {
      logToFile(`Error during token refresh: ${error}`);
      throw error;
    }
  }

  /**
   * One refresh round trip through the cloud function (it holds the client
   * secret), retried on anything that is not Google rejecting the grant.
   * Throws `RefreshGrantRevokedError` only on a 400/401 `invalid_grant`;
   * every other failure ends in an error whose text names no auth fault, so
   * a caller never mistakes a network blip for a dead grant.
   */
  private async requestRefreshedTokens(
    refreshToken: string,
  ): Promise<Auth.Credentials> {
    const delays = this.timing.refreshRetryDelaysMs;
    let lastFailure = 'unknown error';

    for (let attempt = 0; attempt <= delays.length; attempt++) {
      if (attempt > 0) await sleep(delays[attempt - 1]);
      logToFile(
        `Calling cloud function to refresh token (attempt ${attempt + 1})...`,
      );

      let response: Response;
      try {
        response = await fetch(`${CLOUD_FUNCTION_URL}/refreshToken`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ refresh_token: refreshToken }),
          signal: AbortSignal.timeout(this.timing.refreshTimeoutMs),
        });
      } catch (error) {
        const err = error as Error & { cause?: { code?: string } };
        lastFailure = err?.cause?.code ?? err?.name ?? String(error);
        logToFile(`Token refresh request did not complete: ${lastFailure}`);
        continue;
      }

      if (response.ok) {
        try {
          const tokens = (await response.json()) as Auth.Credentials;
          if (tokens?.access_token) return tokens;
          lastFailure = 'response carried no access token';
        } catch {
          lastFailure = 'unparsable response';
        }
        logToFile(`Token refresh returned no usable tokens: ${lastFailure}`);
        continue;
      }

      const body = await response.text().catch(() => '');
      if (
        (response.status === 400 || response.status === 401) &&
        body.includes('invalid_grant')
      ) {
        logToFile('Token refresh rejected by Google: invalid_grant');
        throw new RefreshGrantRevokedError();
      }
      lastFailure = `HTTP ${response.status}`;
      logToFile(`Token refresh attempt failed: ${lastFailure}`);
    }

    throw new Error(
      `Google token refresh is temporarily unavailable (${lastFailure}); stored credentials were kept, retry shortly.`,
    );
  }

  private async getAvailablePort(): Promise<number> {
    return new Promise((resolve, reject) => {
      let port = 0;
      try {
        const portStr = process.env['OAUTH_CALLBACK_PORT'];
        if (portStr) {
          port = parseInt(portStr, 10);
          if (isNaN(port) || port <= 0 || port > 65535) {
            return reject(
              new Error(`Invalid value for OAUTH_CALLBACK_PORT: "${portStr}"`),
            );
          }
          return resolve(port);
        }
        const server = net.createServer();
        server.listen(0, () => {
          const address = server.address()! as net.AddressInfo;
          port = address.port;
        });
        server.on('listening', () => {
          server.close();
          server.unref();
        });
        server.on('error', (e) => reject(e));
        server.on('close', () => resolve(port));
      } catch (e) {
        reject(e);
      }
    });
  }

  private async authWithWeb(client: Auth.OAuth2Client): Promise<OauthWebLogin> {
    logToFile(
      `Requesting authentication with scopes: ${this.scopes.join(', ')}`,
    );

    const port = await this.getAvailablePort();
    const host = process.env['OAUTH_CALLBACK_HOST'] || 'localhost';

    const localRedirectUri = `http://${host}:${port}/oauth2callback`;

    const isGuiAvailable = shouldLaunchBrowser();

    // SECURITY: Generate a random token for CSRF protection.
    const csrfToken = crypto.randomBytes(32).toString('hex');

    // The state now contains a JSON payload indicating the flow mode and CSRF token.
    const statePayload = {
      uri: isGuiAvailable ? localRedirectUri : undefined,
      manual: !isGuiAvailable,
      csrf: csrfToken,
    };
    const state = Buffer.from(JSON.stringify(statePayload)).toString('base64');

    // The redirect URI for Google's auth server is the cloud function
    const cloudFunctionRedirectUri = CLOUD_FUNCTION_URL;

    const authUrl = client.generateAuthUrl({
      redirect_uri: cloudFunctionRedirectUri, // Tell Google to go to the cloud function
      access_type: 'offline',
      scope: this.scopes,
      state: state, // Pass our JSON payload in the state
      prompt: 'consent', // Make sure we get a refresh token
    });

    const loginCompletePromise = new Promise<void>((resolve, reject) => {
      const server = http.createServer(async (req, res) => {
        try {
          // Use startsWith for more robust path checking.
          if (!req.url || !req.url.startsWith('/oauth2callback')) {
            res.end();
            reject(
              new Error(
                'OAuth callback not received. Unexpected request: ' + req.url,
              ),
            );
            return;
          }

          const qs = new url.URL(req.url, `http://${host}:${port}`)
            .searchParams;

          // SECURITY: Validate the state parameter to prevent CSRF attacks.
          const returnedState = qs.get('state');
          if (returnedState !== csrfToken) {
            res.end('State mismatch. Possible CSRF attack.');
            reject(new Error('OAuth state mismatch. Possible CSRF attack.'));
            return;
          }

          if (qs.get('error')) {
            const errorCode = qs.get('error');
            const errorDescription =
              qs.get('error_description') || 'No additional details provided';
            res.end();
            reject(
              new Error(
                `Google OAuth error: ${errorCode}. ${errorDescription}`,
              ),
            );
            return;
          }

          const access_token = qs.get('access_token');
          const refresh_token = qs.get('refresh_token');
          const scope = qs.get('scope');
          const token_type = qs.get('token_type');
          const expiry_date_str = qs.get('expiry_date');

          if (access_token && expiry_date_str) {
            const tokens: Auth.Credentials = {
              access_token: access_token,
              refresh_token: refresh_token || null,
              scope: scope || undefined,
              token_type: (token_type as 'Bearer') || undefined,
              expiry_date: parseInt(expiry_date_str, 10),
            };
            client.setCredentials(tokens);
            res.end('Authentication successful! Please return to the console.');
            resolve();
          } else {
            reject(
              new Error(
                'Authentication failed: Did not receive tokens from callback.',
              ),
            );
          }
        } catch (e) {
          reject(e);
        } finally {
          server.close();
        }
      });

      server.listen(port, host, () => {
        // Server started successfully
      });

      server.on('error', (err) => {
        reject(new Error(`OAuth callback server error: ${err}`));
      });
    });

    return {
      authUrl,
      loginCompletePromise,
    };
  }
}
