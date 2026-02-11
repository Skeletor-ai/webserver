import { randomBytes } from 'node:crypto';
import type { Express, Request, Response } from 'express';
import {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import type {
    AuthenticatorTransportFuture,
    Base64URLString,
    RegistrationResponseJSON,
    AuthenticationResponseJSON,
} from '@simplewebauthn/server';

import type { OAuth2Model } from './oauth2-model';
import { oauthTokenToResponse } from './utils';

/** A stored WebAuthn credential */
export interface StoredCredential {
    credentialId: Base64URLString;
    publicKey: string; // base64-encoded Uint8Array
    counter: number;
    transports?: AuthenticatorTransportFuture[];
    name: string;
    createdAt: number;
}

/** Options passed to setupWebAuthnRoutes */
export interface WebAuthnOptions {
    rpId: string;
    rpName: string;
    /** Expected origin(s), e.g. "https://iobroker.example.com:8081" */
    expectedOrigins: string | string[];
}

/** Challenge stored in session */
interface ChallengeSession {
    challenge: string;
    userId?: string; // system.user.xxx - set for register + 2fa
    type: 'register' | 'login' | '2fa';
    timestamp: number;
}

const CHALLENGE_TTL = 300; // 5 minutes

/**
 * Get the authenticated user from the request (set by authorize middleware or cookie)
 */
function getAuthenticatedUser(req: Request): string | undefined {
    return (req as Request & { user?: string }).user;
}

/**
 * Get user's WebAuthn credentials from the database
 */
async function getUserCredentials(adapter: ioBroker.Adapter, userId: string): Promise<StoredCredential[]> {
    const obj = await adapter.getForeignObjectAsync(`system.user.${userId}`);
    if (!obj?.native?.webauthn) {
        return [];
    }
    return obj.native.webauthn as StoredCredential[];
}

/**
 * Save user's WebAuthn credentials to the database
 */
async function saveUserCredentials(
    adapter: ioBroker.Adapter,
    userId: string,
    credentials: StoredCredential[],
): Promise<void> {
    await adapter.extendForeignObjectAsync(`system.user.${userId}`, {
        native: { webauthn: credentials },
    });
}

/**
 * Check if user has 2FA enabled
 */
async function is2FAEnabled(adapter: ioBroker.Adapter, userId: string): Promise<boolean> {
    const obj = await adapter.getForeignObjectAsync(`system.user.${userId}`);
    // @ts-expect-error webauthn2FA is not in the standard type
    return obj?.common?.webauthn2FA === true;
}

/**
 * Store a challenge in ioBroker session storage
 */
function storeChallenge(adapter: ioBroker.Adapter, challengeId: string, data: ChallengeSession): Promise<void> {
    return new Promise<void>((resolve, reject) =>
        adapter.setSession(`webauthn:${challengeId}`, CHALLENGE_TTL, data as any, err =>
            err ? reject(err) : resolve(),
        ),
    );
}

/**
 * Retrieve and consume a challenge from session storage
 */
function getChallenge(adapter: ioBroker.Adapter, challengeId: string): Promise<ChallengeSession | null> {
    return new Promise<ChallengeSession | null>(resolve => {
        adapter.getSession(`webauthn:${challengeId}`, (session: any) => {
            if (session) {
                // consume it
                void adapter.destroySession(`webauthn:${challengeId}`);
            }
            resolve(session as ChallengeSession | null);
        });
    });
}

/**
 * Setup all WebAuthn routes on the Express app.
 *
 * @param app Express app
 * @param adapter ioBroker adapter
 * @param model OAuth2Model for token generation
 * @param options WebAuthn configuration
 */
export function setupWebAuthnRoutes(
    app: Express,
    adapter: ioBroker.Adapter,
    model: OAuth2Model,
    options: WebAuthnOptions,
): void {
    const { rpId, rpName, expectedOrigins } = options;

    // ---- Registration ----

    /** POST /webauthn/register/options - Generate registration options (requires auth) */
    app.post('/webauthn/register/options', async (req: Request, res: Response): Promise<void> => {
        try {
            const userId = getAuthenticatedUser(req);
            if (!userId) {
                res.status(401).json({ error: 'Authentication required' });
                return;
            }

            const existingCredentials = await getUserCredentials(adapter, userId);

            const regOptions = await generateRegistrationOptions({
                rpName,
                rpID: rpId,
                userName: userId,
                excludeCredentials: existingCredentials.map(c => ({
                    id: c.credentialId,
                    transports: c.transports,
                })),
                authenticatorSelection: {
                    residentKey: 'preferred',
                    userVerification: 'preferred',
                },
            });

            const challengeId = randomBytes(32).toString('hex');
            await storeChallenge(adapter, challengeId, {
                challenge: regOptions.challenge,
                userId,
                type: 'register',
                timestamp: Date.now(),
            });

            res.json({ ...regOptions, challengeId });
        } catch (e) {
            adapter.log.error(`WebAuthn register/options error: ${(e as Error).message}`);
            res.status(500).json({ error: 'Internal error' });
        }
    });

    /** POST /webauthn/register/verify - Verify registration (requires auth) */
    app.post('/webauthn/register/verify', async (req: Request, res: Response): Promise<void> => {
        try {
            const userId = getAuthenticatedUser(req);
            if (!userId) {
                res.status(401).json({ error: 'Authentication required' });
                return;
            }

            const { challengeId, credential, name: credName } = req.body as {
                challengeId: string;
                credential: RegistrationResponseJSON;
                name?: string;
            };

            const session = await getChallenge(adapter, challengeId);
            if (!session || session.type !== 'register' || session.userId !== userId) {
                res.status(400).json({ error: 'Invalid or expired challenge' });
                return;
            }

            const verification = await verifyRegistrationResponse({
                response: credential,
                expectedChallenge: session.challenge,
                expectedOrigin: expectedOrigins,
                expectedRPID: rpId,
            });

            if (!verification.verified || !verification.registrationInfo) {
                res.status(400).json({ error: 'Verification failed' });
                return;
            }

            const { credential: cred } = verification.registrationInfo;

            const storedCred: StoredCredential = {
                credentialId: cred.id,
                publicKey: Buffer.from(cred.publicKey).toString('base64'),
                counter: cred.counter,
                transports: cred.transports,
                name: credName || `Passkey ${new Date().toLocaleDateString()}`,
                createdAt: Date.now(),
            };

            const existing = await getUserCredentials(adapter, userId);
            existing.push(storedCred);
            await saveUserCredentials(adapter, userId, existing);

            res.json({ success: true, credentialName: storedCred.name });
        } catch (e) {
            adapter.log.error(`WebAuthn register/verify error: ${(e as Error).message}`);
            res.status(500).json({ error: 'Internal error' });
        }
    });

    // ---- Authentication ----

    /** POST /webauthn/login/options - Generate authentication options (no auth required) */
    app.post('/webauthn/login/options', async (req: Request, res: Response): Promise<void> => {
        try {
            const { username } = req.body as { username?: string };

            let allowCredentials:
                | { id: Base64URLString; transports?: AuthenticatorTransportFuture[] }[]
                | undefined;

            if (username) {
                const credentials = await getUserCredentials(adapter, username);
                if (credentials.length === 0) {
                    res.status(400).json({ error: 'No passkeys registered for this user' });
                    return;
                }
                allowCredentials = credentials.map(c => ({
                    id: c.credentialId,
                    transports: c.transports,
                }));
            }
            // If no username, use discoverable credentials (allowCredentials undefined)

            const authOptions = await generateAuthenticationOptions({
                rpID: rpId,
                allowCredentials,
                userVerification: 'preferred',
            });

            const challengeId = randomBytes(32).toString('hex');
            await storeChallenge(adapter, challengeId, {
                challenge: authOptions.challenge,
                userId: username,
                type: 'login',
                timestamp: Date.now(),
            });

            res.json({ ...authOptions, challengeId });
        } catch (e) {
            adapter.log.error(`WebAuthn login/options error: ${(e as Error).message}`);
            res.status(500).json({ error: 'Internal error' });
        }
    });

    /** POST /webauthn/login/verify - Verify authentication and issue token */
    app.post('/webauthn/login/verify', async (req: Request, res: Response): Promise<void> => {
        try {
            const { challengeId, credential } = req.body as {
                challengeId: string;
                credential: AuthenticationResponseJSON;
            };

            const session = await getChallenge(adapter, challengeId);
            if (!session || session.type !== 'login') {
                res.status(400).json({ error: 'Invalid or expired challenge' });
                return;
            }

            // Find the credential across all users
            const { userId, storedCred } = await findCredentialByIdAcrossUsers(
                adapter,
                credential.id,
                session.userId,
            );

            if (!userId || !storedCred) {
                res.status(400).json({ error: 'Unknown credential' });
                return;
            }

            const verification = await verifyAuthenticationResponse({
                response: credential,
                expectedChallenge: session.challenge,
                expectedOrigin: expectedOrigins,
                expectedRPID: rpId,
                credential: {
                    id: storedCred.credentialId,
                    publicKey: new Uint8Array(Buffer.from(storedCred.publicKey, 'base64')),
                    counter: storedCred.counter,
                    transports: storedCred.transports,
                },
            });

            if (!verification.verified) {
                res.status(400).json({ error: 'Authentication failed' });
                return;
            }

            // Update counter
            storedCred.counter = verification.authenticationInfo.newCounter;
            const allCreds = await getUserCredentials(adapter, userId);
            const idx = allCreds.findIndex(c => c.credentialId === storedCred.credentialId);
            if (idx >= 0) {
                allCreds[idx] = storedCred;
                await saveUserCredentials(adapter, userId, allCreds);
            }

            // Generate OAuth tokens
            const token = await model.generateTokens(userId);
            const responseToken = oauthTokenToResponse(token);

            const cookieOptions = {
                httpOnly: true,
                secure: false, // will be overridden by caller if needed
                sameSite: 'strict' as const,
            };

            res.cookie('access_token', responseToken.access_token, cookieOptions);
            res.json(responseToken);
        } catch (e) {
            adapter.log.error(`WebAuthn login/verify error: ${(e as Error).message}`);
            res.status(500).json({ error: 'Internal error' });
        }
    });

    // ---- 2FA ----

    /** POST /webauthn/2fa/verify - Verify 2FA challenge after password login */
    app.post('/webauthn/2fa/verify', async (req: Request, res: Response): Promise<void> => {
        try {
            const { challengeId, credential } = req.body as {
                challengeId: string;
                credential: AuthenticationResponseJSON;
            };

            const session = await getChallenge(adapter, challengeId);
            if (!session || session.type !== '2fa' || !session.userId) {
                res.status(400).json({ error: 'Invalid or expired 2FA challenge' });
                return;
            }

            const storedCreds = await getUserCredentials(adapter, session.userId);
            const storedCred = storedCreds.find(c => c.credentialId === credential.id);

            if (!storedCred) {
                res.status(400).json({ error: 'Unknown credential' });
                return;
            }

            const verification = await verifyAuthenticationResponse({
                response: credential,
                expectedChallenge: session.challenge,
                expectedOrigin: expectedOrigins,
                expectedRPID: rpId,
                credential: {
                    id: storedCred.credentialId,
                    publicKey: new Uint8Array(Buffer.from(storedCred.publicKey, 'base64')),
                    counter: storedCred.counter,
                    transports: storedCred.transports,
                },
            });

            if (!verification.verified) {
                res.status(400).json({ error: '2FA verification failed' });
                return;
            }

            // Update counter
            storedCred.counter = verification.authenticationInfo.newCounter;
            const idx = storedCreds.findIndex(c => c.credentialId === storedCred.credentialId);
            if (idx >= 0) {
                storedCreds[idx] = storedCred;
                await saveUserCredentials(adapter, session.userId, storedCreds);
            }

            // Generate OAuth tokens
            const token = await model.generateTokens(session.userId);
            const responseToken = oauthTokenToResponse(token);

            res.cookie('access_token', responseToken.access_token, {
                httpOnly: true,
                sameSite: 'strict',
            });
            res.json(responseToken);
        } catch (e) {
            adapter.log.error(`WebAuthn 2fa/verify error: ${(e as Error).message}`);
            res.status(500).json({ error: 'Internal error' });
        }
    });

    // ---- Credential Management ----

    /** GET /webauthn/credentials - List user's credentials (without publicKey) */
    app.get('/webauthn/credentials', async (req: Request, res: Response): Promise<void> => {
        try {
            const userId = getAuthenticatedUser(req);
            if (!userId) {
                res.status(401).json({ error: 'Authentication required' });
                return;
            }

            const credentials = await getUserCredentials(adapter, userId);
            // Strip publicKey for security
            const safe = credentials.map(c => ({
                credentialId: c.credentialId,
                name: c.name,
                createdAt: c.createdAt,
                transports: c.transports,
            }));

            res.json(safe);
        } catch (e) {
            adapter.log.error(`WebAuthn credentials list error: ${(e as Error).message}`);
            res.status(500).json({ error: 'Internal error' });
        }
    });

    /** DELETE /webauthn/credentials/:credentialId - Remove a credential */
    app.delete('/webauthn/credentials/:credentialId', async (req: Request, res: Response): Promise<void> => {
        try {
            const userId = getAuthenticatedUser(req);
            if (!userId) {
                res.status(401).json({ error: 'Authentication required' });
                return;
            }

            const { credentialId } = req.params;
            const credentials = await getUserCredentials(adapter, userId);
            const filtered = credentials.filter(c => c.credentialId !== credentialId);

            if (filtered.length === credentials.length) {
                res.status(404).json({ error: 'Credential not found' });
                return;
            }

            await saveUserCredentials(adapter, userId, filtered);

            // If no more credentials, disable 2FA
            if (filtered.length === 0) {
                await adapter.extendForeignObjectAsync(`system.user.${userId}`, {
                    common: { webauthn2FA: false } as any,
                });
            }

            res.json({ success: true });
        } catch (e) {
            adapter.log.error(`WebAuthn credential delete error: ${(e as Error).message}`);
            res.status(500).json({ error: 'Internal error' });
        }
    });
}

/**
 * Find a WebAuthn credential across all users by credential ID.
 * If hintUserId is provided, check that user first.
 */
async function findCredentialByIdAcrossUsers(
    adapter: ioBroker.Adapter,
    credentialId: string,
    hintUserId?: string,
): Promise<{ userId: string; storedCred: StoredCredential } | { userId: undefined; storedCred: undefined }> {
    // Check hint user first
    if (hintUserId) {
        const creds = await getUserCredentials(adapter, hintUserId);
        const found = creds.find(c => c.credentialId === credentialId);
        if (found) {
            return { userId: hintUserId, storedCred: found };
        }
    }

    // Search all users
    const objView = await adapter.getObjectViewAsync('system', 'user', {
        startkey: 'system.user.',
        endkey: 'system.user.\u9999',
    });

    for (const row of objView.rows) {
        const creds = (row.value?.native as any)?.webauthn as StoredCredential[] | undefined;
        if (creds) {
            const found = creds.find(c => c.credentialId === credentialId);
            if (found) {
                const userId = row.id.replace(/^system\.user\./, '');
                return { userId, storedCred: found };
            }
        }
    }

    return { userId: undefined, storedCred: undefined };
}

/**
 * Generate a 2FA challenge for a user (called from the token endpoint).
 * Returns the challenge options to send to the client.
 */
export async function generate2FAChallenge(
    adapter: ioBroker.Adapter,
    userId: string,
    rpId: string,
): Promise<{ challengeId: string; options: any } | null> {
    const credentials = await getUserCredentials(adapter, userId);
    if (credentials.length === 0) {
        return null;
    }

    const authOptions = await generateAuthenticationOptions({
        rpID: rpId,
        allowCredentials: credentials.map(c => ({
            id: c.credentialId,
            transports: c.transports,
        })),
        userVerification: 'discouraged', // 2FA — user already proved identity with password
    });

    const challengeId = randomBytes(32).toString('hex');
    await storeChallenge(adapter, challengeId, {
        challenge: authOptions.challenge,
        userId,
        type: '2fa',
        timestamp: Date.now(),
    });

    return { challengeId, options: authOptions };
}

export { is2FAEnabled, getUserCredentials };
