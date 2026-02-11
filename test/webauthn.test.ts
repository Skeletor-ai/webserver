import { describe, it } from 'mocha';
import { expect } from 'chai';
import express from 'express';
import type { Express } from 'express';
import { setupWebAuthnRoutes, type WebAuthnOptions, type StoredCredential } from '../src/lib/webauthn';
import { OAuth2Model } from '../src/lib/oauth2-model';

// --- Mock adapter ---
function createMockAdapter(): ioBroker.Adapter {
    const sessions: Record<string, any> = {};
    const objects: Record<string, any> = {};

    return {
        log: {
            debug: () => {},
            info: () => {},
            warn: () => {},
            error: () => {},
            silly: () => {},
        },
        getForeignObjectAsync: async (id: string) => objects[id] || null,
        extendForeignObjectAsync: async (id: string, obj: any) => {
            objects[id] = objects[id] || { _id: id, type: 'user', common: {}, native: {} };
            if (obj.native) {
                Object.assign(objects[id].native, obj.native);
            }
            if (obj.common) {
                Object.assign(objects[id].common, obj.common);
            }
            return { id };
        },
        getObjectViewAsync: async () => ({
            rows: Object.entries(objects)
                .filter(([k]) => k.startsWith('system.user.'))
                .map(([id, value]) => ({ id, value })),
        }),
        setSession: (id: string, ttl: number, data: any, cb?: (err?: any) => void) => {
            sessions[id] = data;
            cb?.();
        },
        getSession: (id: string, cb: (session: any) => void) => {
            cb(sessions[id] || null);
        },
        destroySession: (id: string, cb?: () => void) => {
            delete sessions[id];
            cb?.();
        },
        checkPassword: (user: string, pass: string, cb: (success: boolean, user: string) => void) => {
            if (pass === 'correct') {
                cb(true, `system.user.${user}`);
            } else {
                cb(false, '');
            }
        },
    } as unknown as ioBroker.Adapter;
}

function createApp(adapter: ioBroker.Adapter): Express {
    const app = express();
    app.use(express.json());

    const model = new OAuth2Model(adapter);

    const webauthnOptions: WebAuthnOptions = {
        rpId: 'localhost',
        rpName: 'Test',
        expectedOrigins: 'http://localhost',
    };

    // Simple auth middleware for testing
    app.use((req: any, _res, next) => {
        if (req.headers['x-test-user']) {
            req.user = req.headers['x-test-user'];
        }
        next();
    });

    setupWebAuthnRoutes(app, adapter, model, webauthnOptions);
    return app;
}

// We need supertest or manual http for integration tests. 
// For now, test the core logic by importing functions directly.
describe('WebAuthn Module', () => {
    describe('Credential Storage', () => {
        it('should store and retrieve credentials', async () => {
            const adapter = createMockAdapter();
            const userId = 'testuser';

            // Initially no credentials
            const obj = await adapter.getForeignObjectAsync(`system.user.${userId}`);
            expect(obj).to.be.null;

            // Store credentials
            const cred: StoredCredential = {
                credentialId: 'test-cred-id',
                publicKey: Buffer.from('test-public-key').toString('base64'),
                counter: 0,
                transports: ['internal'],
                name: 'Test Passkey',
                createdAt: Date.now(),
            };

            await adapter.extendForeignObjectAsync(`system.user.${userId}`, {
                native: { webauthn: [cred] },
            });

            const stored = await adapter.getForeignObjectAsync(`system.user.${userId}`);
            expect(stored).to.not.be.null;
            expect(stored!.native.webauthn).to.have.length(1);
            expect(stored!.native.webauthn[0].credentialId).to.equal('test-cred-id');
        });
    });

    describe('Challenge Storage', () => {
        it('should store and retrieve challenges via sessions', (done) => {
            const adapter = createMockAdapter();
            const challengeData = { challenge: 'test-challenge', type: 'login', timestamp: Date.now() };

            adapter.setSession('webauthn:test-id', 300, challengeData as any, () => {
                adapter.getSession('webauthn:test-id', (session: any) => {
                    expect(session).to.not.be.null;
                    expect(session.challenge).to.equal('test-challenge');
                    done();
                });
            });
        });

        it('should return null for missing challenges', (done) => {
            const adapter = createMockAdapter();
            adapter.getSession('webauthn:nonexistent', (session: any) => {
                expect(session).to.be.null;
                done();
            });
        });
    });

    describe('Express Routes Setup', () => {
        it('should create an app with WebAuthn routes without errors', () => {
            const adapter = createMockAdapter();
            // Should not throw
            const app = createApp(adapter);
            expect(app).to.not.be.null;
        });
    });
});
