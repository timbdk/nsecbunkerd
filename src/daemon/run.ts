import NDK, { NDKEvent, NDKPrivateKeySigner, Nip46PermitCallback, Nip46PermitCallbackParams } from '@nostr-dev-kit/ndk';
import { log, auditSigningRequest, logStartup, logError } from '../lib/logger.js';
import { nip19 } from 'nostr-tools';
import { Backend } from './backend/index.js';
import {
    IMethod,
    checkIfPubkeyAllowed,
} from './lib/acl/index.js';
import AdminInterface from './admin/index.js';
import { IConfig } from '../config/index.js';
import { NDKRpcRequest } from '@nostr-dev-kit/ndk';
import prisma from '../db.js';
import { DaemonConfig } from './index.js';
import { decryptNsec } from '../config/keys.js';
import { requestAuthorization } from './authorize.js';
import Fastify, { type FastifyInstance } from 'fastify';
import FastifyFormBody from "@fastify/formbody";
import FastifyView from '@fastify/view';
import Handlebars from "handlebars";
import { authorizeRequestWebHandler, processRequestWebHandler } from "./web/authorize.js";
import { processRegistrationWebHandler } from "./web/authorize.js";

export type Key = {
    name: string;
    npub?: string;
};

export type KeyUser = {
    name: string;
    pubkey: string;
    description?: string;
    createdAt: Date;
    lastUsedAt?: Date;
};

function getKeys(config: DaemonConfig) {
    return async (): Promise<Key[]> => {
        let lockedKeyNames = Object.keys(config.allKeys);
        const keys: Key[] = [];

        for (const [name, nsec] of Object.entries(config.keys)) {
            const hexpk = nip19.decode(nsec).data as string;
            const user = await new NDKPrivateKeySigner(hexpk).user();
            const key = {
                name,
                npub: user.npub,
                userCount: await prisma.keyUser.count({ where: { keyName: name } }),
                tokenCount: await prisma.token.count({ where: { keyName: name } })
            };

            lockedKeyNames = lockedKeyNames.filter((keyName) => keyName !== name);
            keys.push(key);
        }

        for (const name of lockedKeyNames) {
            keys.push({ name });
        }

        return keys;
    };
}

function getKeyUsers(config: IConfig) {
    return async (req: NDKRpcRequest): Promise<KeyUser[]> => {
        const keyUsers: KeyUser[] = [];
        const keyName = req.params[0];

        const users = await prisma.keyUser.findMany({
            where: {
                keyName,
            },
            include: {
                signingConditions: true,
            },
        });

        for (const user of users) {
            const keyUser = {
                id: user.id,
                name: user.keyName,
                pubkey: user.userPubkey,
                description: user.description || undefined,
                createdAt: user.createdAt,
                lastUsedAt: user.lastUsedAt || undefined,
                revokedAt: user.revokedAt || undefined,
                signingConditions: user.signingConditions, // Include signing conditions
            };

            keyUsers.push(keyUser);
        }

        return keyUsers;
    };
}

/**
 * Called by the NDKNip46Backend when an action requires authorization
 * @param keyName -- Key attempting to be used
 * @param adminInterface
 * @returns
 */
function signingAuthorizationCallback(keyName: string, adminInterface: AdminInterface): Nip46PermitCallback {
    return async (p: Nip46PermitCallbackParams): Promise<boolean> => {
        const { id, method, pubkey: remotePubkey, params: payload } = p;
        log.signing(`Request ${id}: ${method} by ${remotePubkey.slice(0, 16)}... for ${keyName}`);

        if (!adminInterface.requestPermission) {
            throw new Error('adminInterface.requestPermission is not defined');
        }

        try {
            const keyAllowed = await checkIfPubkeyAllowed(keyName, remotePubkey, method as IMethod, payload);

            if (keyAllowed === true || keyAllowed === false) {
                // Audit log for signing decisions
                auditSigningRequest({
                    timestamp: new Date().toISOString(),
                    keyName,
                    clientPubkey: remotePubkey,
                    method,
                    allowed: keyAllowed,
                });
                return keyAllowed;
            }

            return new Promise((resolve) => {
                requestAuthorization(
                    adminInterface,
                    keyName,
                    remotePubkey,
                    id,
                    method,
                    payload
                )
                .then(() => resolve(true))
                .catch(() => resolve(false));
            });
        } catch (e: any) {
            logError('signing', `Authorization callback error for ${keyName}`, e);
        }

        return false;
    };
}

export default async function run(config: DaemonConfig) {
    const daemon = new Daemon(config);
    await daemon.start();
}

class Daemon {
    private config: DaemonConfig;
    private activeKeys: Record<string, any>;
    private adminInterface: AdminInterface;
    private ndk: NDK;
    public fastify: FastifyInstance;
    private isReady: boolean = false;

    constructor(config: DaemonConfig) {
        this.config = config;
        this.activeKeys = config.keys;
        const registrarNpub = process.env.REGISTRAR_NPUB;
        this.adminInterface = new AdminInterface({
            ...config.admin,
            registrarNpub
        }, config.configFile, config);

        this.adminInterface.getKeys = getKeys(config);
        this.adminInterface.getKeyUsers = getKeyUsers(config);
        this.adminInterface.unlockKey = this.unlockKey.bind(this);
        this.adminInterface.loadNsec = this.loadNsec.bind(this);

        this.fastify = Fastify({ logger: true });
        this.fastify.register(FastifyFormBody);

        this.ndk = new NDK({
            explicitRelayUrls: config.nostr.relays,
        });

        // Assign a signer to the NDK instance so it can handle NIP-42 AUTH challenges
        // Using the master key for the daemon's own connection authentication
        log.daemon(`SIGNER_MASTER_KEY: ${process.env.SIGNER_MASTER_KEY ? 'present' : 'missing'}`);
        if (process.env.SIGNER_MASTER_KEY) {
            log.daemon('Daemon NDK Signer configured with Master Key');
            this.ndk.signer = new NDKPrivateKeySigner(process.env.SIGNER_MASTER_KEY);
        }
        this.ndk.pool.on('relay:connect', (r) => log.daemon(`Connected to ${r.url}`));
        this.ndk.pool.on('relay:notice', (n, r) => log.daemon(`Notice from ${r.url}: ${n}`));

        this.ndk.pool.on('relay:disconnect', (r) => {
            log.daemon(`Disconnected from ${r.url}`);
        });
    }

    async startWebAuth() {
        if (!this.config.authPort) return;

        const urlPrefix = new URL(this.config.baseUrl as string).pathname.replace(/\/+$/, '');

        this.fastify.register(FastifyView, {
            engine: {
                handlebars: Handlebars,
            },
            defaultContext: {
                urlPrefix
            }
        });

        this.fastify.listen({ port: this.config.authPort, host: this.config.authHost });

        this.fastify.get('/requests/:id', authorizeRequestWebHandler);
        this.fastify.post('/requests/:id', processRequestWebHandler);
        this.fastify.post('/register/:id', processRegistrationWebHandler);
        this.fastify.get('/health', (req, res) => {
            if (this.isReady) {
                res.status(200).send('OK');
            } else {
                res.status(503).send('NOT READY');
            }
        });

        // Testing endpoints - only enabled in testing/development
        // Fail-safe: must be explicitly set, not just "not production"
        const env = process.env.NODE_ENV;
        if (env === 'testing' || env === 'development') {
            console.log('🧪 Testing endpoints enabled (NODE_ENV=' + env + ')');

            // Get key metadata by keyName (nsec never leaves signer)
            this.fastify.get('/testing/keys/:keyName', async (req, res) => {
                const { keyName } = req.params as { keyName: string };
                const key = await prisma.key.findUnique({ where: { keyName } });
                if (!key) return res.status(404).send({ error: 'Key not found' });
                // Return metadata only, not the private key
                return res.send({
                    keyName: key.keyName,
                    pubkey: key.pubkey,
                    createdAt: key.createdAt,
                    updatedAt: key.updatedAt
                });
            });

            // Short-circuit registration for testing
            // Test-runner provides the nsec and clientPubkey, signer stores and authorizes them
            this.fastify.post('/testing/register', async (req, res) => {
                const { keyName, nsec, pubkey, clientPubkey } = req.body as {
                    keyName: string;
                    nsec: string;
                    pubkey: string;
                    clientPubkey?: string;
                };
                if (!keyName || !nsec || !pubkey) {
                    return res.status(400).send({ error: 'keyName, nsec and pubkey are required' });
                }
                try {
                    // Import required functions
                    const { storeKey } = await import('../services/KeyService.js');
                    const { allowAllRequestsFromKey } = await import('./lib/acl/index.js');

                    // Decode nsec to hex
                    const privateKeyHex = nip19.decode(nsec).data as string;

                    // Store encrypted in DB
                    await storeKey(keyName, privateKeyHex, pubkey);

                    // Grant permissions to client keypair if provided
                    if (clientPubkey) {
                        await allowAllRequestsFromKey(clientPubkey, keyName, "connect", undefined, "test-client");
                        await allowAllRequestsFromKey(clientPubkey, keyName, "sign_event", undefined, "test-client", { kind: 'all' });
                        await allowAllRequestsFromKey(clientPubkey, keyName, "encrypt", undefined, "test-client");
                        await allowAllRequestsFromKey(clientPubkey, keyName, "decrypt", undefined, "test-client");
                        console.log(`🧪 Testing: authorized client ${clientPubkey.slice(0, 16)}... for key ${keyName}`);
                    }

                    // Load into active keys for signing
                    this.activeKeys[keyName] = nsec;

                    console.log(`🧪 Testing: registered key ${keyName}`);

                    return res.status(201).send({
                        success: true,
                        keyName,
                        pubkey,
                        clientAuthorized: !!clientPubkey
                    });
                } catch (e: any) {
                    if (e.code === 'P2002') {
                        return res.status(409).send({ error: 'Key already exists' });
                    }
                    console.error(`Testing register error:`, e);
                    return res.status(500).send({ error: e.message });
                }
            });

            // Authorize a client pubkey for an existing key (for post-registration authorization)
            this.fastify.post('/testing/authorize-client', async (req, res) => {
                const { keyName, clientPubkey } = req.body as {
                    keyName: string;
                    clientPubkey: string;
                };
                if (!keyName || !clientPubkey) {
                    return res.status(400).send({ error: 'keyName and clientPubkey are required' });
                }
                try {
                    const { allowAllRequestsFromKey } = await import('./lib/acl/index.js');

                    // Verify the key exists
                    const key = await prisma.key.findUnique({ where: { keyName } });
                    if (!key) {
                        return res.status(404).send({ error: `Key not found: ${keyName}` });
                    }

                    // Grant permissions to client pubkey
                    await allowAllRequestsFromKey(clientPubkey, keyName, "connect", undefined, "test-client");
                    await allowAllRequestsFromKey(clientPubkey, keyName, "sign_event", undefined, "test-client", { kind: 'all' });
                    await allowAllRequestsFromKey(clientPubkey, keyName, "encrypt", undefined, "test-client");
                    await allowAllRequestsFromKey(clientPubkey, keyName, "decrypt", undefined, "test-client");

                    console.log(`🧪 Testing: authorized client ${clientPubkey.slice(0, 16)}... for key ${keyName}`);

                    return res.status(200).send({
                        success: true,
                        keyName,
                        clientPubkey: clientPubkey.slice(0, 16) + '...'
                    });
                } catch (e: any) {
                    console.error(`Testing authorize-client error:`, e);
                    return res.status(500).send({ error: e.message });
                }
            });

            // Legacy: Create a key entry for testing (pubkey only)
            this.fastify.post('/testing/keys', async (req, res) => {
                const { keyName, pubkey } = req.body as { keyName: string; pubkey: string };
                if (!keyName || !pubkey) {
                    return res.status(400).send({ error: 'keyName and pubkey are required' });
                }
                try {
                    const key = await prisma.key.create({
                        data: { keyName, pubkey }
                    });
                    return res.status(201).send({
                        id: key.id,
                        keyName: key.keyName,
                        pubkey: key.pubkey,
                        createdAt: key.createdAt,
                        updatedAt: key.updatedAt
                    });
                } catch (e: any) {
                    if (e.code === 'P2002') {
                        return res.status(409).send({ error: 'Key already exists' });
                    }
                    return res.status(500).send({ error: e.message });
                }
            });

            // Sign a challenge to prove private key exists
            // The nsec stays in the signer - we just return proof it works
            this.fastify.post('/testing/sign-challenge', async (req, res) => {
                const { keyName, challenge } = req.body as { keyName: string; challenge: string };
                const nsec = this.activeKeys[keyName];
                if (!nsec) return res.status(404).send({ error: 'Key not loaded' });

                try {
                    const signer = new NDKPrivateKeySigner(nsec);
                    const user = await signer.user();
                    const event = new NDKEvent(this.ndk, {
                        kind: 1,
                        content: challenge,
                        created_at: Math.floor(Date.now() / 1000),
                        tags: []
                    } as any);
                    await event.sign(signer);

                    return res.send({
                        pubkey: user.pubkey,
                        sig: event.sig,
                        verified: true
                    });
                } catch (e: any) {
                    return res.status(500).send({ error: e.message, verified: false });
                }
            });

            // List received events for observability
            this.fastify.get('/testing/events/received', async (req, res) => {
                const { method } = req.query as { method?: string };
                const requests = await prisma.request.findMany({
                    where: method ? { method } : {},
                    orderBy: { createdAt: 'desc' },
                    take: 20
                });
                return res.send(requests);
            });

            // Audit endpoints for comprehensive NIP-46 operation tracking
            this.fastify.get('/testing/audit', async (req, res) => {
                const { correlationId, method, status, type } = req.query as {
                    correlationId?: string;
                    method?: string;
                    status?: string;
                    type?: string;
                };

                const { auditService } = await import('../services/AuditService.js');
                const events = auditService.getEvents({
                    ...(correlationId && { correlationId }),
                    ...(method && { method }),
                    ...(status && { status: status as any }),
                    ...(type && { type: type as any })
                });

                return res.send({ events, count: events.length });
            });

            this.fastify.delete('/testing/audit', async (req, res) => {
                const { auditService } = await import('../services/AuditService.js');
                auditService.clear();
                return res.send({ cleared: true });
            });
        }
    }

    async startKeys() {
        // Load all encrypted keys from SQLite database
        const { retrieveKey } = await import('../services/KeyService.js');

        const keys = await prisma.key.findMany({
            where: {
                encryptedKey: { not: null },
                deletedAt: null
            },
            select: { keyName: true }
        });

        log.keys(`Starting ${keys.length} keys from database`);

        for (const key of keys) {
            try {
                const privateKeyHex = await retrieveKey(key.keyName);
                if (privateKeyHex) {
                    log.keys(`Starting key: ${key.keyName}`);
                    await this.startKey(key.keyName, privateKeyHex);
                } else {
                    logError('keys', `Could not decrypt key: ${key.keyName}`);
                }
            } catch (e: any) {
                logError('keys', `Failed to start key ${key.keyName}`, e);
            }
        }
    }

    async start() {
        // Validate SIGNER_MASTER_KEY is set
        const masterKey = process.env.SIGNER_MASTER_KEY;
        if (!masterKey) {
            logError('daemon', 'CRITICAL: SIGNER_MASTER_KEY environment variable not set');
            console.error('This key must be provided and should never touch disk.');
            process.exit(1);
        }
        if (masterKey.length !== 64) {
            logError('daemon', 'CRITICAL: SIGNER_MASTER_KEY must be a 64-character hex string (256 bits)');
            process.exit(1);
        }
        logStartup('SIGNER_MASTER_KEY validated');

        // Validate stored encrypted keys (if any)
        try {
            const { validateAllKeys } = await import('../services/KeyService.js');
            const result = await validateAllKeys();

            if (result.failed.length > 0) {
                if (result.failed.length > 5) {
                    logError('keys', `Structural key corruption detected (${result.failed.length} failures)`);
                    console.error('Run: npx nsecbunker validate-keys --verbose');
                    console.error('Or restore keys from backup.');
                    process.exit(1);
                } else {
                    for (const keyName of result.failed) {
                        logError('keys', `Key validation failed: ${keyName}`);
                    }
                    console.error('Run: npx nsecbunker validate-keys --restore');
                    process.exit(1);
                }
            } else if (result.total > 0) {
                logStartup(`Validated ${result.valid}/${result.total} stored keys`);
            }
        } catch (e: any) {
            // May fail if no keys yet, that's OK
            log.keys(`Key validation skipped: ${e.message}`);
        }

        await this.ndk.connect(5000);
        await this.startWebAuth();
        await this.startKeys();

        this.isReady = true;
        logStartup('nsecBunker ready to serve requests');

        // Keep process alive in testing (NDK subscriptions keep prod alive)
        if (process.env.NODE_ENV === 'testing') {
            setInterval(() => {
                // No-op to keep event loop active
            }, 1000 * 60 * 60);
        }

        process.on('uncaughtException', (e) => {
            console.error('CRITICAL: Uncaught Exception:', e);
        });

        process.on('unhandledRejection', (e) => {
            console.error('CRITICAL: Unhandled Rejection:', e);
        });
    }

    /**
     * Method to start a key's backend
     * @param name Name of the key
     * @param nsec NSec of the key
     */
    async startKey(name: string, nsec: string) {
        const cb = signingAuthorizationCallback(name, this.adminInterface);
        let hexpk: string;

        if (nsec.startsWith('nsec1')) {
            try {
                const key = new NDKPrivateKeySigner(nsec);
                hexpk = key.privateKey!;
            } catch (e) {
                console.error(`Error loading key ${name}:`, e);
                return
            }
        } else {
            hexpk = nsec;
        }

        const backend = new Backend(this.ndk, this.fastify, hexpk, cb, this.config.baseUrl);
        await backend.start();
    }

    async unlockKey(keyName: string, passphrase: string): Promise<boolean> {
        const keyData = this.config.allKeys[keyName];
        const { iv, data } = keyData;

        const nsec = decryptNsec(iv, data, passphrase);
        this.activeKeys[keyName] = nsec;

        this.startKey(keyName, nsec);

        return true;
    }

    loadNsec(keyName: string, nsec: string) {
        this.activeKeys[keyName] = nsec;

        this.startKey(keyName, nsec).catch((e) => {
            console.error(`ERROR: Failed to start key ${keyName}:`, e);
        });
    }
}
