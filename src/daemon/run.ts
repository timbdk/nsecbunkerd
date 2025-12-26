import NDK, { NDKEvent, NDKPrivateKeySigner, Nip46PermitCallback, Nip46PermitCallbackParams } from '@nostr-dev-kit/ndk';
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
import {authorizeRequestWebHandler, processRequestWebHandler} from "./web/authorize.js";
import {processRegistrationWebHandler} from "./web/authorize.js";

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
        console.log(`🔑 ${keyName} is being requested to ${method} by ${nip19.npubEncode(remotePubkey)}, request ${id}`);

        if (!adminInterface.requestPermission) {
            throw new Error('adminInterface.requestPermission is not defined');
        }

        try {
            const keyAllowed = await checkIfPubkeyAllowed(keyName, remotePubkey, method as IMethod, payload);

            if (keyAllowed === true || keyAllowed === false) {
                console.log(`🔎 ${nip19.npubEncode(remotePubkey)} is ${keyAllowed ? 'allowed' : 'denied'} to ${method} with key ${keyName}`);
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
        } catch(e) {
            console.log('callbackForKey error:', e);
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
        }, config.configFile);

        this.adminInterface.getKeys = getKeys(config);
        this.adminInterface.getKeyUsers = getKeyUsers(config);
        this.adminInterface.unlockKey = this.unlockKey.bind(this);
        this.adminInterface.loadNsec = this.loadNsec.bind(this);

        this.fastify = Fastify({ logger: true });
        this.fastify.register(FastifyFormBody);

        this.ndk = new NDK({
            explicitRelayUrls: config.nostr.relays,
        });
        this.ndk.pool.on('relay:connect', (r) => console.log(`✅ Connected to ${r.url}`) );
        this.ndk.pool.on('relay:notice', (n, r) => { console.log(`👀 Notice from ${r.url}`, n); });

        this.ndk.pool.on('relay:disconnect', (r) => {
            console.log(`🚫 Disconnected from ${r.url}`);
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
        }
    }

    async startKeys() {
        console.log('🔑 Starting keys', Object.keys(this.config.keys));
        for (const [name, nsec] of Object.entries(this.config.keys)) {
            console.log(`🔑 Starting ${name}...`);
            await this.startKey(name, nsec);
        }

        // Load unencrypted keys
        const config = await this.adminInterface.config();
        for (const [keyName, settings ] of Object.entries(config.keys))  {
            if (!settings.key) {
                continue;
            }

            const nsec = nip19.nsecEncode(settings.key);
            this.loadNsec(keyName, nsec);
        }
    }

    async start() {
        await this.ndk.connect(5000);
        await this.startWebAuth();
        await this.startKeys();

        this.isReady = true;
        console.log('✅ nsecBunker ready to serve requests.');

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
            } catch(e) {
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
