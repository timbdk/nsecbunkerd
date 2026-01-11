import { Hexpubkey, NDKKind, NDKPrivateKeySigner, NDKRpcRequest, NDKUserProfile, NDKUser } from "@nostr-dev-kit/ndk";
import AdminInterface from "..";
import { nip19 } from 'nostr-tools';
import { setupSkeletonProfile } from "../../lib/profile";
import { IConfig, getCurrentConfig } from "../../../config";
import { allowAllRequestsFromKey } from "../../lib/acl";
import { requestAuthorization } from "../../authorize";
import { generateWallet } from "./account/wallet";
import prisma from "../../../db";
import createDebug from "debug";
import { encryptPrivateKey, storeKey, hexToNsec, markKeyBackedUp } from "../../../services/KeyService.js";
import { backupKey } from "../../../services/BackupService.js";

const debug = createDebug("nsecbunker:createAccount");

export async function validate(currentConfig, username: string, domain: string, email?: string) {
    if (!username) {
        throw new Error('username is required');
    }

    // make sure we have the domain
    if (!currentConfig.domains[domain]) {
        throw new Error('domain not found');
    }

    // Check if username already exists in database
    const keyName = `${username}@${domain}`;
    const existingKey = await prisma.key.findFirst({
        where: { keyName, deletedAt: null }
    });

    if (existingKey) {
        throw new Error('username already exists');
    }
}

/**
 * Reserved usernames that cannot be used since someone might
 * confuse them with some type of authority of this domain
 * and scammers are scoundrels
 */
const RESERVED_USERNAMES = [
    "admin", "root", "_", "administrator", "__"
];

async function validateUsername(username: string | undefined, domain: string, admin: AdminInterface, req: NDKRpcRequest) {
    if (!username || username.length === 0) {
        // create a random username of 10 characters
        username = Math.random().toString(36).substring(2, 15);
    }

    // check if the username is available
    if (RESERVED_USERNAMES.includes(username)) {
        throw new Error('username not available');
    }

    return username;
}

async function validateDomain(domain: string | undefined, admin: AdminInterface, req: NDKRpcRequest) {
    const availableDomains = (await admin.config()).domains;

    if (!availableDomains || Object.keys(availableDomains).length === 0)
        throw new Error('no domains available');

    if (!domain || domain.length === 0) domain = Object.keys(availableDomains)[0];

    // check if the domain is available
    if (!availableDomains[domain]) {
        throw new Error('domain not available');
    }

    return domain;
}

export default async function createAccount(admin: AdminInterface, req: NDKRpcRequest) {
    // params: [username, domain, email?, clientPubkey?, correlationId?]
    let [ username, domain, email, clientPubkey, correlationId ] = req.params as [ string?, string?, string?, string?, string? ];

    // Log with correlationId for tracing
    debug(`[${correlationId?.slice(0, 8) || 'no-corr'}] create_account request from ${req.pubkey.slice(0, 16)}...`);

    try {
        domain = await validateDomain(domain, admin, req);
        username = await validateUsername(username, domain, admin, req);
    } catch (e: any) {
        const originalKind = req.event.kind!;
        debug(`[${correlationId?.slice(0, 8) || 'no-corr'}] create_account validation failed: ${e.message}`);
        admin.rpc.sendResponse(req.id, req.pubkey, "error", originalKind, e.message);
        return;
    }

    const nip05 = `${username}@${domain}`;
    const payload: string[] = [ username, domain ];
    if (email) payload.push(email);
    if (clientPubkey) payload.push(clientPubkey);

    // Check if request is from Registrar and bypass authorization
    const registrarNpub = (admin as any).opts?.registrarNpub;
    let isRegistrar = false;
    if (registrarNpub) {
        const registrarPubkey = (new NDKUser({ npub: registrarNpub })).pubkey;
        if (req.pubkey === registrarPubkey) {
            isRegistrar = true;
        }
    }

    if (isRegistrar) {
        debug(`[${correlationId?.slice(0, 8) || 'no-corr'}] Bypassing authorization for Registrar`);
        return createAccountReal(admin, req, username, domain, email, clientPubkey);
    }

    debug(`Requesting authorization for ${nip05}`);
    const authorizationWithPayload = await requestAuthorization(
        admin,
        nip05,
        req.pubkey,
        req.id,
        req.method,
        JSON.stringify(payload)
    );
    debug(`Authorization for ${nip05} ${authorizationWithPayload ? 'granted' : 'denied'}`);

    if (authorizationWithPayload) {
        const payload = JSON.parse(authorizationWithPayload);
        username = payload[0];
        domain = payload[1];
        email = payload[2];
        clientPubkey = payload[3];
        return createAccountReal(admin, req, username, domain, email, clientPubkey);
    }
}

/**
 * This is where the real work of creating the private key, wallet, nip-05, granting access, etc happen
 */
export async function createAccountReal(
    admin: AdminInterface,
    req: NDKRpcRequest,
    username: string,
    domain: string,
    email?: string,
    clientPubkey?: string
): Promise<void> {
    const { auditService } = await import('../../../services/AuditService.js');
    const scope = auditService.createScope(req.id, 'create_account');
    
    scope.logReceived({
        clientPubkey,
        requestEventId: req.event.id,
        userIdentifier: `${username}@${domain}`,
        details: { username, domain, email }
    });

    try {
        debug(`[${req.id}] create_account request from ${clientPubkey?.slice(0, 16) || 'unknown'}...`);
        debug(`[${req.id}] Creating account for ${username}@${domain}`);

        const currentConfig = await getCurrentConfig(admin.configFile);

        if (!currentConfig.domains) {
            throw new Error('no domains configured');
        }

        const domainConfig = currentConfig.domains[domain];

        // await validate(currentConfig, username, domain, email);

        try {
            await validate(currentConfig, username, domain, email);

        } catch (e: any) {
            if (e.message === 'username already exists') {
                debug('username already exists, implementing idempotency');
                const keyName = `${username}@${domain}`;
                const existingKey = await prisma.key.findFirst({
                    where: { keyName, deletedAt: null },
                    select: { pubkey: true }
                });
                if (existingKey) {
                    debug(`Found existing pubkey ${existingKey.pubkey} for ${username}`);
                    // Ensure permissions are granted (idempotent)
                    await grantPermissions(req, keyName, clientPubkey);
                    debug('permissions re-granted for existing user');
                    return admin.rpc.sendResponse(req.id, req.pubkey, existingKey.pubkey, NDKKind.NostrConnectAdmin);
                }
            }
            throw e;
        }

        const nip05 = `${username}@${domain}`;
        const key = NDKPrivateKeySigner.generate();
        const profile: NDKUserProfile = {
            display_name: username,
            name: username,
            nip05,
            ...(domainConfig.defaultProfile || {})
        };

        const generatedUser = await key.user();

        debug(`Created user ${generatedUser.npub} for ${nip05}`);

        // Note: NIP-05 data is stored in the Key table (keyName = username@domain)
        // No separate file write needed - keyName serves as the NIP-05 identifier

        // Create wallet
        if (domainConfig.wallet) {
            generateWallet(
                domainConfig.wallet,
                username, domain, generatedUser.npub
            ).then((lnaddress) => {
                debug(`wallet for ${nip05}`, {lnaddress});
                if (lnaddress) profile.lud16 = lnaddress;
            }).catch((e) => {
                debug(`error generating wallet for ${nip05}`, e);
            }).finally(() => {
                debug(`saving profile for ${nip05}`, profile);
                setupSkeletonProfile(key, profile, email, currentConfig.nostr.relays);
            })
        } else {
            debug(`no wallet configuration for ${domain}`);
            // Create user profile
            setupSkeletonProfile(key, profile, email, currentConfig.nostr.relays);
        }

        const keyName = nip05;
        const privateKeyHex = key.privateKey!;
        const nsec = nip19.nsecEncode(privateKeyHex);

        // Backup-first: encrypt and backup before local storage
        debug(`Encrypting key for ${keyName}`);
        const encryptedData = encryptPrivateKey(privateKeyHex, keyName);

        debug(`Backing up key for ${keyName}`);
        const backupResult = await backupKey(keyName, encryptedData, generatedUser.pubkey);
        if (!backupResult.success) {
            throw new Error(`Backup failed for ${keyName}: ${backupResult.error}`);
        }

        // Only store locally after successful backup
        debug(`Storing key locally for ${keyName}`);
        await storeKey(keyName, privateKeyHex, generatedUser.pubkey);
        await markKeyBackedUp(keyName);

        await admin.loadNsec!(keyName, nsec);

        // Immediately grant access to the creator key and client
        // This means that the client creating this account can immediately
        // access it without having to go through an approval flow
        await grantPermissions(req, keyName, clientPubkey);

        scope.logResponse({
            userPubkey: generatedUser.pubkey,
            userIdentifier: keyName,
            responseEventId: undefined, // Will be set by rpc layer
            clientPubkey: clientPubkey || req.pubkey
        });

        return admin.rpc.sendResponse(req.id, req.pubkey, generatedUser.pubkey, NDKKind.NostrConnectAdmin);
    } catch (e: any) {
        debug(`error creating account: ${e.message}`);
        scope.logError(e, { username, domain });
        return admin.rpc.sendResponse(req.id, req.pubkey, "error", NDKKind.NostrConnectAdmin,
            e.message);
    }
}

async function grantPermissions(req: NDKRpcRequest, keyName: string, clientPubkey?: string) {
    // Grant permissions to the registrar that initiated the request
    await allowAllRequestsFromKey(req.pubkey, keyName, "connect", undefined, "registrar");
    await allowAllRequestsFromKey(req.pubkey, keyName, "sign_event", undefined, "registrar", { kind: 'all' });
    await allowAllRequestsFromKey(req.pubkey, keyName, "encrypt", undefined, "registrar");
    await allowAllRequestsFromKey(req.pubkey, keyName, "decrypt", undefined, "registrar");
    
    // Grant permissions to the client's ephemeral keypair
    // This allows the web browser that initiated registration to immediately connect
    if (clientPubkey) {
        await allowAllRequestsFromKey(clientPubkey, keyName, "connect", undefined, "client");
        await allowAllRequestsFromKey(clientPubkey, keyName, "sign_event", undefined, "client", { kind: 'all' });
        await allowAllRequestsFromKey(clientPubkey, keyName, "encrypt", undefined, "client");
        await allowAllRequestsFromKey(clientPubkey, keyName, "decrypt", undefined, "client");
    }
}
