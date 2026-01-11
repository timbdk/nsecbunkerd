import { NDKKind, NDKRpcRequest } from "@nostr-dev-kit/ndk"
import AdminInterface from "../index.js"
import { allowAllRequestsFromKey } from "../../lib/acl/index.js"
import prisma from "../../../db.js"
import createDebug from "debug"

const debug = createDebug("nsecbunker:authorizeClient")

/**
 * Authorizes a client pubkey to perform signing operations with a user's key.
 * Called during login flow to authorize a new device/browser.
 *
 * The client uses an ephemeral keypair for NIP-46 communication. This command
 * grants that client keypair permission to connect and sign with the user's key.
 *
 * Params: [keyName, userPubkey, clientPubkey, correlationId?]
 * - keyName: The NIP-05 style key name (e.g., "username@verity.local")
 * - userPubkey: The hex pubkey of the user's key (for verification)
 * - clientPubkey: The hex pubkey of the client's ephemeral keypair (to authorize)
 * - correlationId: Optional correlation ID for tracing across services
 */
export default async function authorizeClient(admin: AdminInterface, req: NDKRpcRequest) {
    const [keyName, userPubkey, clientPubkey, correlationId] = req.params as [string, string, string, string?]
    const corrPrefix = `[${correlationId?.slice(0, 8) || 'no-corr'}]`

    const { auditService } = await import('../../../services/AuditService.js');
    const scope = auditService.createScope(req.id, 'authorize_client');

    if (!keyName || !userPubkey || !clientPubkey) {
        debug(`${corrPrefix} Invalid params: keyName=${keyName}, userPubkey=${userPubkey?.slice(0, 16)}, clientPubkey=${clientPubkey?.slice(0, 16)}`)
        scope.logError(new Error('Invalid params'), { keyName, userPubkey, clientPubkey });
        return admin.rpc.sendResponse(
            req.id,
            req.pubkey,
            "error",
            NDKKind.NostrConnect,
            "Invalid params: keyName, userPubkey, and clientPubkey required"
        )
    }

    scope.logReceived({
        clientPubkey,
        userPubkey,
        userIdentifier: keyName,
        requestEventId: req.event.id,
        details: { keyName }
    });

    debug(`${corrPrefix} Authorizing client ${clientPubkey.slice(0, 16)}... for key ${keyName}`)

    // Verify the key exists
    const key = await prisma.key.findUnique({ where: { keyName } })
    if (!key) {
        debug(`Key not found: ${keyName}`)
        scope.logError(new Error('Key not found'), { keyName });
        return admin.rpc.sendResponse(req.id, req.pubkey, "error", NDKKind.NostrConnect, `Key not found: ${keyName}`)
    }

    // Verify the userPubkey matches (ensures the requester knows the correct user)
    if (key.pubkey !== userPubkey) {
        debug(`Pubkey mismatch: expected ${key.pubkey.slice(0, 16)}..., got ${userPubkey.slice(0, 16)}...`)
        scope.logError(new Error('Pubkey mismatch'), { expected: key.pubkey, got: userPubkey });
        return admin.rpc.sendResponse(req.id, req.pubkey, "error", NDKKind.NostrConnect, "User pubkey mismatch")
    }

    try {
        // Grant permissions to the CLIENT pubkey (not the user pubkey!)
        await allowAllRequestsFromKey(clientPubkey, keyName, "connect", undefined, "client authorization")
        await allowAllRequestsFromKey(clientPubkey, keyName, "sign_event", undefined, "client authorization", { kind: 'all' })
        await allowAllRequestsFromKey(clientPubkey, keyName, "encrypt", undefined, "client authorization")
        await allowAllRequestsFromKey(clientPubkey, keyName, "decrypt", undefined, "client authorization")

        debug(`Client ${clientPubkey.slice(0, 16)}... authorized for key ${keyName}`)

        scope.logResponse({
            clientPubkey,
            userPubkey: key.pubkey,
            userIdentifier: keyName
        });

        return admin.rpc.sendResponse(req.id, req.pubkey, "authorized", NDKKind.NostrConnect)

    } catch (e: any) {
        debug(`Error authorizing client: ${e.message}`)
        scope.logError(e, { keyName, clientPubkey });
        return admin.rpc.sendResponse(req.id, req.pubkey, "error", NDKKind.NostrConnect, e.message)
    }
}
