import { NDKKind, NDKRpcRequest } from "@nostr-dev-kit/ndk"
import AdminInterface from "../index.js"
import { rejectAllRequestsFromKey } from "../../lib/acl/index.js"
import prisma from "../../../db.js"
import createDebug from "debug"

const debug = createDebug("nsecbunker:revokeClient")

/**
 * Revokes a client's permission to sign events with a user's key.
 * Called during logout flow to invalidate the client's signing session.
 *
 * Params: [keyName, userPubkey, clientPubkey?, correlationId?]
 * - keyName: The NIP-05 style key name (e.g., "username@verity.local")
 * - userPubkey: The hex pubkey of the user (for verification)
 * - clientPubkey: The hex pubkey of the client to revoke (optional - if undefined, revokes all clients)
 * - correlationId: Optional correlation ID for tracing across services
 */
export default async function revokeClient(admin: AdminInterface, req: NDKRpcRequest) {
    const [keyName, userPubkey, clientPubkey, correlationId] = req.params as [string, string, string | undefined, string?]
    const corrPrefix = `[${correlationId?.slice(0, 8) || 'no-corr'}]`

    if (!keyName) {
        debug(`${corrPrefix} Invalid params: keyName required`)
        return admin.rpc.sendResponse(
            req.id,
            req.pubkey,
            "error",
            NDKKind.NostrConnect,
            "Invalid params: keyName required"
        )
    }

    debug(`${corrPrefix} Revoking ${clientPubkey ? 'client ' + clientPubkey.slice(0, 16) + '...' : 'ALL clients'} from key ${keyName}`)

    // Verify the key exists
    const key = await prisma.key.findUnique({ where: { keyName } })
    if (!key) {
        debug(`Key not found: ${keyName}`)
        return admin.rpc.sendResponse(req.id, req.pubkey, "error", NDKKind.NostrConnect, `Key not found: ${keyName}`)
    }

    try {
        if (clientPubkey) {
            // Revoke specific client
            await rejectAllRequestsFromKey(clientPubkey, keyName)
            debug(`Client ${clientPubkey.slice(0, 16)}... revoked from key ${keyName}`)
        } else {
            // Revoke all clients by revoking the userPubkey
            // Note: This is a broad revocation that may need refinement
            if (userPubkey) {
                await rejectAllRequestsFromKey(userPubkey, keyName)
                debug(`All clients revoked for user ${userPubkey.slice(0, 16)}... on key ${keyName}`)
            }
        }

        return admin.rpc.sendResponse(req.id, req.pubkey, "revoked", NDKKind.NostrConnect)

    } catch (e: any) {
        debug(`Error revoking client: ${e.message}`)
        return admin.rpc.sendResponse(req.id, req.pubkey, "error", NDKKind.NostrConnect, e.message)
    }
}
