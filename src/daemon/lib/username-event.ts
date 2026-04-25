import NDK, { NDKEvent, NDKPrivateKeySigner, NDKRelayAuthPolicies, type NostrEvent } from '@nostr-dev-kit/ndk'
import { log } from '../../lib/logger.js'
import { checkpointService } from '../../services/CheckpointService.js'

const KIND_USERNAME_REGISTRATION = 415

/**
 * Publish a Kind 415 username registration event (idempotent).
 *
 * Creates the relay-queryable mapping: username → pubkey.
 * Signed by the user's own key (not the admin/registrar key).
 *
 * Authentication model (two identity layers):
 * - Connection identity: SIGNER_MASTER_KEY authenticates the WebSocket via NIP-42.
 *   The relay requires this trusted signer connection for Kind 415 writes.
 * - Event identity: userSigner signs the event itself (event.pubkey = user's key).
 *   The relay allows event.pubkey ≠ connection pubkey ("No Identity Lock" design).
 *
 * Flow:
 * 1. Connect to relay and authenticate as trusted signer (SIGNER_MASTER_KEY)
 * 2. Query relay for existing Kind 415 with matching pubkey + username
 * 3. If found → skip (already published, e.g. pg-boss retry)
 * 4. If not found → sign with user's key and publish
 * 5. If relay unreachable → throw (pg-boss will retry the full job)
 */
export async function publishUsernameEvent(
  userSigner: NDKPrivateKeySigner,
  username: string,
  pubkey: string,
  relayUrls: string[],
  createdAt?: number
): Promise<void> {
  if (!relayUrls || relayUrls.length === 0) {
    throw new Error('No relay URLs configured — cannot publish Kind 415')
  }

  // Use SIGNER_MASTER_KEY for NIP-42 connection authentication.
  // This key is validated at daemon startup (run.ts) and is always present.
  const masterKey = process.env.SIGNER_MASTER_KEY
  if (!masterKey) {
    throw new Error('SIGNER_MASTER_KEY not set — cannot authenticate with relay')
  }
  const authSigner = new NDKPrivateKeySigner(masterKey)

  const ndk = new NDK({
    explicitRelayUrls: relayUrls,
    signer: authSigner, // Connection identity: trusted signer for NIP-42
    enableOutboxModel: false,
    autoDeviceDiscovery: false,
    autoFetchUserMutelist: false,
    cacheAdapter: undefined
  })

  // Enable automatic NIP-42 AUTH response
  ndk.relayAuthDefaultPolicy = NDKRelayAuthPolicies.signIn({ ndk })

  await ndk.connect(5000)

  // Wait for relay authentication to complete before any operations.
  // NDK status: CONNECTED=5, AUTH_REQUESTED=6, AUTHENTICATING=7, AUTHENTICATED=8
  const relay = Array.from(ndk.pool.relays.values())[0] as any
  if (relay) {
    let authAttempts = 0
    while (relay.status < 8 && authAttempts < 50) {
      await new Promise(resolve => setTimeout(resolve, 100))
      authAttempts++
    }
    if (relay.status < 8) {
      log.admin(`Warning: relay auth not confirmed (status: ${relay.status}) for Kind 415 publish`)
    }
  }

  try {
    // Idempotency: check if Kind 415 already exists for this pubkey + username
    const existing = await queryExistingUsernameEvent(ndk, pubkey, username)
    if (existing) {
      log.admin(`Kind 415 already exists for ${username}, skipping publish`)
      checkpointService.broadcast('signer.kind415.published', {
        username,
        pubkey: pubkey.substring(0, 16),
        skipped: true
      })
      return
    }

    // Construct and publish
    // Event identity: signed by user's own key (event.pubkey = user's pubkey)
    const event = new NDKEvent(ndk, {
      kind: KIND_USERNAME_REGISTRATION,
      tags: [['u', username]],
      content: '',
      pubkey,
      created_at: createdAt
    } as NostrEvent)

    await event.sign(userSigner)
    const published = await event.publish()

    if (published.size === 0) {
      throw new Error(`Not enough relays received the event (0 published, ${relayUrls.length} required)`)
    }

    log.admin(`Kind 415 published to ${published.size} relay(s) for ${username}`)

    checkpointService.broadcast('signer.kind415.published', {
      username,
      pubkey: pubkey.substring(0, 16),
      skipped: false
    })
  } finally {
    if (ndk.pool) {
      ndk.pool.relays.forEach(relay => relay.disconnect())
    }
  }
}

/**
 * Query relay for an existing Kind 415 event matching pubkey + username.
 * Returns true if found, false if not, throws if relay unreachable.
 */
async function queryExistingUsernameEvent(
  ndk: NDK,
  pubkey: string,
  username: string
): Promise<boolean> {
  return new Promise<boolean>((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error('Timeout querying relay for existing Kind 415'))
    }, 10000)

    let found = false

    const sub = ndk.subscribe(
      { kinds: [KIND_USERNAME_REGISTRATION as any], authors: [pubkey], '#u': [username], limit: 1 },
      { closeOnEose: true }
    )

    sub.on('event', () => { found = true })
    sub.on('eose', () => {
      clearTimeout(timeout)
      resolve(found)
    })
  })
}
