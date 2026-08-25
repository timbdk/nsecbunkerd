import NDK, { NDKPrivateKeySigner, NDKRelayAuthPolicies, NDKRelaySet } from '@nostr-dev-kit/ndk'
import { Kind415UsernameRegistration, identityIdFromPublicKey } from 'verity-event-data-module'
import { log } from '../../lib/logger.js'
import { checkpointService } from '../../services/CheckpointService.js'

/**
 * Publish a Kind 415 username registration event (idempotent).
 *
 * Creates the relay-queryable mapping: username → uid.
 * Signed by the user's own key (not the admin/registrar key).
 *
 * Authentication model (two identity layers):
 * - Connection identity: SIGNER_MASTER_KEY authenticates the WebSocket via NIP-42.
 *   The relay requires this trusted signer connection for Kind 415 writes.
 * - Event identity: userSigner signs the event itself (event.uid = user's identity id).
 *   The relay allows event.uid ≠ connection uid ("No Identity Lock" design).
 *
 * Flow:
 * 1. Connect to relay and authenticate as trusted signer (SIGNER_MASTER_KEY)
 * 2. Query relay for existing Kind 415 with matching uid + username
 * 3. If found → skip (already published, e.g. pg-boss retry)
 * 4. If not found → sign with user's key and publish
 * 5. If relay unreachable → throw (pg-boss will retry the full job)
 */
const NDK_RELAY_STATUS_AUTHENTICATED = 8

export async function publishUsernameEvent(
  userSigner: NDKPrivateKeySigner,
  username: string,
  pubkey: string,
  relayUrls: string[],
  createdAt?: number,
  kid?: string,
  ndkInstance?: NDK
): Promise<void> {
  if (!relayUrls || relayUrls.length === 0) {
    throw new Error('No relay URLs configured — cannot publish Kind 415')
  }

  let ndk: NDK
  if (ndkInstance) {
    ndk = ndkInstance
  } else {
    // Use SIGNER_MASTER_KEY for NIP-42 connection authentication.
    const masterKey = process.env.SIGNER_MASTER_KEY
    if (!masterKey) {
      throw new Error('SIGNER_MASTER_KEY not set — cannot authenticate with relay')
    }
    const authSigner = new NDKPrivateKeySigner(masterKey)

    ndk = new NDK({
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

    const relay = Array.from(ndk.pool.relays.values())[0] as any
    if (relay) {
      let authAttempts = 0
      while (relay.status < NDK_RELAY_STATUS_AUTHENTICATED && authAttempts < 50) {
        await new Promise(resolve => setTimeout(resolve, 100))
        authAttempts++
      }
      if (relay.status < NDK_RELAY_STATUS_AUTHENTICATED) {
        log.admin(`Warning: relay auth not confirmed (status: ${relay.status}) for Kind 415 publish`)
      }
    }
  }

  try {
    const key = kid ? undefined : ('secp256k1-schnorr:' + Buffer.from(pubkey, 'hex').toString('base64'))
    const uid = identityIdFromPublicKey(pubkey)

    // Idempotency: check if Kind 415 already exists for this uid + username
    const existing = await queryExistingUsernameEvent(ndk, uid, username)
    if (existing) {
      log.admin(`Kind 415 already exists for ${username}, skipping publish`)
      checkpointService.broadcast('signer.kind415.published', {
        username,
        pubkey: pubkey.substring(0, 16),
        skipped: true
      })
      return
    }

    // Construct via Level 2 Builder, using build() callback for the dominant claim case.
    // Event identity: signed by user's own key
    let builder = Kind415UsernameRegistration.build(username)
    if (createdAt) builder = builder.createdAt(createdAt)
    if (kid) builder = builder.setKid(kid)

    const event = await builder.toSignedNDKEvent({
      ndk,
      signer: userSigner,
      uid,
      kid,
      key
    })
    event.on('relay:publish:failed', (relay: any, err: any) => {
      log.admin(`❌ Kind 415 publish failed on relay ${relay?.url}: ${err?.message || err}`)
    })
    event.on('relay:published', (relay: any) => {
      log.admin(`✅ Kind 415 published on relay ${relay?.url}`)
    })

    log.admin(`Publishing Kind 415 for ${username} (id: ${event.id}, kid: ${event.kid}, uid: ${event.uid})`)
    const relaySet = NDKRelaySet.fromRelayUrls(relayUrls, ndk)
    const published = await event.publish(relaySet)

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
    if (!ndkInstance && ndk.pool) {
      ndk.pool.relays.forEach(relay => relay.disconnect())
    }
  }
}

/**
 * Query relay for an existing Kind 415 event matching uid + username.
 * Returns true if found, false if not, throws if relay unreachable.
 */
async function queryExistingUsernameEvent(
  ndk: NDK,
  uid: string,
  username: string
): Promise<boolean> {
  const filter = {
    ...Kind415UsernameRegistration.filters.byUsername(username),
    authors: [uid]
  }

  const events = await ndk.fetchEvents(filter as any)
  return events.size > 0
}
