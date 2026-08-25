import NDK, { NDKPrivateKeySigner, NDKRelayAuthPolicies } from '@nostr-dev-kit/ndk'
import { Kind723Invited, identityIdFromPublicKey } from 'verity-event-data-module'
import { log } from '../../lib/logger.js'
import { checkpointService } from '../../services/CheckpointService.js'

/** Timeout for relay queries to check for existing Kind 723 events before publishing */
const RELAY_QUERY_TIMEOUT_MS = 10_000

/**
 * Publish a Kind 723 invited event (idempotent).
 * Mapped inviter -> invitee, signed by the inviter's own key.
 */
const NDK_RELAY_STATUS_AUTHENTICATED = 8

export async function publishInvitedEvent(
  inviterSigner: NDKPrivateKeySigner,
  inviteePubkey: string,
  relayUrls: string[],
  createdAt?: number,
  kid?: string,
  ndkInstance?: NDK
): Promise<void> {
  if (!relayUrls || relayUrls.length === 0) {
    throw new Error('No relay URLs configured — cannot publish Kind 723')
  }

  let ndk: NDK
  if (ndkInstance) {
    ndk = ndkInstance
  } else {
    const masterKey = process.env.SIGNER_MASTER_KEY
    if (!masterKey) {
      throw new Error('SIGNER_MASTER_KEY not set — cannot authenticate with relay')
    }
    const authSigner = new NDKPrivateKeySigner(masterKey)

    ndk = new NDK({
      explicitRelayUrls: relayUrls,
      signer: authSigner,
      enableOutboxModel: false,
      autoDeviceDiscovery: false,
      autoFetchUserMutelist: false,
      cacheAdapter: undefined
    })

    ndk.relayAuthDefaultPolicy = NDKRelayAuthPolicies.signIn({ ndk })

    await ndk.connect(5000)

    const relay = Array.from(ndk.pool.relays.values())[0] as any
    if (relay) {
      let authAttempts = 0
      while (relay.status < NDK_RELAY_STATUS_AUTHENTICATED && authAttempts < 50) {
        await new Promise(resolve => setTimeout(resolve, 100))
        authAttempts++
      }
    }
  }

  try {
    const inviterPubkey = await inviterSigner.user().then(u => u.pubkey)
    const inviterPubkeyBytes = Buffer.from(inviterPubkey, 'hex')
    const key = kid ? undefined : ('secp256k1-schnorr:' + inviterPubkeyBytes.toString('base64'))
    const uid = identityIdFromPublicKey(inviterPubkey)

    // Idempotency: check if Kind 723 already exists for this inviter and invitee
    const existing = await queryExistingInvitedEvent(ndk, uid, inviteePubkey)
    if (existing) {
      log.admin(`Kind 723 already exists for inviter ${inviterPubkey.substring(0, 8)} -> invitee ${inviteePubkey.substring(0, 8)}, skipping publish`)
      checkpointService.broadcast('signer.kind723.published', {
        inviterPubkey: inviterPubkey.substring(0, 16),
        inviteePubkey: inviteePubkey.substring(0, 16),
        skipped: true
      })
      return
    }

    let builder = Kind723Invited.build({ inviteePubkey })
    if (kid) builder = builder.setKid(kid)

    const event = await builder.toSignedNDKEvent({
      ndk,
      signer: inviterSigner,
      uid,
      kid,
      key
    })
    const published = await event.publish()

    if (published.size === 0) {
      throw new Error(`Not enough relays received the event (0 published, ${relayUrls.length} required)`)
    }

    log.admin(`Kind 723 published to ${published.size} relay(s)`)

    checkpointService.broadcast('signer.kind723.published', {
      inviterPubkey: inviterPubkey.substring(0, 16),
      inviteePubkey: inviteePubkey.substring(0, 16),
      skipped: false
    })
  } finally {
    if (!ndkInstance && ndk.pool) {
      ndk.pool.relays.forEach(relay => relay.disconnect())
    }
  }
}

async function queryExistingInvitedEvent(
  ndk: NDK,
  inviterUid: string,
  inviteePubkey: string
): Promise<boolean> {
  return new Promise<boolean>((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error('Timeout querying relay for existing Kind 723'))
    }, RELAY_QUERY_TIMEOUT_MS)

    let found = false

    const filter = {
      kinds: [723],
      authors: [inviterUid],
      '#p': [inviteePubkey]
    }

    const sub = ndk.subscribe(
      filter,
      { closeOnEose: true }
    )

    sub.on('event', () => { found = true })
    sub.on('eose', () => {
      clearTimeout(timeout)
      resolve(found)
    })
  })
}
