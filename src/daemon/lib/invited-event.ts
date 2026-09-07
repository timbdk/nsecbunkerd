import NDK, { NDKMlDsaSigner, NDKPrivateKeySigner, NDKRelayAuthPolicies, NDKSigner } from '@nostr-dev-kit/ndk'
import { Kind723Invited, identityIdFromPublicKey } from 'verity-event-data-module'
import { log } from '../../lib/logger.js'
import { checkpointService } from '../../services/CheckpointService.js'

/**
 * Publish a Kind 723 invited event (idempotent).
 * Mapped inviter -> invitee, signed by the inviter's own key.
 */
const NDK_RELAY_STATUS_AUTHENTICATED = 8

export async function publishInvitedEvent(
  inviterSigner: NDKSigner,
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
    const daemonKey = process.env.SIGNER_DAEMON_KEY
    if (!daemonKey) {
      throw new Error('SIGNER_DAEMON_KEY not set — cannot authenticate with relay')
    }
    const authSigner = new NDKMlDsaSigner(daemonKey)

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
    const isMlDsa = inviterPubkey.length === 2624
    const key = kid ? undefined : ((isMlDsa ? 'ml-dsa-44:' : 'secp256k1-schnorr:') + inviterPubkeyBytes.toString('base64'))
    const uid = identityIdFromPublicKey(inviterPubkey)
    const inviteeUid = /^[0-9a-fA-F]{64}$/.test(inviteePubkey)
      ? inviteePubkey
      : identityIdFromPublicKey(inviteePubkey)

    // Idempotency: check if Kind 723 already exists for this inviter and invitee
    const existing = await queryExistingInvitedEvent(ndk, uid, inviteeUid)
    if (existing) {
      log.admin(`Kind 723 already exists for inviter ${inviterPubkey.substring(0, 8)} -> invitee ${inviteeUid.substring(0, 8)}, skipping publish`)
      checkpointService.broadcast('signer.kind723.published', {
        inviterPubkey: inviterPubkey.substring(0, 16),
        inviteePubkey: inviteeUid.substring(0, 16),
        skipped: true
      })
      return
    }

    let builder = Kind723Invited.build({ inviteePubkey: inviteeUid })
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
  const filter = {
    kinds: [723],
    authors: [inviterUid],
    '#p': [inviteePubkey]
  }

  const event = await ndk.fetchEvent(filter)
  return !!event
}
