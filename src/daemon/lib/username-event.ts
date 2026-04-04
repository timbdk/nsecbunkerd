import NDK, { NDKEvent, NDKPrivateKeySigner, type NostrEvent } from '@nostr-dev-kit/ndk'
import { log } from '../../lib/logger.js'
import { checkpointService } from '../../services/CheckpointService.js'

const KIND_USERNAME_REGISTRATION = 415

/**
 * Publish a Kind 415 username registration event (idempotent).
 *
 * Creates the relay-queryable mapping: username → pubkey.
 * Signed by the user's own key (not the admin/registrar key).
 *
 * Flow:
 * 1. Query relay for existing Kind 415 with matching pubkey + username
 * 2. If found → skip (already published, e.g. pg-boss retry)
 * 3. If not found → sign with user's key and publish
 * 4. If relay unreachable → throw (pg-boss will retry the full job)
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

  const ndk = new NDK({
    explicitRelayUrls: relayUrls,
    signer: userSigner,
    enableOutboxModel: false,
    autoDeviceDiscovery: false,
    autoFetchUserMutelist: false,
    cacheAdapter: undefined
  })

  await ndk.connect(5000)

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
      throw new Error(`Kind 415 published to 0 relays for ${username}`)
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
