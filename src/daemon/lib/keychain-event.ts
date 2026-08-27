/**
 * Purpose: Publish Kind 297 Key Chain events (idempotent) and evaluate identity chains.
 * Behavior: Publishes user genesis entries endorsed by daemon service key; queries chains for latest identity entry.
 * Usage: Consumed by create_account, rename_account, and HTTP testing server in signer-service.
 */

// ── Imports ──────────────────────────────────────────────────────────────────

import NDK, { NDKEvent, NDKPrivateKeySigner, NDKRelayAuthPolicies, NDKRelaySet } from '@nostr-dev-kit/ndk'
import {
  Kind297KeyChain,
  identityIdFromPublicKey,
  endorsementPreimage,
  currentIdentityEntry,
  type ChainEntry,
  type PlatformEndorsement
} from 'verity-event-data-module'
import { schnorr } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { hexToBytes } from '@noble/hashes/utils.js'
import { base64 } from '@scure/base'
import { log } from '../../lib/logger.js'
import { checkpointService } from '../../services/CheckpointService.js'

/** Timeout for relay queries */
const RELAY_QUERY_TIMEOUT_MS = 10_000

// ── Endorsement Construction ─────────────────────────────────────────────────

export function buildEndorsement(
  content: any,
  uid: string,
  variant: string,
  daemonPrivateKeyHex: string,
  daemonServiceEntryId: string
): PlatformEndorsement {
  const preimage = endorsementPreimage(uid, variant, content)
  const hash = sha256(new TextEncoder().encode(preimage))
  const daemonPrivBytes = hexToBytes(daemonPrivateKeyHex)
  const sig = schnorr.sign(hash, daemonPrivBytes)

  return {
    entry: daemonServiceEntryId,
    alg: 'secp256k1-schnorr',
    b64: base64.encode(sig)
  }
}

// ── Chain Query Helpers ──────────────────────────────────────────────────────

export async function queryExistingGenesisEntry(
  ndk: NDK,
  uid: string
): Promise<NDKEvent | null> {
  const events = await ndk.fetchEvents({
    kinds: [297 as any],
    authors: [uid],
    '#v': ['genesis']
  })
  return Array.from(events)[0] ?? null
}

export async function queryCurrentIdentityEntry(
  ndk: NDK,
  uid: string
): Promise<ChainEntry | null> {
  const eventsSet = await ndk.fetchEvents({
    kinds: [297 as any],
    authors: [uid]
  })

  const events: any[] = []
  for (const ev of eventsSet) {
    try {
      const parsedContent = typeof ev.content === 'string' ? JSON.parse(ev.content) : ev.content
      const vTag = ev.tags?.find((t) => t[0] === 'v')
      events.push({
        id: ev.id,
        uid: (ev as any).uid ?? ev.pubkey,
        created_at: ev.created_at,
        kind: ev.kind,
        variant: vTag?.[1],
        kid: (ev as any).kid,
        tags: ev.tags,
        content: parsedContent
      })
    } catch {
      // Ignore unparseable entries
    }
  }

  return currentIdentityEntry(events)
}

// ── Genesis Publication ──────────────────────────────────────────────────────

/**
 * Publishes a Kind 297 genesis event for a new user identity (idempotent).
 * Signed by the user's identity key and endorsed by the daemon key.
 */
const NDK_RELAY_STATUS_AUTHENTICATED = 8

export async function publishGenesisEntry(
  userSigner: NDKPrivateKeySigner,
  pubkey: string,
  relayUrls: string[],
  platformServiceEntryId: string,
  createdAt?: number,
  ndkInstance?: NDK
): Promise<string> {
  if (!relayUrls || relayUrls.length === 0) {
    throw new Error('No relay URLs configured — cannot publish Kind 297')
  }
  const masterKey = process.env.SIGNER_MASTER_KEY
  if (!masterKey) {
    throw new Error('SIGNER_MASTER_KEY not set — cannot endorse or authenticate with relay')
  }

  let ndk: NDK
  if (ndkInstance) {
    ndk = ndkInstance
  } else {
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
        await new Promise((resolve) => setTimeout(resolve, 100))
        authAttempts++
      }
      if (relay.status < NDK_RELAY_STATUS_AUTHENTICATED) {
        log.admin(`Warning: relay auth not confirmed (status: ${relay.status}) for Kind 297 publish`)
      }
    }
  }

  try {
    const pubBytes = Buffer.from(pubkey, 'hex')
    const b64 = pubBytes.toString('base64')
    const signKey = `secp256k1-schnorr:${b64}`
    const encKey = `secp256k1-nip44:${b64}`
    const uid = identityIdFromPublicKey(pubkey)
    const validFrom = createdAt || Math.floor(Date.now() / 1000)

    // Idempotency: check if genesis already exists
    const existing = await queryExistingGenesisEntry(ndk, uid)
    if (existing) {
      log.admin(`Kind 297 genesis already exists for ${uid.substring(0, 16)}..., skipping publish`)
      checkpointService.broadcast('signer.kind297.published', {
        variant: 'genesis',
        entryId: existing.id,
        uid: uid.substring(0, 16),
        skipped: true
      })
      return existing.id
    }

    // Build content without endorsement first
    const contentWithoutPlatform = {
      version: 1,
      keys: {
        sign: signKey,
        enc: encKey
      },
      valid: {
        from: validFrom
      }
    }

    // Endorse with daemon key
    const endorsement = buildEndorsement(
      contentWithoutPlatform,
      uid,
      'genesis',
      masterKey,
      platformServiceEntryId
    )

    const fullContent = {
      ...contentWithoutPlatform,
      platform: endorsement
    }

    const builder = Kind297KeyChain.build({
      variant: 'genesis',
      content: fullContent
    })
    if (createdAt) builder.createdAt(createdAt)

    const event = await builder.toSignedNDKEvent({
      ndk,
      signer: userSigner,
      uid
    })

    event.on('relay:publish:failed', (relay: any, err: any) => {
      log.admin(`❌ Kind 297 publish failed on relay ${relay?.url}: ${err?.message || err}`)
    })
    event.on('relay:published', (relay: any) => {
      log.admin(`✅ Kind 297 published on relay ${relay?.url}`)
    })

    const relaySet = NDKRelaySet.fromRelayUrls(relayUrls, ndk)
    const published = await event.publish(relaySet)
    if (published.size === 0) {
      throw new Error(`Not enough relays received the Kind 297 event (0 published, ${relayUrls.length} required)`)
    }

    log.admin(`Kind 297 genesis published for ${uid.substring(0, 16)}... (id: ${event.id})`)

    checkpointService.broadcast('signer.kind297.published', {
      variant: 'genesis',
      entryId: event.id,
      uid: uid.substring(0, 16),
      skipped: false
    })

    return event.id
  } finally {
    if (!ndkInstance && ndk.pool) {
      ndk.pool.relays.forEach((relay) => relay.disconnect())
    }
  }
}

// ── Delegate Publication ─────────────────────────────────────────────────────

/**
 * Publishes a Kind 297 delegate event authorizing a client signing key.
 * Signed by the user's identity key and endorsed by the daemon key.
 * Day-quantized and held-until-first-use at the relay.
 */
export async function publishDelegateEntry(
  userSigner: NDKPrivateKeySigner,
  pubkey: string,
  localSigningPubkey: string,
  relayUrls: string[],
  platformServiceEntryId: string,
  parentEntryId?: string,
  createdAt?: number,
  ndkInstance?: NDK
): Promise<string> {
  if (!relayUrls || relayUrls.length === 0) {
    throw new Error('No relay URLs configured — cannot publish Kind 297')
  }
  const masterKey = process.env.SIGNER_MASTER_KEY
  if (!masterKey) {
    throw new Error('SIGNER_MASTER_KEY not set — cannot endorse or authenticate with relay')
  }

  let ndk: NDK
  if (ndkInstance) {
    ndk = ndkInstance
  } else {
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
  }

  try {
    const uid = identityIdFromPublicKey(pubkey)
    let kid = parentEntryId
    if (!kid) {
      const genesis = await queryExistingGenesisEntry(ndk, uid)
      if (!genesis) {
        throw new Error(`Cannot issue delegate entry: no genesis entry found for ${uid}`)
      }
      kid = genesis.id
    }

    let localKeyStr: string
    if (localSigningPubkey.startsWith('secp256k1-schnorr:')) {
      localKeyStr = localSigningPubkey
    } else if (/^[a-f0-9]{64}$/i.test(localSigningPubkey)) {
      const pubBytes = hexToBytes(localSigningPubkey)
      localKeyStr = `secp256k1-schnorr:${base64.encode(pubBytes)}`
    } else {
      localKeyStr = `secp256k1-schnorr:${localSigningPubkey}`
    }

    const nowSec = createdAt || Math.floor(Date.now() / 1000)
    const startOfDay = Math.floor(nowSec / 86400) * 86400
    const endOfDay = startOfDay + 86400 - 1

    const contentWithoutPlatform = {
      version: 1,
      keys: {
        sign: localKeyStr
      },
      valid: {
        from: startOfDay,
        until: endOfDay
      }
    }

    const endorsement = buildEndorsement(
      contentWithoutPlatform,
      uid,
      'delegate',
      masterKey,
      platformServiceEntryId
    )

    const fullContent = {
      ...contentWithoutPlatform,
      platform: endorsement
    }

    const builder = Kind297KeyChain.build({
      variant: 'delegate',
      kid,
      created_at: startOfDay,
      content: fullContent
    })

    const event = await builder.toSignedNDKEvent({
      ndk,
      signer: userSigner,
      uid
    })

    const relaySet = NDKRelaySet.fromRelayUrls(relayUrls, ndk)
    const published = await event.publish(relaySet)
    if (published.size === 0) {
      throw new Error(`Not enough relays received the Kind 297 delegate event (0 published, ${relayUrls.length} required)`)
    }

    log.admin(`Kind 297 delegate published for ${uid.substring(0, 16)}... (id: ${event.id})`)

    checkpointService.broadcast('signer.kind297.published', {
      variant: 'delegate',
      entryId: event.id,
      uid: uid.substring(0, 16),
      skipped: false
    })

    return event.id
  } finally {
    if (!ndkInstance && ndk.pool) {
      ndk.pool.relays.forEach((relay) => relay.disconnect())
    }
  }
}

// ── Revoke Publication ───────────────────────────────────────────────────────

/**
 * Publishes a Kind 297 revoke event referencing a target delegate entry via #e tag.
 * Signed by the user's identity key and endorsed by the daemon key.
 */
export async function publishRevokeEntry(
  userSigner: NDKPrivateKeySigner,
  pubkey: string,
  targetEntryId: string,
  relayUrls: string[],
  platformServiceEntryId: string,
  parentEntryId?: string,
  createdAt?: number,
  ndkInstance?: NDK
): Promise<string> {
  if (!relayUrls || relayUrls.length === 0) {
    throw new Error('No relay URLs configured — cannot publish Kind 297')
  }
  const masterKey = process.env.SIGNER_MASTER_KEY
  if (!masterKey) {
    throw new Error('SIGNER_MASTER_KEY not set — cannot endorse or authenticate with relay')
  }

  let ndk: NDK
  if (ndkInstance) {
    ndk = ndkInstance
  } else {
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
  }

  try {
    const uid = identityIdFromPublicKey(pubkey)
    let kid = parentEntryId
    if (!kid) {
      const genesis = await queryExistingGenesisEntry(ndk, uid)
      if (!genesis) {
        throw new Error(`Cannot issue revoke entry: no genesis entry found for ${uid}`)
      }
      kid = genesis.id
    }

    const nowSec = createdAt || Math.floor(Date.now() / 1000)

    const contentWithoutPlatform = {
      version: 1
    }

    const endorsement = buildEndorsement(
      contentWithoutPlatform,
      uid,
      'revoke',
      masterKey,
      platformServiceEntryId
    )

    const fullContent = {
      ...contentWithoutPlatform,
      platform: endorsement
    }

    const builder = Kind297KeyChain.build({
      variant: 'revoke',
      kid,
      created_at: nowSec,
      tags: {
        e: targetEntryId
      },
      content: fullContent
    })

    const event = await builder.toSignedNDKEvent({
      ndk,
      signer: userSigner,
      uid
    })

    const relaySet = NDKRelaySet.fromRelayUrls(relayUrls, ndk)
    const published = await event.publish(relaySet)
    if (published.size === 0) {
      throw new Error(`Not enough relays received the Kind 297 revoke event (0 published, ${relayUrls.length} required)`)
    }

    log.admin(`Kind 297 revoke published for ${uid.substring(0, 16)}... (id: ${event.id}, revoked: ${targetEntryId})`)

    checkpointService.broadcast('signer.kind297.published', {
      variant: 'revoke',
      entryId: event.id,
      uid: uid.substring(0, 16),
      skipped: false
    })

    return event.id
  } finally {
    if (!ndkInstance && ndk.pool) {
      ndk.pool.relays.forEach((relay) => relay.disconnect())
    }
  }
}

