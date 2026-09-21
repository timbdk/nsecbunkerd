/**
 * Purpose: Transport KEM manager handling active/overlap key states, decapsulation dispatch,
 *          Kind 30297 announcement publication, and KEM_STALE_KEY error construction.
 * Behavior: Manages an active ML-KEM-768 keypair and an unexpired overlap keypair with injectable clock.
 * Usage: Consumed by Daemon startup, NIP-46 backend transport decapsulation, and HTTP rotation endpoints.
 */

import { base64 } from '@scure/base'
import { hexToBytes, bytesToHex } from '@noble/hashes/utils.js'
import { sha256 } from '@noble/hashes/sha2.js'
import NDK, { NDKRelaySet, NDKSigner, DEFAULT_PUBLISH_TIMEOUT_MS } from '@nostr-dev-kit/ndk'
import {
  Kind30297ServiceAnnouncement,
  keygen,
  publicKeyFromSecret,
  kemDecrypt
} from 'verity-event-data-module'
import { checkpointService } from '../../services/CheckpointService.js'
import { log } from '../../lib/logger.js'
import prisma from '../../db.js'
import { RELAY_QUERY_TIMEOUT_MS } from './keychain-event.js'

export interface TransportKeypair {
  secretKeyHex: string
  publicKeyHex: string
}

export interface OverlapTransportKeypair extends TransportKeypair {
  expiresAt: number
}

export class TransportKemManager {
  public activeKey: TransportKeypair
  public overlapKey: OverlapTransportKeypair | null = null
  public clock: () => number

  constructor(
    initialKeyHex: string,
    initialOverlapKeyHex?: string,
    clock: () => number = () => Date.now()
  ) {
    this.clock = clock
    const activePubBytes = publicKeyFromSecret('ml-kem-768', initialKeyHex)
    this.activeKey = {
      secretKeyHex: initialKeyHex,
      publicKeyHex: bytesToHex(activePubBytes)
    }

    if (initialOverlapKeyHex) {
      const overlapPubBytes = publicKeyFromSecret('ml-kem-768', initialOverlapKeyHex)
      this.overlapKey = {
        secretKeyHex: initialOverlapKeyHex,
        publicKeyHex: bytesToHex(overlapPubBytes),
        expiresAt: this.clock() + 86400 * 1000
      }
    }
  }

  getActivePublicKey(): string {
    return this.activeKey.publicKeyHex
  }

  rotate(
    newKeypair?: TransportKeypair,
    windowSeconds: number = 86400
  ): TransportKeypair {
    const now = this.clock()
    this.overlapKey = {
      ...this.activeKey,
      expiresAt: now + windowSeconds * 1000
    }

    if (newKeypair) {
      this.activeKey = newKeypair
    } else {
      const kp = keygen('ml-kem-768')
      this.activeKey = {
        secretKeyHex: bytesToHex(kp.secretKey),
        publicKeyHex: bytesToHex(kp.publicKey)
      }
    }

    return this.activeKey
  }

  getCandidateSecretKeys(now: number = this.clock()): string[] {
    const keys = [this.activeKey.secretKeyHex]
    if (this.overlapKey && this.overlapKey.expiresAt > now) {
      keys.push(this.overlapKey.secretKeyHex)
    }
    return keys
  }

  decapsulate(payload: string, now: number = this.clock()): string {
    const keys = this.getCandidateSecretKeys(now)
    for (const sk of keys) {
      try {
        return kemDecrypt(sk, payload)
      } catch {
        // Try next candidate key
      }
    }
    throw new Error('AEAD decryption failed: no matching active or unexpired overlap transport KEM key')
  }

  async buildStaleKeyError(
    senderUid: string,
    requestId?: string
  ): Promise<{ error: string; code: string; id?: string } | null> {
    const session = await prisma.session.findFirst({
      where: {
        clientPubkey: senderUid,
        revokedAt: null
      }
    })

    if (!session) {
      log.daemon(`Undecapsulatable request from unknown transport uid ${senderUid.substring(0, 16)}... dropped silently`)
      return null
    }

    return {
      error: 'KEM key is stale; please refresh transport announcement',
      code: 'KEM_STALE_KEY',
      id: requestId
    }
  }

  async publishAnnouncement(
    ndk: NDK,
    daemonSigner: NDKSigner,
    daemonKeyHex: string,
    relayUrls: string[]
  ): Promise<string> {
    if (!relayUrls || relayUrls.length === 0) {
      throw new Error('No relay URLs configured — cannot publish Kind 30297 announcement')
    }

    const daemonPubBytes = publicKeyFromSecret('ml-dsa-44', daemonKeyHex)
    const daemonKeyHash = bytesToHex(sha256(daemonPubBytes))
    const keyField = `ml-dsa-44:${base64.encode(daemonPubBytes)}`

    const activePubBytes = hexToBytes(this.activeKey.publicKeyHex)
    const kemB64 = base64.encode(activePubBytes)

    try {
      const queryPromise = ndk.fetchEvents({
        kinds: [30297 as any],
        authors: [daemonKeyHash],
        '#d': ['transport-kem']
      })
      const timeoutPromise = new Promise<Set<any>>((resolve) =>
        setTimeout(() => resolve(new Set()), RELAY_QUERY_TIMEOUT_MS)
      )
      const existingEvents = await Promise.race([queryPromise, timeoutPromise])

      let latestEvent: any = null
      for (const ev of existingEvents) {
        if (!latestEvent || ev.created_at > latestEvent.created_at) {
          latestEvent = ev
        }
      }

      if (latestEvent) {
        try {
          const parsed = typeof latestEvent.content === 'string' ? JSON.parse(latestEvent.content) : latestEvent.content
          if (parsed?.kem?.b64 === kemB64) {
            log.daemon(`Kind 30297 transport announcement already current for ${daemonKeyHash.substring(0, 16)}...`)
            checkpointService.broadcast('signer.announcement.published', {
              eventId: latestEvent.id.substring(0, 16),
              fingerprint: daemonKeyHash.substring(0, 16),
              skipped: true
            })
            return latestEvent.id
          }
        } catch {
          // ignore parse failure, publish fresh
        }
      }
    } catch (e: any) {
      log.daemon(`Query existing 30297 failed, proceeding to publish: ${e.message}`)
    }

    const content = {
      version: 1 as const,
      kem: {
        alg: 'ml-kem-768' as const,
        b64: kemB64
      }
    }

    const builder = Kind30297ServiceAnnouncement.build({
      key: keyField,
      uid: daemonKeyHash,
      tags: {
        d: 'transport-kem'
      },
      content
    })
      .createdAt(Math.floor(this.clock() / 1000))

    const event = await builder.toSignedNDKEvent({
      ndk,
      signer: daemonSigner,
      uid: daemonKeyHash,
      key: keyField
    })

    let published: Set<any>
    if (ndk.pool) {
      const relaySet = NDKRelaySet.fromRelayUrls(relayUrls, ndk)
      published = await event.publish(relaySet, DEFAULT_PUBLISH_TIMEOUT_MS)
    } else {
      published = await (ndk as any).publish(event)
    }
    if (published.size === 0) {
      throw new Error(`Not enough relays received the Kind 30297 announcement (0 published, ${relayUrls.length} required)`)
    }

    log.daemon(`Kind 30297 transport announcement published for ${daemonKeyHash.substring(0, 16)}... (id: ${event.id})`)

    checkpointService.broadcast('signer.announcement.published', {
      eventId: event.id.substring(0, 16),
      fingerprint: daemonKeyHash.substring(0, 16),
      skipped: false
    })

    return event.id
  }
}
