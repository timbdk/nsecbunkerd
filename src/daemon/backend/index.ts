import NDK, {
  NDKNip46Backend,
  NDKNip46DaemonBackend,
  NDKMlDsaSigner,
  NDKTransportCredential,
  NDKEvent,
  Nip46PermitCallback,
  Nip46DaemonPermitCallback,
  Nip46SessionResolution,
  IEventHandlingStrategy
} from '@nostr-dev-kit/ndk'
import { IConfig } from '../../config/index.js'
import type { KeyFamily } from '../../services/KeyService.js'
import { queryCurrentIdentityEntry } from '../lib/keychain-event.js'
import { identityIdFromPublicKey, kemDecrypt } from 'verity-event-data-module'
import { log } from '../../lib/logger.js'
import { checkpointService } from '../../services/CheckpointService.js'
import prisma from '../../db.js'
import { base64 } from '@scure/base'
import { bytesToHex } from '@noble/hashes/utils.js'
import type { TransportKemManager } from '../lib/transport-kem.js'

export async function validateKidNomination(
  ndk: NDK,
  candidateKid: string | undefined,
  identityUid: string
): Promise<void> {
  if (!candidateKid) {
    throw new Error(`[KID_NOMINATION_INVALID] missing: kid tag is required`)
  }

  const current = await queryCurrentIdentityEntry(ndk, identityUid)
  if (!current || current.id !== candidateKid) {
    throw new Error(`[KID_NOMINATION_INVALID] ${candidateKid}: not the current active identity key entry`)
  }

  // Defensive check: queryCurrentIdentityEntry resolves via currentIdentityEntry
  // which filters to genesis/rotate, but we verify here as defense-in-depth.
  if (current.variant !== 'genesis' && current.variant !== 'rotate') {
    throw new Error(`[KID_NOMINATION_INVALID] ${candidateKid}: entry is variant '${current.variant}', not an identity key entry`)
  }
}

export class VeritySignEventStrategy implements IEventHandlingStrategy {
  constructor(private backend?: Backend, private family?: KeyFamily) {}

  async handle(backend: NDKNip46Backend, id: string, remotePubkey: string, params: string[]): Promise<string | undefined> {
    const [eventString] = params
    const parsedEvent = JSON.parse(eventString)
    const event = new NDKEvent(backend.ndk, parsedEvent)

    if (parsedEvent.uid) event.uid = parsedEvent.uid
    if (parsedEvent.kid) (event as any).kid = parsedEvent.kid
    if (parsedEvent.id) event.id = parsedEvent.id

    // Check ACL authorization before performing any relay queries
    if (
      !(await backend.pubkeyAllowed({
        id,
        pubkey: remotePubkey,
        method: 'sign_event',
        params: event
      }))
    ) {
      log.signing(`sign_event request from ${remotePubkey} rejected by ACL`)
      return undefined
    }

    const family: KeyFamily | undefined = (backend as any).sessionBinding?.context?.family ?? (backend as any).family ?? this.family
    if (!family) {
      log.signing(`sign_event request from ${remotePubkey} rejected: no identity family resolved`)
      return undefined
    }

    const identitySigner = (backend as any).identitySigner ?? (backend as any).backend?.identitySigner ?? this.backend?.identitySigner ?? new NDKMlDsaSigner(family.identity.privateKeyHex)

    // Nomination validation (relay round-trip, only after client is authorized)
    const identityUid = identityIdFromPublicKey(family.identity.pubkey)
    await validateKidNomination(backend.ndk, (event as any).kid, identityUid)

    // Sign with ML-DSA identity signer
    await event.sign(identitySigner)

    // Preserve verbatim template fields on raw event
    const raw = event.rawEvent()
    if (parsedEvent.uid) (raw as any).uid = parsedEvent.uid
    if (parsedEvent.kid) (raw as any).kid = parsedEvent.kid

    return JSON.stringify(raw)
  }
}

export class VerityKemDecryptStrategy implements IEventHandlingStrategy {
  constructor(
    private backend?: Backend,
    private family?: KeyFamily,
    private decapsulate: (secretKeyHex: string, payload: string) => string = kemDecrypt
  ) {}

  async handle(backend: NDKNip46Backend, id: string, remotePubkey: string, params: string[]): Promise<string | undefined> {
    if (!params || params.length !== 1 || typeof params[0] !== 'string' || !params[0]) {
      throw new Error('Invalid parameters: kem_decrypt requires exactly [value]')
    }

    const [payload] = params

    if (
      !(await backend.pubkeyAllowed({
        id,
        pubkey: remotePubkey,
        method: 'kem_decrypt',
        params: payload
      }))
    ) {
      return undefined
    }

    const family: KeyFamily | undefined = (backend as any).sessionBinding?.context?.family ?? (backend as any).family ?? this.backend?.family ?? this.family
    const kemFamily = family?.kem

    const candidateKeys: string[] = []
    if (kemFamily?.active?.privateKeyHex) {
      candidateKeys.push(kemFamily.active.privateKeyHex)
    }
    if (kemFamily?.retired && kemFamily.retired.length > 0) {
      for (const member of kemFamily.retired) {
        if (member.privateKeyHex) {
          candidateKeys.push(member.privateKeyHex)
        }
      }
    }

    if (candidateKeys.length === 0) {
      throw new Error('No KEM key configured for account')
    }

    for (const secretKeyHex of candidateKeys) {
      try {
        const decrypted = this.decapsulate(secretKeyHex, payload)
        checkpointService.broadcast('signer.kem_decrypt.completed', {
          keyName: family ? family.identity.keyName.substring(0, 16) : 'unknown',
          id
        })
        return decrypted
      } catch {
        // Try next candidate key
      }
    }

    throw new Error('AEAD decryption failed: no matching active or retired KEM key')
  }
}

export class VerityConnectStrategy implements IEventHandlingStrategy {
  constructor(private backend?: Backend, private family?: KeyFamily) {}

  async handle(backend: NDKNip46Backend, id: string, remotePubkey: string, params: string[]): Promise<string | undefined> {
    const token = params[1]
    const rawKemCandidate = params[3] ?? params[2]
    const debug = backend.debug.extend('connect')

    debug(`connection request from ${remotePubkey}`)

    if (token && backend.applyToken) {
      debug('applying token')
      await backend.applyToken(remotePubkey, token)
    }

    if (
      !(await backend.pubkeyAllowed({
        id,
        pubkey: remotePubkey,
        method: 'connect',
        params: token
      }))
    ) {
      debug(`connection request from ${remotePubkey} rejected`)
      return undefined
    }

    const family: KeyFamily | undefined = (backend as any).sessionBinding?.context?.family ?? (backend as any).family ?? this.family
    const keyName = family?.identity?.keyName ?? (backend as any).keyName

    let clientKemHex: string | undefined
    if (rawKemCandidate) {
      try {
        if (/^[a-f0-9]{2368}$/i.test(rawKemCandidate)) {
          clientKemHex = rawKemCandidate.toLowerCase()
        } else {
          const decoded = base64.decode(rawKemCandidate)
          if (decoded.length === 1184) {
            clientKemHex = bytesToHex(decoded)
          }
        }
      } catch {
        // ignore
      }
    }

    if (keyName) {
      try {
        const normalizedRemote = remotePubkey.length === 2624 ? identityIdFromPublicKey(remotePubkey) : remotePubkey
        const updateData: any = { updatedAt: new Date(), lastUsedAt: new Date() }
        if (clientKemHex) {
          updateData.clientKemPubkey = clientKemHex
        }
        await prisma.session.updateMany({
          where: {
            keyName,
            clientPubkey: { in: [remotePubkey, normalizedRemote] }
          },
          data: updateData
        })
        debug(`updated session for keyName=${keyName}, client=${remotePubkey}`)
      } catch (e) {
        log.acl('Failed to update session on connect', e)
      }
    }

    const sessionUid = remotePubkey.length === 2624 ? identityIdFromPublicKey(remotePubkey) : remotePubkey
    checkpointService.broadcast('signer.rpc.connect.completed', {
      keyName: keyName ? keyName.substring(0, 16) : 'unknown',
      sessionUid: sessionUid.substring(0, 16)
    })

    debug(`connection request from ${remotePubkey} allowed`)
    return 'ack'
  }
}

/**
 * Consolidated DaemonBackend serving all identities through a single subscription.
 */
export class DaemonBackend extends NDKNip46DaemonBackend {
  public keyRegistry: Map<string, KeyFamily>
  public transportKemManager: TransportKemManager

  constructor(
    ndk: NDK,
    daemonCredential: NDKTransportCredential,
    keyRegistry: Map<string, KeyFamily>,
    transportKemManager: TransportKemManager,
    permitCallback: Nip46DaemonPermitCallback,
    config: IConfig
  ) {
    const resolvePeerKemKey = async (clientPubkey: string) => {
      const normalizedPubkey = clientPubkey.length === 2624 ? identityIdFromPublicKey(clientPubkey) : clientPubkey
      const session = await prisma.session.findFirst({
        where: {
          clientPubkey: { in: [clientPubkey, normalizedPubkey] },
          revokedAt: null
        },
        orderBy: { updatedAt: 'desc' },
        select: { clientKemPubkey: true }
      })
      const key = session?.clientKemPubkey
      if (!key || key.length !== 2368) {
        return undefined
      }
      return key
    }

    const resolveSession = async (transportUid: string, method?: string, params?: any[]): Promise<Nip46SessionResolution | undefined> => {
      const normalizedUid = transportUid.length === 2624 ? identityIdFromPublicKey(transportUid) : transportUid

      // 1. On connect, resolve strictly for the requested user candidate from params[0]
      if (method === 'connect' && params && params[0]) {
        const candidate = params[0]
        for (const [name, fam] of keyRegistry.entries()) {
          if (name === candidate || fam.identity.pubkey === candidate || identityIdFromPublicKey(fam.identity.pubkey) === candidate) {
            const specificSession = await prisma.session.findFirst({
              where: {
                keyName: name,
                clientPubkey: { in: [transportUid, normalizedUid] },
                revokedAt: null
              }
            })
            if (specificSession) {
              return {
                keyName: name,
                responseKemKey: specificSession.clientKemPubkey ?? undefined,
                identitySigner: new NDKMlDsaSigner(fam.identity.privateKeyHex),
                identityPubkey: fam.identity.pubkey,
                context: { family: fam }
              }
            }
            return undefined
          }
        }
        return undefined
      }

      // 2. Otherwise find the most recently active session for this client
      let session = await prisma.session.findFirst({
        where: {
          clientPubkey: { in: [transportUid, normalizedUid] },
          revokedAt: null
        },
        orderBy: { updatedAt: 'desc' }
      })

      if (!session) return undefined

      const family = keyRegistry.get(session.keyName)
      if (!family) {
        log.daemon(`Session found for key ${session.keyName} but key family is not loaded in daemon registry`)
        return undefined
      }

      return {
        keyName: session.keyName,
        responseKemKey: session.clientKemPubkey ?? undefined,
        identitySigner: new NDKMlDsaSigner(family.identity.privateKeyHex),
        identityPubkey: family.identity.pubkey,
        context: { family }
      }
    }

    super(ndk, daemonCredential, {
      resolveSession,
      permitCallback,
      relayUrls: config.nostr.relays,
      rpcOptions: {
        envelopeMode: 'kem',
        resolvePeerKemKey,
        responseCapable: true
      },
      onStaleKeySent: (transportUid: string) => {
        checkpointService.broadcast('signer.rpc.kem_stale_key', {
          uid: transportUid.substring(0, 16)
        })
      },
      onRequestReceived: ({ id, method, transportUid, keyName }) => {
        checkpointService.broadcast('signer.rpc.request.received', {
          id,
          method,
          uid: transportUid.substring(0, 16),
          keyName: keyName ? keyName.substring(0, 16) : undefined
        })
      },
      onResponseSent: ({ id, method, transportUid, keyName }) => {
        checkpointService.broadcast('signer.rpc.response.sent', {
          id,
          method,
          uid: transportUid.substring(0, 16),
          keyName: keyName ? keyName.substring(0, 16) : undefined
        })
      }
    })

    this.keyRegistry = keyRegistry
    this.transportKemManager = transportKemManager

    this.setStrategy('connect', new VerityConnectStrategy(this as any, undefined as any))
    this.setStrategy('sign_event', new VeritySignEventStrategy(this as any, undefined as any))
    this.setStrategy('kem_decrypt', new VerityKemDecryptStrategy(this as any, undefined as any))
  }
}

/**
 * Per-user Backend class (maintained for unit tests and backwards compatibility).
 */
export class Backend extends NDKNip46Backend {
  public identitySigner: NDKMlDsaSigner
  public family: KeyFamily

  constructor(ndk: NDK, family: KeyFamily, cb: Nip46PermitCallback, config: IConfig) {
    const identitySigner = new NDKMlDsaSigner(family.identity.privateKeyHex)
    const credential = new NDKTransportCredential(
      identitySigner,
      {
        kem: family.kem?.active?.privateKeyHex
      },
      ndk
    )

    credential.kemDecaps = (payload: string): string => {
      const candidateKeys: string[] = []
      const kemFamily = this?.family?.kem ?? family.kem
      if (kemFamily?.active?.privateKeyHex) {
        candidateKeys.push(kemFamily.active.privateKeyHex)
      }
      if (kemFamily?.retired && kemFamily.retired.length > 0) {
        for (const member of kemFamily.retired) {
          if (member.privateKeyHex) {
            candidateKeys.push(member.privateKeyHex)
          }
        }
      }
      for (const secretKeyHex of candidateKeys) {
        try {
          return kemDecrypt(secretKeyHex, payload)
        } catch {
          // Try next candidate key
        }
      }
      throw new Error('AEAD decryption failed: no matching active or retired KEM key')
    }

    const resolvePeerKemKey = async (clientPubkey: string) => {
      const normalizedPubkey = clientPubkey.length === 2624 ? identityIdFromPublicKey(clientPubkey) : clientPubkey
      const session = await prisma.session.findFirst({
        where: {
          keyName: family.identity.keyName,
          clientPubkey: { in: [clientPubkey, normalizedPubkey] }
        },
        select: { clientKemPubkey: true }
      })
      const key = session?.clientKemPubkey
      if (!key || key.length !== 2368) {
        return undefined
      }
      return key
    }

    super(ndk, credential, cb, config.nostr.relays, {
      envelopeMode: 'kem',
      resolvePeerKemKey,
      responseCapable: true
    })
    this.identitySigner = identitySigner
    this.family = family

    this.setStrategy('connect', new VerityConnectStrategy(this, family))
    this.setStrategy('sign_event', new VeritySignEventStrategy(this, family))
    this.setStrategy('kem_decrypt', new VerityKemDecryptStrategy(this, family))
  }

  updateKemFamily(kem: KeyFamily['kem']) {
    this.family.kem = kem
  }
}
