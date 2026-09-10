import NDK, {
  NDKNip46Backend,
  NDKMlDsaSigner,
  NDKPrivateKeySigner,
  NDKTransportCredential,
  NDKEvent,
  NDKUser,
  Nip46PermitCallback,
  IEventHandlingStrategy
} from '@nostr-dev-kit/ndk'
import { IConfig } from '../../config/index.js'
import type { KeyFamily } from '../../services/KeyService.js'
import { queryCurrentIdentityEntry } from '../lib/keychain-event.js'
import { identityIdFromPublicKey } from 'verity-event-data-module'
import { log } from '../../lib/logger.js'
import prisma from '../../db.js'
import { base64 } from '@scure/base'
import { bytesToHex } from '@noble/hashes/utils.js'

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
  constructor(private backend: Backend, private family: KeyFamily) {}

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

    // Nomination validation (relay round-trip, only after client is authorized)
    const identityUid = identityIdFromPublicKey(this.family.identity.pubkey)
    await validateKidNomination(backend.ndk, (event as any).kid, identityUid)

    // Sign with ML-DSA identity signer
    await event.sign(this.backend.identitySigner)

    // Preserve verbatim template fields on raw event
    const raw = event.rawEvent()
    if (parsedEvent.uid) (raw as any).uid = parsedEvent.uid
    if (parsedEvent.kid) (raw as any).kid = parsedEvent.kid

    return JSON.stringify(raw)
  }
}

export class VerityNip44EncryptStrategy implements IEventHandlingStrategy {
  constructor(private backend: Backend, private family: KeyFamily) {}

  async handle(backend: NDKNip46Backend, id: string, remotePubkey: string, params: string[]): Promise<string | undefined> {
    if (!this.backend.encSigner) {
      throw new Error('No encryption key configured for account')
    }

    const [recipientPubkey, payload] = params
    const ownIdentityPubkey = this.family.identity.pubkey
    const ownUid = identityIdFromPublicKey(ownIdentityPubkey)
    const ownEncPubkey = this.family.enc?.pubkey

    let targetPubkey = recipientPubkey
    if (targetPubkey === ownIdentityPubkey || targetPubkey === ownUid || targetPubkey === ownEncPubkey) {
      targetPubkey = (await this.backend.encSigner.user()).pubkey
    }

    const recipientUser = new NDKUser({ pubkey: targetPubkey })

    if (
      !(await backend.pubkeyAllowed({
        id,
        pubkey: remotePubkey,
        method: 'nip44_encrypt',
        params: payload
      }))
    ) {
      return undefined
    }

    return await this.backend.encSigner.encrypt(recipientUser, payload, 'nip44')
  }
}

export class VerityNip44DecryptStrategy implements IEventHandlingStrategy {
  constructor(private backend: Backend, private family: KeyFamily) {}

  async handle(backend: NDKNip46Backend, id: string, remotePubkey: string, params: string[]): Promise<string | undefined> {
    if (!this.backend.encSigner) {
      throw new Error('No encryption key configured for account')
    }

    const [senderPubkey, payload] = params
    const ownIdentityPubkey = this.family.identity.pubkey
    const ownUid = identityIdFromPublicKey(ownIdentityPubkey)
    const ownEncPubkey = this.family.enc?.pubkey

    let targetPubkey = senderPubkey
    if (targetPubkey === ownIdentityPubkey || targetPubkey === ownUid || targetPubkey === ownEncPubkey) {
      targetPubkey = (await this.backend.encSigner.user()).pubkey
    }

    const senderUser = new NDKUser({ pubkey: targetPubkey })

    if (
      !(await backend.pubkeyAllowed({
        id,
        pubkey: remotePubkey,
        method: 'nip44_decrypt',
        params: payload
      }))
    ) {
      return undefined
    }

    return await this.backend.encSigner.decrypt(senderUser, payload, 'nip44')
  }
}

export class VerityConnectStrategy implements IEventHandlingStrategy {
  constructor(private backend: Backend, private family: KeyFamily) {}

  async handle(backend: NDKNip46Backend, id: string, remotePubkey: string, params: string[]): Promise<string | undefined> {
    const [_, token, encPubkey] = params
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

    let clientEncHex: string | undefined
    if (encPubkey) {
      try {
        if (/^[a-f0-9]{64}$/i.test(encPubkey)) {
          clientEncHex = encPubkey.toLowerCase()
        } else {
          clientEncHex = bytesToHex(base64.decode(encPubkey))
        }
      } catch {
        // ignore
      }
    }
    if (!clientEncHex && backend.rpc?.peerEcdhPubkeys?.has(remotePubkey)) {
      clientEncHex = backend.rpc.peerEcdhPubkeys.get(remotePubkey)
    }

    if (clientEncHex && !/^[0-9a-f]{64}$/i.test(clientEncHex)) {
      clientEncHex = undefined
    }

    if (clientEncHex) {
      try {
        const normalizedRemote = remotePubkey.length === 2624 ? identityIdFromPublicKey(remotePubkey) : remotePubkey
        await prisma.session.updateMany({
          where: {
            keyName: this.family.identity.keyName,
            clientPubkey: { in: [remotePubkey, normalizedRemote] }
          },
          data: {
            clientEncPubkey: clientEncHex
          }
        })
        debug(`saved clientEncPubkey ${clientEncHex} for ${remotePubkey}`)
      } catch (e) {
        log.acl('Failed to save clientEncPubkey on session', e)
      }
    }

    debug(`connection request from ${remotePubkey} allowed`)
    return 'ack'
  }
}

export class Backend extends NDKNip46Backend {
  public identitySigner: NDKMlDsaSigner
  public encSigner?: NDKPrivateKeySigner

  constructor(ndk: NDK, family: KeyFamily, cb: Nip46PermitCallback, config: IConfig) {
    const identitySigner = new NDKMlDsaSigner(family.identity.privateKeyHex)
    const encSigner = family.enc ? new NDKPrivateKeySigner(family.enc.privateKeyHex) : undefined
    const credential = encSigner ? new NDKTransportCredential(identitySigner, encSigner, ndk) : identitySigner

    super(ndk, credential, cb, [])
    this.identitySigner = identitySigner
    this.encSigner = encSigner

    this.setStrategy('connect', new VerityConnectStrategy(this, family))
    this.setStrategy('sign_event', new VeritySignEventStrategy(this, family))
    this.setStrategy('nip44_encrypt', new VerityNip44EncryptStrategy(this, family))
    this.setStrategy('nip44_decrypt', new VerityNip44DecryptStrategy(this, family))

    this.rpc.resolvePeerEcdhPubkey = async (clientPubkey: string) => {
      const normalizedPubkey = clientPubkey.length === 2624 ? identityIdFromPublicKey(clientPubkey) : clientPubkey
      const session = await prisma.session.findFirst({
        where: {
          keyName: family.identity.keyName,
          clientPubkey: { in: [clientPubkey, normalizedPubkey] }
        },
        select: { clientEncPubkey: true }
      })
      return session?.clientEncPubkey ?? undefined
    }
  }
}
