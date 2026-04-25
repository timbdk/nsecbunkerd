import { NDKEvent, NostrEvent } from '@nostr-dev-kit/ndk'
import prisma from '../../../db.js'
import { log } from '../../../lib/logger.js'

export async function checkIfPubkeyAllowed(
  keyName: string,
  clientPubkey: string,
  method: IMethod,
  payload?: string | NostrEvent
): Promise<boolean | undefined> {
  // find Session by specific pubkey
  let session = await prisma.session.findUnique({
    where: { keyName_clientPubkey: { keyName, clientPubkey } }
  })

  if (!session) {
    return undefined
  }

  // find SigningCondition
  const signingConditionQuery = requestToSigningConditionQuery(method, payload)

  const explicitReject = await prisma.signingCondition.findFirst({
    where: {
      sessionId: session.id,
      method: '*',
      allowed: false
    }
  })

  if (explicitReject) {
    log.acl(`explicit reject`, explicitReject)
    return false
  }

  const signingCondition = await prisma.signingCondition.findFirst({
    where: {
      sessionId: session.id,
      ...signingConditionQuery
    }
  })

  // if no SigningCondition found, return undefined
  if (!signingCondition) {
    return undefined
  }

  const allowed = signingCondition.allowed

  // Check if the session has been revoked
  if (allowed) {
    const revoked = await prisma.session.findFirst({
      where: {
        id: session.id,
        revokedAt: { not: null }
      }
    })

    if (revoked) {
      return false
    }
  }

  if (allowed === true || allowed === false) {
    log.acl(`found signing condition`, signingCondition)
    return allowed
  }

  return undefined
}

export type IMethod =
  | 'connect'
  | 'sign_event'
  | 'nip44_encrypt'
  | 'nip44_decrypt'
  | 'ping'
  | 'switch_relays'
  | 'get_public_key'

export type IAllowScope = {
  kind?: number | null
}

export function requestToSigningConditionQuery(method: IMethod, payload?: any) {
  const signingConditionQuery: any = { method }

  if (method === 'sign_event' && payload) {
    try {
      let kind: number | undefined
      
      // NIP-46 sign_event params is [eventJson]
      if (Array.isArray(payload) && typeof payload[0] === 'string') {
        const event = JSON.parse(payload[0])
        kind = event.kind
      } else if (typeof payload === 'object' && payload.kind !== undefined) {
        kind = payload.kind
      }

      if (kind !== undefined) {
        // Match specific kind OR null (wildcard)
        signingConditionQuery.OR = [
          { kind },
          { kind: null }
        ]
        // Remove the top-level method if we use OR at top level, 
        // but we want to keep method constraint.
        // Prisma: { method: 'sign_event', OR: [...] } works as AND(method, OR(...))
      }
    } catch (e) {
      log.acl('Error parsing event kind from payload', e)
    }
  }

  return signingConditionQuery
}

export function allowScopeToSigningConditionQuery(method: string, scope?: IAllowScope) {
  const signingConditionQuery: any = { method }

  if (scope && scope.kind !== undefined) {
    signingConditionQuery.kind = scope.kind
  }

  return signingConditionQuery
}

export async function allowAllRequestsFromKey(
  clientPubkey: string,
  keyName: string,
  method: string,
  param?: any,
  description?: string,
  allowScope?: IAllowScope
): Promise<void> {
  try {
    // Upsert the Session with the given clientPubkey
    const upsertedSession = await prisma.session.upsert({
      where: { keyName_clientPubkey: { keyName, clientPubkey } },
      update: { revokedAt: null },
      create: { keyName, clientPubkey, description }
    })

    // Create a new SigningCondition for the given Session and set allowed to true
    const signingConditionQuery = allowScopeToSigningConditionQuery(method, allowScope)
    await prisma.signingCondition.create({
      data: {
        allowed: true,
        sessionId: upsertedSession.id,
        ...signingConditionQuery
      }
    })

    // Resolve any pending authorization requests for this key/pubkey/method
    await prisma.audit.updateMany({
      where: {
        keyName,
        clientPubkey,
        method,
        allowed: null
      },
      data: {
        allowed: true
      }
    })
  } catch (e) {
    log.acl('allowAllRequestsFromKey', e)
  }
}

export async function rejectAllRequestsFromKey(clientPubkey: string, keyName: string): Promise<void> {
  // Upsert the Session with the given clientPubkey
  const upsertedSession = await prisma.session.upsert({
    where: { keyName_clientPubkey: { keyName, clientPubkey } },
    update: {},
    create: { keyName, clientPubkey }
  })

  // Create a new SigningCondition for the given Session and set allowed to false
  await prisma.signingCondition.create({
    data: {
      allowed: false,
      sessionId: upsertedSession.id
    }
  })
}
