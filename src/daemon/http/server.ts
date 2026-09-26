import { checkpointService } from '../../services/CheckpointService.js'
import prisma from '../../db.js'
import { NDKEvent, NDKPrivateKeySigner, NDKMlDsaSigner, DEFAULT_PUBLISH_TIMEOUT_MS } from '@nostr-dev-kit/ndk'
import { identityIdFromPublicKey, keygen } from 'verity-event-data-module'
import { Server } from 'bun'
import { log, logError } from '../../lib/logger.js'

export function startHttpServer(daemon: any, port: number, host?: string): Server {
  const isTesting = process.env.NODE_ENV === 'testing' || process.env.NODE_ENV === 'development'

  if (isTesting) {
    log.http(`🧪 Testing endpoints enabled (NODE_ENV=${process.env.NODE_ENV})`)
  }

  const server = Bun.serve({
    port,
    hostname: host || '0.0.0.0',
    async fetch(req) {
      const url = new URL(req.url)
      
      // CORS headers
      const headers = new Headers()
      headers.set('Access-Control-Allow-Origin', '*')
      headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
      headers.set('Access-Control-Allow-Headers', 'Content-Type')

      if (req.method === 'OPTIONS') {
        return new Response(null, { headers })
      }

      // Root endpoint
      if (url.pathname === '/') {
        return Response.json({
          status: 'ok',
          service: 'nsecbunker',
          ready: daemon.isReady,
          testing: isTesting
        }, { headers })
      }

      // Health check endpoint
      if (url.pathname === '/health') {
        const healthy = daemon.isReady && daemon.ndk?.pool?.relays?.size > 0
        return Response.json({
          status: healthy ? 'healthy' : 'unhealthy',
          ready: daemon.isReady,
          relays: daemon.ndk?.pool?.relays?.size || 0
        }, { status: healthy ? 200 : 503, headers })
      }

      // Testing endpoints (only available in testing/development environments)
      if (isTesting) {
        // POST /testing/register
        if (url.pathname === '/testing/register' && req.method === 'POST') {
          try {
            const body = await req.json() as any
            const { keyName, clientPubkey, clientEncPubkey, clientKemPubkey, createdAt, identityKey, encKey, kemKey } = body

            if (!keyName || !identityKey) {
              return Response.json({ error: 'keyName and identityKey are required' }, { status: 400, headers })
            }

            const { storeKey, retrieveKey } = await import('../../services/KeyService.js')
            const { allowAllRequestsFromKey, allowMethodsFromKey } = await import('../lib/acl/index.js')

            checkpointService.broadcast('signer.testing.register.received', { keyName, clientPubkey })

            const identitySecretHex: string = identityKey.secretKey
            const identityPubkeyHex: string = identityKey.publicKey

            const isMlDsa = identitySecretHex.length === 5120 || identityPubkeyHex.length === 2624
            if (!isMlDsa) {
              return Response.json({ error: 'Classical secp256k1 keys are not supported; ML-DSA-44 required' }, { status: 400, headers })
            }
            const identityAlg = 'ml-dsa-44'

            let encSecretHex: string | undefined
            let encPubkeyHex: string | undefined
            let shouldStoreEnc = false

            if (encKey) {
              encSecretHex = encKey.secretKey
              encPubkeyHex = encKey.publicKey
              shouldStoreEnc = true
            } else {
              const existingEnc = await prisma.key.findFirst({
                where: { parentKeyName: keyName, role: 'enc', status: 'ACTIVE' }
              })
              if (existingEnc) {
                encPubkeyHex = existingEnc.pubkey
                encSecretHex = await retrieveKey(existingEnc.keyName)
              } else {
                const generatedEnc = keygen('secp256k1-nip44')
                encSecretHex = Buffer.from(generatedEnc.secretKey).toString('hex')
                encPubkeyHex = Buffer.from(generatedEnc.publicKey).toString('hex')
                shouldStoreEnc = true
              }
            }

            let kemSecretHex: string | undefined
            let kemPubkeyHex: string | undefined
            let shouldStoreKem = false

            if (kemKey) {
              kemSecretHex = kemKey.secretKey
              kemPubkeyHex = kemKey.publicKey
              shouldStoreKem = true
            } else {
              const existingKem = await prisma.key.findFirst({
                where: { parentKeyName: keyName, role: 'kem', status: 'ACTIVE' }
              })
              if (existingKem) {
                kemPubkeyHex = existingKem.pubkey
              } else {
                const generatedKem = keygen('ml-kem-768')
                kemSecretHex = Buffer.from(generatedKem.secretKey).toString('hex')
                kemPubkeyHex = Buffer.from(generatedKem.publicKey).toString('hex')
                shouldStoreKem = true
              }
            }

            // Store identity row
            await storeKey(keyName, identitySecretHex, identityPubkeyHex, identityAlg, 'identity')
            // Store enc row if newly generated or explicitly provided
            if (shouldStoreEnc && encSecretHex && encPubkeyHex) {
              await storeKey(`${keyName}#enc`, encSecretHex, encPubkeyHex, 'secp256k1-nip44', 'enc', keyName)
            }
            // Store kem row if newly generated or explicitly provided
            if (shouldStoreKem && kemSecretHex && kemPubkeyHex) {
              await storeKey(`${keyName}#kem`, kemSecretHex, kemPubkeyHex, 'ml-kem-768', 'kem', keyName)
            }
            checkpointService.broadcast('signer.testing.key_stored', { keyName })

            const testSigner = new NDKMlDsaSigner(identitySecretHex)

            if (clientPubkey) {
              await allowMethodsFromKey(
                clientPubkey,
                keyName,
                [
                  { method: 'connect' },
                  { method: 'sign_event', allowScope: { kind: null } },
                  { method: 'nip44_encrypt' },
                  { method: 'nip44_decrypt' },
                  { method: 'kem_decrypt' },
                  { method: 'switch_relays' },
                  { method: 'get_public_key' },
                  { method: 'ping' }
                ],
                'test-client'
              )
              log.http(`🧪 Testing: authorized client ${clientPubkey.slice(0, 16)}... for key ${keyName}`)
              checkpointService.broadcast('signer.testing.client_authorized', { keyName, clientPubkey })

              const clientUid = clientPubkey.length === 2624 ? identityIdFromPublicKey(clientPubkey) : clientPubkey
              const targetKemPubkey = clientKemPubkey || (clientEncPubkey && clientEncPubkey.length === 2368 ? clientEncPubkey : undefined)
              if (targetKemPubkey) {
                await prisma.session.updateMany({
                  where: { keyName, clientPubkey: { in: [clientPubkey, clientUid] } },
                  data: { clientKemPubkey: targetKemPubkey }
                })
              }

              const attestationPayload = JSON.stringify({ id: 'short-circuit', result: 'attestation' })
              const encSigner = new NDKPrivateKeySigner(encSecretHex)
              const targetEncPubkey = clientEncPubkey || encPubkeyHex
              const clientUser = new (await import('@nostr-dev-kit/ndk')).NDKUser({ pubkey: targetEncPubkey })
              const encryptedAttestation = await encSigner.encrypt(clientUser, attestationPayload, 'nip44')

              const { NDKRelaySet } = await import('@nostr-dev-kit/ndk')
              const uid = identityIdFromPublicKey(identityPubkeyHex)
              const userPubkeyBytes = Buffer.from(identityPubkeyHex, 'hex')
              const keyField = 'ml-dsa-44:' + userPubkeyBytes.toString('base64')

              const attestationTags = [
                ['p', uid],
                ['policy', 'allow', 'user', uid],
                ['client', clientUid],
                ['user', uid]
              ]
              if (clientUid !== clientPubkey) {
                attestationTags.push(['client', clientPubkey])
              }

              const attestationEvent = new NDKEvent(daemon.ndk, {
                kind: 24135,
                content: encryptedAttestation,
                created_at: createdAt || Math.floor(Date.now() / 1000),
                tags: attestationTags
              } as any)
              attestationEvent.uid = uid
              attestationEvent.key = keyField

              await attestationEvent.sign(testSigner)
              const relaySet = NDKRelaySet.fromRelayUrls(daemon.config.nostr.relays, daemon.ndk)
              await attestationEvent.publish(relaySet, DEFAULT_PUBLISH_TIMEOUT_MS)
              checkpointService.broadcast('signer.testing.identity_attested', {
                devicePubkey: clientPubkey.substring(0, 16),
                userPubkey: identityPubkeyHex.substring(0, 16)
              })
            }

            const { publishGenesisEntry } = await import('../lib/keychain-event.js')
            const daemonServiceEntryId = daemon.platformServiceEntryId
            if (!daemonServiceEntryId) {
              throw new Error('Signer daemon has no verified platformServiceEntryId')
            }
            const genesisEntryId = await publishGenesisEntry(
              testSigner,
              identityPubkeyHex,
              daemon.config.nostr.relays,
              daemonServiceEntryId,
              createdAt,
              daemon.ndk,
              isMlDsa ? kemPubkeyHex : undefined,
              isMlDsa ? encPubkeyHex : undefined
            )

            const { publishUsernameEvent } = await import('../lib/username-event.js')
            const usernameFromKeyName = keyName.split('@')[0]
            await publishUsernameEvent(
              testSigner,
              usernameFromKeyName,
              identityPubkeyHex,
              daemon.config.nostr.relays,
              createdAt,
              genesisEntryId,
              daemon.ndk
            )

            await daemon.loadKey(keyName, identitySecretHex, identityAlg)

            log.http(`🧪 Testing: registered key ${keyName} (genesis: ${genesisEntryId})`)
            checkpointService.broadcast('signer.testing.register.completed', { keyName })

            return Response.json({
              success: true,
              keyName,
              pubkey: identityPubkeyHex,
              genesisEntryId,
              clientAuthorized: !!clientPubkey
            }, { status: 201, headers })
          } catch (e: any) {
            if (e.code === 'P2002') return Response.json({ error: 'Key already exists' }, { status: 409, headers })
            logError('http', `Testing register error: ${e.message}`, e)
            if (e.errors) {
              const errEntries = e.errors instanceof Map ? e.errors.entries() : Array.isArray(e.errors) ? e.errors.entries() : Object.entries(e.errors)
              for (const [r, err] of errEntries) {
                logError('http', `Relay ${(r as any)?.url ?? r} rejected: ${(err as any)?.message ?? (err as any)}`)
              }
            }
            return Response.json({ error: e.message }, { status: 500, headers })
          }
        }

        // POST /testing/authorize-client
        if (url.pathname === '/testing/authorize-client' && req.method === 'POST') {
          try {
            const body = await req.json() as any
            const { keyName, clientPubkey, clientEncPubkey, clientKemPubkey, certify, localSigningPubkey, createdAt, parentEntryId } = body
            
            if (!keyName || !clientPubkey) return Response.json({ error: 'keyName and clientPubkey are required' }, { status: 400, headers })

            const { allowMethodsFromKey } = await import('../lib/acl/index.js')
            checkpointService.broadcast('signer.testing.authorize.received', { keyName, clientPubkey })

            const key = await prisma.key.findUnique({ where: { keyName } })
            if (!key) return Response.json({ error: `Key not found: ${keyName}` }, { status: 404, headers })

            await allowMethodsFromKey(
              clientPubkey,
              keyName,
              [
                { method: 'connect' },
                { method: 'sign_event', allowScope: { kind: null } },
                { method: 'nip44_encrypt' },
                { method: 'nip44_decrypt' },
                { method: 'kem_decrypt' },
                { method: 'switch_relays' },
                { method: 'get_public_key' },
                { method: 'ping' }
              ],
              'test-client'
            )

            const targetKemPubkey = clientKemPubkey || (clientEncPubkey && clientEncPubkey.length === 2368 ? clientEncPubkey : undefined)
            if (targetKemPubkey) {
              const clientUid = clientPubkey.length === 2624 ? identityIdFromPublicKey(clientPubkey) : clientPubkey
              await prisma.session.updateMany({
                where: { keyName, clientPubkey: { in: [clientPubkey, clientUid] } },
                data: { clientKemPubkey: targetKemPubkey }
              })
            }

            let delegateEntryId: string | undefined
            if (certify && localSigningPubkey) {
              const { retrieveKey } = await import('../../services/KeyService.js')
              const { publishDelegateEntry } = await import('../lib/keychain-event.js')
              const nsec = await retrieveKey(keyName)
              if (!nsec) throw new Error(`Private key not found for ${keyName}`)
              const userSigner = key.algorithm === 'ml-dsa-44' ? new NDKMlDsaSigner(nsec) : new NDKPrivateKeySigner(nsec)
              const daemonServiceEntryId = daemon.platformServiceEntryId
              if (!daemonServiceEntryId) {
                throw new Error('Signer daemon has no verified platformServiceEntryId')
              }
              delegateEntryId = await publishDelegateEntry(
                userSigner,
                key.pubkey,
                localSigningPubkey,
                daemon.config.nostr.relays,
                daemonServiceEntryId,
                parentEntryId,
                createdAt,
                daemon.ndk
              )
              log.http(`🧪 Testing: published delegate entry ${delegateEntryId} for client ${clientPubkey.slice(0, 16)}... on key ${keyName}`)
            }

            log.http(`🧪 Testing: authorized client ${clientPubkey.slice(0, 16)}... for key ${keyName}`)
            checkpointService.broadcast('signer.testing.authorize.completed', { keyName, clientPubkey })

            return Response.json({
              success: true,
              keyName,
              clientPubkey: clientPubkey.slice(0, 16) + '...',
              delegateEntryId
            }, { status: 200, headers })
          } catch (e: any) {
            logError('http', `Testing authorize-client error:`, e)
            return Response.json({ error: e.message }, { status: 500, headers })
          }
        }

        // POST /testing/revoke-delegate
        if (url.pathname === '/testing/revoke-delegate' && req.method === 'POST') {
          try {
            const body = await req.json() as any
            const { keyName, entryId, createdAt } = body

            if (!keyName) return Response.json({ error: 'keyName is required' }, { status: 400, headers })

            const key = await prisma.key.findUnique({ where: { keyName } })
            if (!key) return Response.json({ error: `Key not found: ${keyName}` }, { status: 404, headers })

            const { retrieveKey } = await import('../../services/KeyService.js')
            const { publishRevokeEntry } = await import('../lib/keychain-event.js')
            const nsec = await retrieveKey(keyName)
            if (!nsec) throw new Error(`Private key not found for ${keyName}`)
            const userSigner = key.algorithm === 'ml-dsa-44' ? new NDKMlDsaSigner(nsec) : new NDKPrivateKeySigner(nsec)
            const daemonServiceEntryId = daemon.platformServiceEntryId
            if (!daemonServiceEntryId) {
              throw new Error('Signer daemon has no verified platformServiceEntryId')
            }

            let targetEntryId = entryId
            if (!targetEntryId) {
              const { identityIdFromPublicKey, delegateEntriesFor } = await import('verity-event-data-module')
              const uid = identityIdFromPublicKey(key.pubkey)
              const eventsSet = await daemon.ndk.fetchEvents({
                kinds: [297 as any],
                authors: [uid]
              })
              const entries: any[] = []
              for (const ev of eventsSet) {
                try {
                  const parsedContent = typeof ev.content === 'string' ? JSON.parse(ev.content) : ev.content
                  const vTag = ev.tags?.find((t: string[]) => t[0] === 'v')
                  entries.push({
                    id: ev.id,
                    uid: (ev as any).uid ?? ev.pubkey,
                    created_at: ev.created_at,
                    kind: ev.kind,
                    variant: vTag?.[1],
                    kid: (ev as any).kid,
                    tags: ev.tags,
                    content: parsedContent
                  })
                } catch { /* ignore */ }
              }
              const delegates = delegateEntriesFor(entries)
              if (delegates.length === 0) {
                return Response.json({ error: `No live delegate entries found for ${keyName}` }, { status: 404, headers })
              }
              targetEntryId = delegates[delegates.length - 1].id
            }

            const revokeEntryId = await publishRevokeEntry(
              userSigner,
              key.pubkey,
              targetEntryId,
              daemon.config.nostr.relays,
              daemonServiceEntryId,
              undefined,
              createdAt,
              daemon.ndk
            )

            log.http(`🧪 Testing: published revoke entry ${revokeEntryId} targeting ${targetEntryId} for key ${keyName}`)

            return Response.json({
              success: true,
              keyName,
              revokeEntryId,
              revokedEntryId: targetEntryId
            }, { status: 200, headers })
          } catch (e: any) {
            logError('http', `Testing revoke-delegate error:`, e)
            return Response.json({ error: e.message }, { status: 500, headers })
          }
        }

        // POST /testing/rotate-transport-kem
        if (url.pathname === '/testing/rotate-transport-kem' && req.method === 'POST') {
          try {
            if (!daemon.transportKemManager) {
              return Response.json({ error: 'Transport KEM manager is not initialized' }, { status: 503, headers })
            }
            const body = (await req.json().catch(() => ({}))) as any
            const { secretKey, windowSeconds } = body
            let newKeypair
            if (secretKey) {
              const { publicKeyFromSecret } = await import('verity-event-data-module')
              const { bytesToHex } = await import('@noble/hashes/utils.js')
              newKeypair = {
                secretKeyHex: secretKey,
                publicKeyHex: bytesToHex(publicKeyFromSecret('ml-kem-768', secretKey))
              }
            }
            daemon.transportKemManager.rotate(newKeypair, windowSeconds ?? 86400)
            const daemonKeyHex = process.env.SIGNER_DAEMON_KEY!
            const daemonSigner = new NDKMlDsaSigner(daemonKeyHex)
            const eventId = await daemon.transportKemManager.publishAnnouncement(
              daemon.ndk,
              daemonSigner,
              daemonKeyHex,
              daemon.config.nostr.relays
            )
            checkpointService.broadcast('signer.testing.transport_kem_rotated', {
              activePubkey: daemon.transportKemManager.activeKey.publicKeyHex,
              overlapPubkey: daemon.transportKemManager.overlapKey?.publicKeyHex ?? null
            })
            return Response.json({
              success: true,
              activePubkey: daemon.transportKemManager.activeKey.publicKeyHex,
              overlapPubkey: daemon.transportKemManager.overlapKey?.publicKeyHex ?? null,
              overlapExpiresAt: daemon.transportKemManager.overlapKey?.expiresAt ?? null,
              eventId
            }, { status: 200, headers })
          } catch (e: any) {
            logError('http', `Rotate transport KEM error: ${e.message}`, e)
            return Response.json({ error: e.message }, { status: 500, headers })
          }
        }

        // POST /testing/rotate-user-kem
        if (url.pathname === '/testing/rotate-user-kem' && req.method === 'POST') {
          try {
            const body = (await req.json()) as any
            const { keyName, newSecretKeyHex, newPublicKeyHex } = body
            if (!keyName) return Response.json({ error: 'keyName is required' }, { status: 400, headers })

            const identityKey = await prisma.key.findFirst({
              where: { keyName, role: 'identity', status: 'ACTIVE' }
            })
            if (!identityKey) return Response.json({ error: `Identity key not found: ${keyName}` }, { status: 404, headers })

            const existingActiveKem = await prisma.key.findFirst({
              where: { parentKeyName: keyName, role: 'kem', status: 'ACTIVE' }
            })
            if (!existingActiveKem) {
              return Response.json({ error: `Active KEM key not found for ${keyName}` }, { status: 404, headers })
            }

            const { storeKey, retrieveKey } = await import('../../services/KeyService.js')

            const retiredAt = new Date()
            await prisma.key.update({
              where: { keyName: existingActiveKem.keyName },
              data: {
                status: 'RETIRED',
                statusAt: retiredAt,
                retiredAt
              }
            })

            let freshSecret = newSecretKeyHex
            let freshPubkey = newPublicKeyHex
            if (!freshSecret || !freshPubkey) {
              const { keygen } = await import('verity-event-data-module')
              const { bytesToHex } = await import('@noble/hashes/utils.js')
              const generated = keygen('ml-kem-768')
              freshSecret = bytesToHex(generated.secretKey)
              freshPubkey = bytesToHex(generated.publicKey)
            }

            const freshKeyName = `${keyName}#kem-${Date.now()}`
            await storeKey(freshKeyName, freshSecret, freshPubkey, 'ml-kem-768', 'kem', keyName)

            const { resolveKeyFamily } = await import('../../services/KeyService.js')
            const updatedFamily = await resolveKeyFamily(keyName)
            if (updatedFamily?.kem) {
              daemon.updateUserKemFamily?.(keyName, updatedFamily.kem)
            }

            const { publishRotateEncEntry } = await import('../lib/keychain-event.js')
            const identitySecretHex = await retrieveKey(keyName)
            if (!identitySecretHex) throw new Error(`Private key not found for identity ${keyName}`)
            const userSigner = identityKey.algorithm === 'ml-dsa-44'
              ? new NDKMlDsaSigner(identitySecretHex)
              : new NDKPrivateKeySigner(identitySecretHex)

            const daemonServiceEntryId = daemon.platformServiceEntryId
            if (!daemonServiceEntryId) {
              throw new Error('Signer daemon has no verified platformServiceEntryId')
            }

            const rotateEntryId = await publishRotateEncEntry(
              userSigner,
              identityKey.pubkey,
              freshPubkey,
              daemon.config.nostr.relays,
              daemonServiceEntryId,
              undefined,
              undefined,
              daemon.ndk
            )

            checkpointService.broadcast('signer.testing.user_kem_rotated', {
              keyName,
              oldPubkey: existingActiveKem.pubkey,
              newPubkey: freshPubkey,
              rotateEntryId
            })

            return Response.json({
              success: true,
              keyName,
              oldPubkey: existingActiveKem.pubkey,
              newPubkey: freshPubkey,
              newPublicKey: freshPubkey,
              rotateEntryId
            }, { status: 200, headers })
          } catch (e: any) {
            logError('http', `Rotate user KEM error: ${e.message}`, e)
            return Response.json({ error: e.message }, { status: 500, headers })
          }
        }

        // POST /testing/keys
        if (url.pathname === '/testing/keys' && req.method === 'POST') {
          try {
            const body = await req.json() as any
            const { keyName, pubkey } = body
            if (!keyName || !pubkey) return Response.json({ error: 'keyName and pubkey are required' }, { status: 400, headers })
            
            const key = await prisma.key.create({ data: { keyName, pubkey } })
            return Response.json({ id: key.id, keyName: key.keyName, pubkey: key.pubkey, createdAt: key.createdAt, updatedAt: key.updatedAt }, { status: 201, headers })
          } catch (e: any) {
             if (e.code === 'P2002') return Response.json({ error: 'Key already exists' }, { status: 409, headers })
             return Response.json({ error: e.message }, { status: 500, headers })
          }
        }

        // GET /testing/keys/:keyName
        if (url.pathname.startsWith('/testing/keys/') && req.method === 'GET') {
          try {
            const keyName = decodeURIComponent(url.pathname.slice('/testing/keys/'.length))
            const key = await prisma.key.findFirst({ where: { keyName, role: 'identity', status: 'ACTIVE' } })
            if (!key) return Response.json({ error: 'Key not found' }, { status: 404, headers })
            return Response.json({ id: key.id, keyName: key.keyName, pubkey: key.pubkey, algorithm: key.algorithm, role: key.role, createdAt: key.createdAt, updatedAt: key.updatedAt }, { status: 200, headers })
          } catch (e: any) {
            return Response.json({ error: e.message }, { status: 500, headers })
          }
        }

        // DELETE /testing/keys/:keyName
        if (url.pathname.startsWith('/testing/keys/') && req.method === 'DELETE') {
          try {
            const keyName = decodeURIComponent(url.pathname.slice('/testing/keys/'.length))
            await prisma.key.deleteMany({ where: { OR: [{ keyName }, { parentKeyName: keyName }] } })
            return Response.json({ success: true }, { status: 200, headers })
          } catch (e: any) {
            return Response.json({ error: e.message }, { status: 500, headers })
          }
        }

        // POST /testing/sign-challenge
        if (url.pathname === '/testing/sign-challenge' && req.method === 'POST') {
          try {
            const body = await req.json() as any
            const { keyName, challenge } = body
            
            const key = await prisma.key.findUnique({ where: { keyName } })
            const { retrieveKey } = await import('../../services/KeyService.js')
            const nsec = await retrieveKey(keyName)
            if (!nsec) return Response.json({ error: 'Key not found' }, { status: 404, headers })

            if (key?.algorithm !== 'ml-dsa-44') {
              return Response.json({ error: 'Classical signing algorithm not supported; ML-DSA-44 required' }, { status: 400, headers })
            }
            const signer = new NDKMlDsaSigner(nsec)
            const user = await signer.user()
            const userPubkeyBytes = Buffer.from(user.pubkey, 'hex')
            const keyField = 'ml-dsa-44:' + userPubkeyBytes.toString('base64')
            const uid = identityIdFromPublicKey(user.pubkey)

            const event = new NDKEvent(daemon.ndk, {
              kind: 1,
              content: challenge,
              created_at: Math.floor(Date.now() / 1000),
              tags: []
            } as any)
            event.uid = uid
            event.key = keyField
            await event.sign(signer)

            return Response.json({ pubkey: user.pubkey, sig: event.sig, verified: true }, { headers })
          } catch (e: any) {
            return Response.json({ error: e.message, verified: false }, { status: 500, headers })
          }
        }

        // POST /testing/corrupt-key
        if (url.pathname === '/testing/corrupt-key' && req.method === 'POST') {
          try {
            const body = (await req.json()) as any
            const { keyName } = body

            if (!keyName) {
              return Response.json({ error: 'keyName is required' }, { status: 400, headers })
            }

            const key = await prisma.key.findUnique({
              where: { keyName }
            })

            if (!key) {
              return Response.json({ error: `Key not found: ${keyName}` }, { status: 404, headers })
            }

            const originalEncrypted = key.encryptedKey
            if (originalEncrypted.length < 32) {
              return Response.json({ error: 'Key ciphertext too short to corrupt' }, { status: 400, headers })
            }

            const corruptedEncrypted = originalEncrypted.slice(0, -32) + '0'.repeat(32)
            await prisma.key.update({
              where: { keyName },
              data: { encryptedKey: corruptedEncrypted }
            })

            log.http(`🧪 Testing: corrupted key row ${keyName}`)
            return Response.json({ success: true, corrupted: true, keyName }, { headers })
          } catch (e: any) {
            return Response.json({ error: e.message }, { status: 500, headers })
          }
        }

        // GET /testing/events/received
        if (url.pathname === '/testing/events/received' && req.method === 'GET') {
          const method = url.searchParams.get('method')
          const requests = await prisma.audit.findMany({
            where: method ? { method } : {},
            orderBy: { createdAt: 'desc' },
            take: 20
          })
          return Response.json(requests, { headers })
        }

        // GET /testing/audit
        if (url.pathname === '/testing/audit' && req.method === 'GET') {
          const correlationId = url.searchParams.get('correlationId')
          const method = url.searchParams.get('method')
          const status = url.searchParams.get('status')
          const type = url.searchParams.get('type')
          const clientPubkey = url.searchParams.get('clientPubkey')

          const { auditService } = await import('../../services/AuditService.js')
          const events = auditService.getEvents({
            ...(correlationId && { correlationId }),
            ...(method && { method }),
            ...(status && { status: status as any }),
            ...(type && { type: type as any }),
            ...(clientPubkey && { clientPubkey })
          })
          return Response.json({ events, count: events.length }, { headers })
        }

        // DELETE /testing/audit
        if (url.pathname === '/testing/audit' && req.method === 'DELETE') {
          const { auditService } = await import('../../services/AuditService.js')
          auditService.clear()
          return Response.json({ cleared: true }, { headers })
        }

        // POST /testing/reset-checkpoints
        if (url.pathname === '/testing/reset-checkpoints' && req.method === 'POST') {
          checkpointService.reset()
          return Response.json({ ok: true }, { headers })
        }

        // GET /testing/health/relay
        if (url.pathname === '/testing/health/relay' && req.method === 'GET') {
          const qsHost = url.searchParams.get('url')
          if (!qsHost) return Response.json({ error: 'url parameter is required' }, { status: 400, headers })
          const decodedUrl = decodeURIComponent(qsHost)
          const relay = daemon.ndk.pool.relays.get(decodedUrl) || daemon.ndk.pool.relays.get(decodedUrl.endsWith('/') ? decodedUrl.slice(0, -1) : decodedUrl + '/')
          if (!relay) return Response.json({ status: 'not-configured', requested: decodedUrl, pool: Array.from(daemon.ndk.pool.relays.keys()) }, { status: 404, headers })
          if (relay.status >= 5) return Response.json({ status: 'listening' }, { headers })
          return Response.json({ status: 'connecting', code: relay.status }, { status: 503, headers })
        }

        // GET /testing/health/db
        if (url.pathname === '/testing/health/db' && req.method === 'GET') {
          try {
            await prisma.key.count()
            return Response.json({ status: 'ready' }, { headers })
          } catch (e: any) {
            return Response.json({ status: 'connecting', error: e.message }, { status: 503, headers })
          }
        }
      }

      return new Response('Not Found', { status: 404, headers })
    }
  })

  log.http(`[SIGNER] HTTP server listening on ${host || '0.0.0.0'}:${port}`)
  return server
}
