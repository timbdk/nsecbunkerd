import { checkpointService } from '../../services/CheckpointService.js'
import prisma from '../../db.js'
import { nip19, utils } from 'nostr-tools'
const { bytesToHex } = utils
import { NDKEvent, NDKPrivateKeySigner } from '@nostr-dev-kit/ndk'
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
      headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
      headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization')
      
      if (req.method === 'OPTIONS') {
        return new Response(null, { headers })
      }

      if (url.pathname === '/health' && req.method === 'GET') {
        if (daemon.isReady) {
          return new Response('OK', { status: 200, headers })
        } else {
          return new Response('NOT READY', { status: 503, headers })
        }
      }

      if (isTesting) {
        // GET /testing/keys/:keyName
        const keysMatch = url.pathname.match(/^\/testing\/keys\/([^/]+)$/)
        if (keysMatch && req.method === 'GET') {
          const keyName = keysMatch[1]
          const key = await prisma.key.findUnique({ where: { keyName } })
          if (!key) return Response.json({ error: 'Key not found' }, { status: 404, headers })
          return Response.json({
            keyName: key.keyName,
            pubkey: key.pubkey,
            createdAt: key.createdAt,
            updatedAt: key.updatedAt
          }, { headers })
        }

        // POST /testing/register
        if (url.pathname === '/testing/register' && req.method === 'POST') {
          try {
            const body = await req.json() as any
            const { keyName, nsec, pubkey, clientPubkey, createdAt } = body
            
            if (!keyName || !nsec || !pubkey) {
              return Response.json({ error: 'keyName, nsec and pubkey are required' }, { status: 400, headers })
            }

            const { storeKey } = await import('../../services/KeyService.js')
            const { allowAllRequestsFromKey } = await import('../lib/acl/index.js')

            checkpointService.broadcast('signer.testing.register.received', { keyName, clientPubkey })

            let privateKeyHex: string
            if (nsec.startsWith('nsec1')) {
              const privateKeyBytes = (nip19.decode(nsec).data as unknown) as Uint8Array
              privateKeyHex = bytesToHex(privateKeyBytes)
            } else {
              privateKeyHex = nsec
            }

            await storeKey(keyName, privateKeyHex, pubkey)
            checkpointService.broadcast('signer.testing.key_stored', { keyName })

            if (clientPubkey) {
              await allowAllRequestsFromKey(clientPubkey, keyName, 'connect', undefined, 'test-client')
              await allowAllRequestsFromKey(clientPubkey, keyName, 'sign_event', undefined, 'test-client', { kind: null })
              await allowAllRequestsFromKey(clientPubkey, keyName, 'nip44_encrypt', undefined, 'test-client')
              await allowAllRequestsFromKey(clientPubkey, keyName, 'nip44_decrypt', undefined, 'test-client')
              await allowAllRequestsFromKey(clientPubkey, keyName, 'switch_relays', undefined, 'test-client')
              await allowAllRequestsFromKey(clientPubkey, keyName, 'get_public_key', undefined, 'test-client')
              await allowAllRequestsFromKey(clientPubkey, keyName, 'ping', undefined, 'test-client')
              log.http(`🧪 Testing: authorized client ${clientPubkey.slice(0, 16)}... for key ${keyName}`)
              checkpointService.broadcast('signer.testing.client_authorized', { keyName, clientPubkey })
            }

            const { publishUsernameEvent } = await import('../lib/username-event.js')
            const usernameFromKeyName = keyName.split('@')[0]
            const testSigner = new NDKPrivateKeySigner(privateKeyHex)
            await publishUsernameEvent(testSigner, usernameFromKeyName, pubkey, daemon.config.nostr.relays, createdAt)

            daemon.loadNsec(keyName, privateKeyHex)

            log.http(`🧪 Testing: registered key ${keyName}`)
            checkpointService.broadcast('signer.testing.register.completed', { keyName })

            return Response.json({ success: true, keyName, pubkey, clientAuthorized: !!clientPubkey }, { status: 201, headers })
          } catch (e: any) {
            if (e.code === 'P2002') return Response.json({ error: 'Key already exists' }, { status: 409, headers })
            logError('http', `Testing register error:`, e)
            return Response.json({ error: e.message }, { status: 500, headers })
          }
        }

        // POST /testing/authorize-client
        if (url.pathname === '/testing/authorize-client' && req.method === 'POST') {
          try {
            const body = await req.json() as any
            const { keyName, clientPubkey } = body
            
            if (!keyName || !clientPubkey) return Response.json({ error: 'keyName and clientPubkey are required' }, { status: 400, headers })

            const { allowAllRequestsFromKey } = await import('../lib/acl/index.js')
            checkpointService.broadcast('signer.testing.authorize.received', { keyName, clientPubkey })

            const key = await prisma.key.findUnique({ where: { keyName } })
            if (!key) return Response.json({ error: `Key not found: ${keyName}` }, { status: 404, headers })

            await allowAllRequestsFromKey(clientPubkey, keyName, 'connect', undefined, 'test-client')
            await allowAllRequestsFromKey(clientPubkey, keyName, 'sign_event', undefined, 'test-client', { kind: null })
            await allowAllRequestsFromKey(clientPubkey, keyName, 'nip44_encrypt', undefined, 'test-client')
            await allowAllRequestsFromKey(clientPubkey, keyName, 'nip44_decrypt', undefined, 'test-client')
            await allowAllRequestsFromKey(clientPubkey, keyName, 'switch_relays', undefined, 'test-client')
            await allowAllRequestsFromKey(clientPubkey, keyName, 'get_public_key', undefined, 'test-client')
            await allowAllRequestsFromKey(clientPubkey, keyName, 'ping', undefined, 'test-client')

            log.http(`🧪 Testing: authorized client ${clientPubkey.slice(0, 16)}... for key ${keyName}`)
            checkpointService.broadcast('signer.testing.authorize.completed', { keyName, clientPubkey })

            return Response.json({ success: true, keyName, clientPubkey: clientPubkey.slice(0, 16) + '...' }, { status: 200, headers })
          } catch (e: any) {
            logError('http', `Testing authorize-client error:`, e)
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

        // POST /testing/sign-challenge
        if (url.pathname === '/testing/sign-challenge' && req.method === 'POST') {
          try {
            const body = await req.json() as any
            const { keyName, challenge } = body
            
            const { retrieveKey } = await import('../../services/KeyService.js')
            const nsec = await retrieveKey(keyName)
            if (!nsec) return Response.json({ error: 'Key not found' }, { status: 404, headers })

            const signer = new NDKPrivateKeySigner(nsec)
            const user = await signer.user()
            const event = new NDKEvent(daemon.ndk, {
              kind: 1,
              content: challenge,
              created_at: Math.floor(Date.now() / 1000),
              tags: []
            } as any)
            await event.sign(signer)

            return Response.json({ pubkey: user.pubkey, sig: event.sig, verified: true }, { headers })
          } catch (e: any) {
            return Response.json({ error: e.message, verified: false }, { status: 500, headers })
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
