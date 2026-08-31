/**
 * Testing Checkpoint Service — Broadcasts pipeline state transitions
 * to connected WebSocket clients for distributed test tracing.
 *
 * Only active when NODE_ENV=testing. All calls are no-ops otherwise.
 *
 * Uses Bun's native WebSocket server (no external dependencies).
 * Singleton: import { checkpointService } from './CheckpointService.js'
 */

import { log } from '../lib/logger.js'

const TESTING_PORT = parseInt(process.env.VERITY_SIGNER_TESTING_PORT || '9200', 10)

class CheckpointService {
  private readonly clients = new Set<any>()
  private readonly enabled = process.env.NODE_ENV === 'testing'
  private server: ReturnType<typeof Bun.serve> | null = null
  // Ring buffer of recent checkpoints, replayed to each new subscriber so a
  // reconnecting pipeline monitor cannot miss events that fired during the gap.
  // Subscribers pass ?since=<ts> to receive only the events newer than what
  // they already saw, so stale events never replay.
  private readonly recentCheckpoints: { ts: number; payload: string }[] = []
  private readonly maxBuffer = 500

  /**
   * Start the WebSocket server. Call once from Daemon.start().
   */
  start(): void {
    if (!this.enabled) return

    const self = this

    this.server = Bun.serve({
      port: TESTING_PORT,
      fetch(req, server) {
        const url = new URL(req.url)
        if (url.pathname === '/testing/stream') {
          const sinceParam = url.searchParams.get('since')
          const since = sinceParam === null ? undefined : Number.parseInt(sinceParam, 10)
          const upgraded = server.upgrade(req, {
            data: { since: Number.isFinite(since) ? since : undefined }
          })
          if (!upgraded) {
            return new Response('WebSocket upgrade failed', { status: 400 })
          }
          return undefined
        }
        return new Response('Not Found', { status: 404 })
      },
      websocket: {
        open(ws) {
          self.clients.add(ws)
          // Ack first (marks subscription) then replay only the checkpoints
          // the subscriber has not seen yet.
          const since = (ws.data as { since?: number } | undefined)?.since
          const replay = self.recentCheckpoints
            .filter((c) => since === undefined || c.ts > since)
            .map((c) => c.payload)
          ws.send(JSON.stringify({ type: 'ack', buffer: replay }))
          log.daemon(`Stream client connected (${self.clients.size} total)`)
        },
        close(ws) {
          self.clients.delete(ws)
          log.daemon(`Stream client disconnected (${self.clients.size} remaining)`)
        },
        message() {
          // No incoming messages expected
        },
      },
    })

    log.daemon(`Checkpoint stream listening on port ${TESTING_PORT}`)
  }

  /**
   * Stop the WebSocket server and disconnect all clients.
   */
  stop(): void {
    if (this.server) {
      this.clients.clear()
      this.server.stop()
      this.server = null
    }
  }

  /**
   * Broadcast a checkpoint event to all connected testing clients.
   *
   * No correlationId at the signer level — each signer instance is per-worker
   * and isolated, so the test runner matches on step name alone.
   *
   * @param step - Checkpoint step name (e.g. 'signer.event.received')
   * @param data - Optional metadata (method, keyName, pubkey, etc.)
   */
  broadcast(step: string, data?: Record<string, any>): void {
    if (!this.enabled) return

    const payload = JSON.stringify({
      type: 'checkpoint',
      step,
      timestamp: Date.now(),
      service: 'signer',
      data,
    })

    this.recentCheckpoints.push({ ts: Date.now(), payload })
    if (this.recentCheckpoints.length > this.maxBuffer) {
      this.recentCheckpoints.shift()
    }

    for (const client of this.clients) {
      try {
        client.send(payload)
      } catch {
        this.clients.delete(client)
      }
    }

    log.daemon(`Checkpoint Broadcast: ${step} (${this.clients.size} clients)`)
  }
}

/** Singleton instance — safe to import anywhere, no-ops when not testing */
export const checkpointService = new CheckpointService()
