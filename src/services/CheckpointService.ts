/**
 * Testing Checkpoint Service — Broadcasts pipeline state transitions
 * to connected WebSocket clients for distributed test tracing.
 *
 * Only active when NODE_ENV=testing. All calls are no-ops otherwise.
 *
 * Uses Bun's native WebSocket server (no external dependencies).
 * Singleton: import { checkpointService } from './CheckpointService.js'
 */

const TESTING_PORT = parseInt(process.env.VERITY_SIGNER_TESTING_PORT || '9200', 10)

class CheckpointService {
  private readonly clients = new Set<any>()
  private readonly enabled = process.env.NODE_ENV === 'testing'
  private server: ReturnType<typeof Bun.serve> | null = null

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
          const upgraded = server.upgrade(req)
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
          console.log(`[testing] Stream client connected (${self.clients.size} total)`)
        },
        close(ws) {
          self.clients.delete(ws)
          console.log(`[testing] Stream client disconnected (${self.clients.size} remaining)`)
        },
        message() {
          // No incoming messages expected
        },
      },
    })

    console.log(`[testing] Checkpoint stream listening on port ${TESTING_PORT}`)
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
    if (!this.enabled || this.clients.size === 0) return

    const payload = JSON.stringify({
      type: 'checkpoint',
      step,
      timestamp: Date.now(),
      service: 'signer',
      data,
    })

    for (const client of this.clients) {
      try {
        client.send(payload)
      } catch {
        this.clients.delete(client)
      }
    }

    console.log(`[testing] Broadcast: ${step} (${this.clients.size} clients)`)
  }
}

/** Singleton instance — safe to import anywhere, no-ops when not testing */
export const checkpointService = new CheckpointService()
