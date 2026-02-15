import { randomUUID } from 'crypto'
import { createWriteStream, WriteStream, mkdirSync, existsSync } from 'fs'
import { join } from 'path'

export interface AuditEvent {
  // Identity
  id: string
  correlationId: string
  timestamp: string

  // Operation
  type: 'nip46_request' | 'nip46_response' | 'relay_publish' | 'error'
  method: string

  // Parties
  clientPubkey: string
  userIdentifier?: string
  userPubkey?: string

  // Status
  status: 'received' | 'processing' | 'success' | 'failure'
  error?: {
    code: string
    message: string
    stack?: string
  }

  // Timing
  durationMs?: number

  // Event references
  requestEventId?: string
  responseEventId?: string
  signedEventId?: string

  // Details
  details?: Record<string, any>

  // Relay info
  relayUrl?: string
  relayStatus?: 'published' | 'failed' | 'no_relays'
}

export class AuditService {
  private static instance: AuditService

  // In-memory buffer for testing
  private events: AuditEvent[] = []

  // File stream for current day
  private currentStream?: WriteStream
  private currentDate?: string
  private eventsToday = 0
  private fileIndex = 0

  private readonly baseLogPath: string
  private readonly enabled: boolean

  private constructor() {
    this.baseLogPath = process.env.AUDIT_LOG_PATH || '/app/logs/audit'
    this.enabled = process.env.DISABLE_AUDIT !== 'true'

    if (this.enabled && process.env.NODE_ENV !== 'test') {
      this.ensureLogDirectory()
    }
  }

  static getInstance(): AuditService {
    if (!AuditService.instance) {
      AuditService.instance = new AuditService()
    }
    return AuditService.instance
  }

  private ensureLogDirectory(): void {
    if (!existsSync(this.baseLogPath)) {
      mkdirSync(this.baseLogPath, { recursive: true })
    }
  }

  private getDayDirectory(): string {
    const today = new Date().toISOString().split('T')[0] // YYYY-MM-DD
    return join(this.baseLogPath, today)
  }

  private rotateIfNeeded(): void {
    const today = new Date().toISOString().split('T')[0]

    // New day - rotate
    if (this.currentDate !== today) {
      this.closeCurrentStream()
      this.currentDate = today
      this.eventsToday = 0
      this.fileIndex = 0

      const dayDir = this.getDayDirectory()
      if (!existsSync(dayDir)) {
        mkdirSync(dayDir, { recursive: true })
      }
    }

    // 100 events reached - rotate file
    if (this.eventsToday >= 100) {
      this.closeCurrentStream()
      this.eventsToday = 0
      this.fileIndex++
    }

    // Open new stream if needed
    if (!this.currentStream) {
      const filename = `audit-${String(this.fileIndex).padStart(3, '0')}.jsonl`
      const filepath = join(this.getDayDirectory(), filename)
      this.currentStream = createWriteStream(filepath, { flags: 'a' })
    }
  }

  private closeCurrentStream(): void {
    if (this.currentStream) {
      this.currentStream.end()
      this.currentStream = undefined
    }
  }

  /**
   * Log an audit event
   */
  log(event: Omit<AuditEvent, 'id' | 'timestamp'>): void {
    if (!this.enabled) return

    const auditEvent: AuditEvent = {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      ...event
    }

    // In-memory (for testing)
    this.events.push(auditEvent)
    if (this.events.length > 1000) this.events.shift()

    // Structured console output
    console.log(
      JSON.stringify({
        ...auditEvent,
        _type: 'AUDIT'
      })
    )

    // File persistence (production)
    if (process.env.NODE_ENV !== 'test') {
      this.rotateIfNeeded()
      if (this.currentStream) {
        this.currentStream.write(JSON.stringify(auditEvent) + '\n')
        this.eventsToday++
      }
    }
  }

  /**
   * Create a correlation scope for tracking an operation
   */
  createScope(correlationId: string, method: string) {
    const startTime = Date.now()

    return {
      logReceived: (data: Partial<AuditEvent>) => {
        this.log({
          correlationId,
          type: 'nip46_request',
          method,
          status: 'received',
          clientPubkey: data.clientPubkey || 'unknown',
          ...data
        })
      },

      logResponse: (data: Partial<AuditEvent>) => {
        this.log({
          correlationId,
          type: 'nip46_response',
          method,
          status: 'success',
          durationMs: Date.now() - startTime,
          clientPubkey: data.clientPubkey || 'unknown',
          ...data
        })
      },

      logPublish: (relayUrl: string, success: boolean, eventId?: string) => {
        this.log({
          correlationId,
          type: 'relay_publish',
          method,
          relayUrl,
          relayStatus: success ? 'published' : 'failed',
          status: success ? 'success' : 'failure',
          clientPubkey: 'system',
          responseEventId: eventId
        })
      },

      logError: (error: Error, details?: any) => {
        this.log({
          correlationId,
          type: 'error',
          method,
          status: 'failure',
          durationMs: Date.now() - startTime,
          clientPubkey: details?.clientPubkey || 'unknown',
          error: {
            code: error.name,
            message: error.message,
            stack: error.stack
          },
          details
        })
      }
    }
  }

  /**
   * Get audit events (for testing)
   */
  getEvents(filter?: Partial<AuditEvent>): AuditEvent[] {
    if (!filter) return [...this.events]

    return this.events.filter((event) => Object.entries(filter).every(([key, value]) => event[key as keyof AuditEvent] === value))
  }

  /**
   * Clear audit buffer (for testing)
   */
  clear(): void {
    this.events = []
  }

  /**
   * Cleanup on shutdown
   */
  close(): void {
    this.closeCurrentStream()
  }
}

export const auditService = AuditService.getInstance()

// Cleanup on process exit
process.on('exit', () => auditService.close())
process.on('SIGINT', () => {
  auditService.close()
  process.exit(0)
})
