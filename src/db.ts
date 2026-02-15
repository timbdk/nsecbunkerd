import { PrismaClient } from '@prisma/client'

// Only enable verbose query logging in testing/development
const logLevel =
  process.env.NODE_ENV === 'testing' || process.env.NODE_ENV === 'development'
    ? (['query', 'info', 'warn', 'error'] as const)
    : (['warn', 'error'] as const)

const prisma = new PrismaClient({
  log: [...logLevel]
})

export default prisma
