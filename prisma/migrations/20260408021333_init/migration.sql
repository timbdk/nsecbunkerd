-- CreateTable
CREATE TABLE "Key" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "keyName" TEXT NOT NULL,
    "pubkey" TEXT NOT NULL,
    "encryptedKey" TEXT NOT NULL,
    "iv" TEXT NOT NULL,
    "authTag" TEXT NOT NULL,
    "backedUpAt" DATETIME,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "statusAt" DATETIME
);

-- CreateTable
CREATE TABLE "Session" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "keyName" TEXT NOT NULL,
    "clientPubkey" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    "revokedAt" DATETIME,
    "lastUsedAt" DATETIME,
    "description" TEXT,
    CONSTRAINT "Session_keyName_fkey" FOREIGN KEY ("keyName") REFERENCES "Key" ("keyName") ON DELETE RESTRICT ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "SigningCondition" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "method" TEXT,
    "kind" INTEGER,
    "allowed" BOOLEAN,
    "sessionId" INTEGER,
    CONSTRAINT "SigningCondition_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "Session" ("id") ON DELETE SET NULL ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "Policy" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "expiresAt" DATETIME,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL
);

-- CreateTable
CREATE TABLE "PolicyRule" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "method" TEXT NOT NULL,
    "kind" INTEGER,
    "maxUsageCount" INTEGER,
    "currentUsageCount" INTEGER NOT NULL DEFAULT 0,
    "policyId" INTEGER,
    CONSTRAINT "PolicyRule_policyId_fkey" FOREIGN KEY ("policyId") REFERENCES "Policy" ("id") ON DELETE SET NULL ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "Audit" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "keyName" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "correlationId" TEXT NOT NULL,
    "clientPubkey" TEXT NOT NULL,
    "method" TEXT NOT NULL,
    "params" TEXT,
    "allowed" BOOLEAN
);

-- CreateTable
CREATE TABLE "_PolicyToSession" (
    "A" INTEGER NOT NULL,
    "B" INTEGER NOT NULL,
    CONSTRAINT "_PolicyToSession_A_fkey" FOREIGN KEY ("A") REFERENCES "Policy" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "_PolicyToSession_B_fkey" FOREIGN KEY ("B") REFERENCES "Session" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateIndex
CREATE UNIQUE INDEX "Key_keyName_key" ON "Key"("keyName");

-- CreateIndex
CREATE UNIQUE INDEX "Session_keyName_clientPubkey_key" ON "Session"("keyName", "clientPubkey");

-- CreateIndex
CREATE UNIQUE INDEX "_PolicyToSession_AB_unique" ON "_PolicyToSession"("A", "B");

-- CreateIndex
CREATE INDEX "_PolicyToSession_B_index" ON "_PolicyToSession"("B");
