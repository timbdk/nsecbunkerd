-- AlterTable: Add encrypted key columns
ALTER TABLE "Key" ADD COLUMN "encryptedKey" TEXT;
ALTER TABLE "Key" ADD COLUMN "iv" TEXT;
ALTER TABLE "Key" ADD COLUMN "authTag" TEXT;
ALTER TABLE "Key" ADD COLUMN "backedUpAt" DATETIME;
