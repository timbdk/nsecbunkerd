-- AlterTable
ALTER TABLE "Key" ADD COLUMN "algorithm" TEXT NOT NULL DEFAULT 'secp256k1-nip44';
ALTER TABLE "Key" ADD COLUMN "role" TEXT NOT NULL DEFAULT 'identity';
ALTER TABLE "Key" ADD COLUMN "parentKeyName" TEXT;
ALTER TABLE "Key" ADD COLUMN "retiredAt" DATETIME;

-- CreateIndex
CREATE INDEX "Key_parentKeyName_role_status_idx" ON "Key"("parentKeyName", "role", "status");
