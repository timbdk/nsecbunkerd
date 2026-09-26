-- AlterTable
ALTER TABLE "Session" RENAME COLUMN "clientEncPubkey" TO "clientKemPubkey";
UPDATE "Session" SET "clientKemPubkey" = NULL WHERE length("clientKemPubkey") != 2368;
