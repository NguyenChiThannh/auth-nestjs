/*
  Warnings:

  - You are about to drop the column `hash` on the `users` table. All the data in the column will be lost.
  - You are about to drop the column `hashedRt` on the `users` table. All the data in the column will be lost.
  - Added the required column `hashPassword` to the `users` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "users" DROP COLUMN "hash",
DROP COLUMN "hashedRt",
ADD COLUMN     "hashPassword" TEXT NOT NULL,
ADD COLUMN     "hashedRefreshToken" TEXT;
