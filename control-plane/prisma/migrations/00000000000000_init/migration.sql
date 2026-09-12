-- ServerOS control plane — initial migration.
--
-- HAND-WRITTEN. `prisma migrate dev` could not be run in the environment this
-- was authored in (no registry access, so no prisma CLI). It is written to
-- match what Prisma 7 emits for prisma/schema.prisma: `@default(uuid())` is
-- generated client-side, so no column here carries a database-level UUID
-- default; `DateTime` maps to TIMESTAMP(3); `Json` maps to JSONB.
--
-- Before trusting it, run:
--   npx prisma migrate diff \
--     --from-migrations prisma/migrations \
--     --to-schema-datamodel prisma/schema.prisma \
--     --shadow-database-url "$SHADOW_DATABASE_URL" \
--     --exit-code
-- A zero exit code means schema and migration agree.

-- CreateEnum
CREATE TYPE "ServerStatus" AS ENUM ('PENDING', 'CONNECTED', 'DEGRADED', 'OFFLINE', 'UNREACHABLE');

-- CreateEnum
CREATE TYPE "ActivityResult" AS ENUM ('SUCCEEDED', 'FAILED');

-- CreateEnum
CREATE TYPE "AuditOutcome" AS ENUM ('SUCCEEDED', 'FAILED', 'DENIED');

-- CreateTable
CREATE TABLE "User" (
    "id" UUID NOT NULL,
    "email" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "lastLoginAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Session" (
    "id" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "familyId" UUID NOT NULL,
    "refreshTokenHash" TEXT NOT NULL,
    "issuedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "rotatedAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),
    "revokedReason" TEXT,
    "userAgent" TEXT,
    "ip" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Session_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ApiKey" (
    "id" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "prefix" TEXT NOT NULL,
    "keyHash" TEXT NOT NULL,
    "scopes" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "lastUsedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ApiKey_pkey" PRIMARY KEY ("id")
);

-- CreateTable
-- NOTE: no credential column here, by design. See the comment on `model Server`
-- in prisma/schema.prisma before adding one.
CREATE TABLE "Server" (
    "id" UUID NOT NULL,
    "ownerId" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "hostname" TEXT NOT NULL,
    "sshPort" INTEGER NOT NULL DEFAULT 22,
    "sshUsername" TEXT NOT NULL,
    "os" TEXT,
    "arch" TEXT,
    "status" "ServerStatus" NOT NULL DEFAULT 'PENDING',
    "agentVersion" TEXT,
    "agentPort" INTEGER NOT NULL DEFAULT 9443,
    "lastSeenAt" TIMESTAMP(3),
    "hostKeyFingerprint" TEXT,
    "tags" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Server_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ServerEnrollment" (
    "id" UUID NOT NULL,
    "serverId" UUID NOT NULL,
    "codeHash" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "consumedAt" TIMESTAMP(3),
    "createdByIp" TEXT,
    "consumedByIp" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ServerEnrollment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Project" (
    "id" UUID NOT NULL,
    "serverId" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "composeProject" TEXT,
    "workingDir" TEXT,
    "description" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Project_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Activity" (
    "id" UUID NOT NULL,
    "serverId" UUID,
    "userId" UUID,
    "kind" TEXT NOT NULL,
    "resourceType" TEXT NOT NULL,
    "resourceId" TEXT,
    "summary" TEXT NOT NULL,
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "result" "ActivityResult" NOT NULL DEFAULT 'SUCCEEDED',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Activity_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuditLog" (
    "id" UUID NOT NULL,
    "actor" TEXT NOT NULL,
    "actorType" TEXT NOT NULL DEFAULT 'user',
    "action" TEXT NOT NULL,
    "targetType" TEXT,
    "targetId" TEXT,
    "ip" TEXT,
    "userAgent" TEXT,
    "outcome" "AuditOutcome" NOT NULL,
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuditLog_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE INDEX "User_createdAt_idx" ON "User"("createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "Session_refreshTokenHash_key" ON "Session"("refreshTokenHash");

-- CreateIndex
CREATE INDEX "Session_userId_idx" ON "Session"("userId");

-- CreateIndex
CREATE INDEX "Session_familyId_idx" ON "Session"("familyId");

-- CreateIndex
CREATE INDEX "Session_expiresAt_idx" ON "Session"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "ApiKey_keyHash_key" ON "ApiKey"("keyHash");

-- CreateIndex
CREATE INDEX "ApiKey_userId_idx" ON "ApiKey"("userId");

-- CreateIndex
CREATE INDEX "ApiKey_expiresAt_idx" ON "ApiKey"("expiresAt");

-- CreateIndex
CREATE INDEX "Server_ownerId_idx" ON "Server"("ownerId");

-- CreateIndex
CREATE INDEX "Server_status_idx" ON "Server"("status");

-- CreateIndex
CREATE INDEX "Server_lastSeenAt_idx" ON "Server"("lastSeenAt");

-- CreateIndex
CREATE UNIQUE INDEX "Server_ownerId_name_key" ON "Server"("ownerId", "name");

-- CreateIndex
CREATE UNIQUE INDEX "ServerEnrollment_codeHash_key" ON "ServerEnrollment"("codeHash");

-- CreateIndex
CREATE INDEX "ServerEnrollment_serverId_idx" ON "ServerEnrollment"("serverId");

-- CreateIndex
CREATE INDEX "ServerEnrollment_expiresAt_idx" ON "ServerEnrollment"("expiresAt");

-- CreateIndex
CREATE INDEX "Project_serverId_idx" ON "Project"("serverId");

-- CreateIndex
CREATE UNIQUE INDEX "Project_serverId_name_key" ON "Project"("serverId", "name");

-- CreateIndex
CREATE INDEX "Activity_serverId_idx" ON "Activity"("serverId");

-- CreateIndex
CREATE INDEX "Activity_userId_idx" ON "Activity"("userId");

-- CreateIndex
CREATE INDEX "Activity_createdAt_idx" ON "Activity"("createdAt");

-- CreateIndex
CREATE INDEX "Activity_serverId_createdAt_idx" ON "Activity"("serverId", "createdAt");

-- CreateIndex
CREATE INDEX "AuditLog_actor_idx" ON "AuditLog"("actor");

-- CreateIndex
CREATE INDEX "AuditLog_action_idx" ON "AuditLog"("action");

-- CreateIndex
CREATE INDEX "AuditLog_targetType_targetId_idx" ON "AuditLog"("targetType", "targetId");

-- CreateIndex
CREATE INDEX "AuditLog_createdAt_idx" ON "AuditLog"("createdAt");

-- AddForeignKey
ALTER TABLE "Session" ADD CONSTRAINT "Session_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ApiKey" ADD CONSTRAINT "ApiKey_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Server" ADD CONSTRAINT "Server_ownerId_fkey" FOREIGN KEY ("ownerId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ServerEnrollment" ADD CONSTRAINT "ServerEnrollment_serverId_fkey" FOREIGN KEY ("serverId") REFERENCES "Server"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Project" ADD CONSTRAINT "Project_serverId_fkey" FOREIGN KEY ("serverId") REFERENCES "Server"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Activity" ADD CONSTRAINT "Activity_serverId_fkey" FOREIGN KEY ("serverId") REFERENCES "Server"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Activity" ADD CONSTRAINT "Activity_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
