-- DropIndex
DROP INDEX "users_id_key";

-- CreateTable
CREATE TABLE "profiles" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "avatar" TEXT,
    "age" INTEGER,
    "city" TEXT,
    "nationality" TEXT,

    CONSTRAINT "profiles_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "profiles_userId_key" ON "profiles"("userId");

-- AddForeignKey
ALTER TABLE "profiles" ADD CONSTRAINT "profiles_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
