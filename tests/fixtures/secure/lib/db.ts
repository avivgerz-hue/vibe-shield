import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export async function findUser(id: string) {
  return prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`;
}

export const db = prisma;
