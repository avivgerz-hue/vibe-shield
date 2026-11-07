import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export async function findUser(id: string) {
  return prisma.$queryRawUnsafe(`SELECT * FROM users WHERE id = '${id}'`);
}

export async function rawSql(table: string) {
  return prisma.$queryRawUnsafe(`SELECT * FROM ${table}`);
}

export const db = {
  query: (sql: string, values?: unknown[]) => prisma.$executeRawUnsafe(sql, values),
  command: (sql: string, values?: unknown[]) => prisma.$executeRawUnsafe(sql, values),
};
