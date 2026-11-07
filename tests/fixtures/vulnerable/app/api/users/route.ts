import { db } from '../../../lib/db';

export async function DELETE(req: Request) {
  const { id } = await req.json();
  const { userId } = await req.json();
  await db.query(`DELETE FROM users WHERE id = ${id} AND owner = ${userId}`);
  return new Response(JSON.stringify({ ok: true }));
}
