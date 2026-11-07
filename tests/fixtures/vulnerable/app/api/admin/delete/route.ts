import { auth } from '../../../lib/auth';
import { db } from '../../../lib/db';

export async function POST(req: Request) {
  const session = await auth();
  if (!session) {
    return new Response('Unauthorized', { status: 401 });
  }
  const body = await req.json();
  await db.command('DELETE FROM accounts WHERE id = $1', [body.id]);
  return new Response(JSON.stringify({ ok: true }));
}
