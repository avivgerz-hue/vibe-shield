import { auth } from '../../../lib/auth';
import { db } from '../../../lib/db';

export async function DELETE(req: Request) {
  const session = await auth();
  if (!session?.user) {
    return new Response('Unauthorized', { status: 401 });
  }
  const { id } = (await req.json()) as { id: string };
  await db.user.delete({ where: { id, userId: session.user.id } });
  return new Response(JSON.stringify({ ok: true }), { status: 200 });
}
