import { cookies } from 'next/headers';
import { jwtVerify } from 'jose';

const SECRET = new TextEncoder().encode(process.env.JWT_SECRET ?? '');

export interface Session {
  user: { id: string; role: 'user' | 'admin' };
}

export async function auth(): Promise<Session | null> {
  const token = cookies().get('session')?.value;
  if (!token) return null;
  try {
    const { payload } = await jwtVerify(token, SECRET, { algorithms: ['HS256'] });
    const id = typeof payload.sub === 'string' ? payload.sub : null;
    if (!id) return null;
    return { user: { id, role: payload.role === 'admin' ? 'admin' : 'user' } };
  } catch {
    return null;
  }
}
