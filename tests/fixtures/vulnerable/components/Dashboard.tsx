'use client';

import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!,
);

export function Dashboard({ html }: { html: string }) {
  const key = process.env.STRIPE_SECRET_KEY;
  return (
    <div>
      <span>{key}</span>
      <div dangerouslySetInnerHTML={{ __html: html }} />
      <button onClick={() => supabase.from('users').delete().eq('id', 'x')}>delete</button>
    </div>
  );
}
