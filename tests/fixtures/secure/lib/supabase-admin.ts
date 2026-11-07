import 'server-only';

import { createClient } from '@supabase/supabase-js';

/** Service-role client. Guarded by `server-only` so the build fails if a client
 *  component ever imports this module. */
export const supabaseAdmin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!,
  { auth: { persistSession: false } },
);
