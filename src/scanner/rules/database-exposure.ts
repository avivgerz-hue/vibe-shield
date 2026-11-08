/**
 * vibe-shield :: database-exposure rules
 * --------------------------------------
 * Supabase + Postgres is where AI-generated code gets *quietly* dangerous. The
 * `CREATE TABLE` an agent writes is perfect; the `ALTER TABLE ... ENABLE ROW
 * LEVEL SECURITY` that should follow it simply never gets written, and with the
 * anon key in every browser the table is world-readable through PostgREST.
 *
 * The RLS rules live here rather than in a linter because the mistake spans
 * files: a table created in migration #1 and secured in migration #7 is fine,
 * and only a project-wide index can tell the difference. `detectProject()`
 * builds that index (`ProjectContext.sqlTables`).
 */

import { UNTRUSTED_SOURCE_REGEX } from '../lexicon';
import { balancedBlock, looksDynamic } from '../text';
import { defineRule, regexHits } from './helpers';
import { CWES, LOGIC_SKIP_FLAGS, isBrowserFile } from './shared';
import type { FileContext, Rule, RuleHit, SqlTableInfo } from '../types';

const SQL_LANGUAGES = ['sql', 'prisma'] as const;
const APP_EXTENSIONS = ['ts', 'tsx', 'js', 'jsx', 'mts', 'mjs', 'cts', 'cjs', 'py', 'rb', 'php', 'go'];

const SUPABASE_SCHEMA_REGEX = /\b(?:public\.|supabase|postgrest|anon|authenticated)\b/i;

/** The build-time guard that keeps a module out of the client bundle. */
const SERVER_ONLY_GUARD_REGEX = /import\s+['"]server-only['"]|\brequire\(\s*['"]server-only['"]\s*\)/;

/** Does the project speak PostgREST (i.e. are tables reachable from a browser)? */
const isExposedBackend = (ctx: FileContext): boolean =>
  ctx.project.hasSupabase || SUPABASE_SCHEMA_REGEX.test(ctx.relativePath) || /supabase/i.test(ctx.relativePath);

/** True when a policy's `USING` clause constrains the row to the caller. */
const policyScopesCaller = (policySql: string): boolean =>
  /\bauth\s*\.\s*(?:uid|jwt|role)\s*\(|\bcurrent_user\b|\bcurrent_setting\s*\(|\bcurrent_role\b|\bsession_user\b/i.test(
    policySql,
  );

const PERMISSIVE_USING_REGEX =
  /\bUSING\s*\(\s*(?:true|1\s*=\s*1|'1'\s*=\s*'1')\s*\)|\bWITH\s+CHECK\s*\(\s*(?:true|1\s*=\s*1)\s*\)/i;

/** A quoted or bare SQL identifier: `"allow all"`, `'weird name'`, `public.accounts`. */
const SQL_NAME = '(?:"[^"]+"|\'[^\']+\'|[^\\s;]+)';

/** Extract every `CREATE POLICY ... ;` statement with its targets. */
function policiesIn(source: string): Array<{ name: string; table: string; body: string; offset: number }> {
  const out: Array<{ name: string; table: string; body: string; offset: number }> = [];
  const policyRegex = new RegExp(
    'CREATE\\s+POLICY\\s+(' + SQL_NAME + ')\\s+ON\\s+(' + SQL_NAME + ')\\s+([\\s\\S]{0,1200}?);',
    'gi',
  );
  for (const match of source.matchAll(policyRegex)) {
    out.push({
      name: match[1] ?? '',
      table: match[2] ?? '',
      body: match[3] ?? '',
      offset: match.index,
    });
  }
  return out;
}

/** VSB-DB-001 - table created without RLS anywhere in the project. */
const tableWithoutRls: Rule = defineRule({
  id: 'VSB-DB-001',
  slug: 'table-without-rls',
  title: 'Table created without Row Level Security enabled',
  category: 'database-exposure',
  severity: 'high',
  confidence: 'high',
  cwe: CWES.rlsDisabled,
  description:
    'In Postgres, RLS is opt-in per table. A table without it is readable and writable by anyone holding the anon key — which, with Supabase, is shipped to every browser. Nothing else in this report matters if the data is publicly addressable.',
  insecureExample: 'create table public.accounts (\n  id uuid primary key,\n  balance numeric\n);',
  secureExample: 'create table public.accounts (...);\nalter table public.accounts enable row level security;',
  remediation: [
    'Add `alter table public.<table> enable row level security;` to the migration that creates the table (never a later one).',
    'Add a policy that scopes rows to the caller, e.g. `using (auth.uid() = user_id)` for each of select/insert/update/delete.',
    'Use the service-role key only in server code, and only where bypassing RLS is genuinely required.',
    'Run `npx github:avivgerz-hue/vibe-shield scan` again — the table should disappear from this report even if no policy was added yet (deny-all is safe).',
  ],
  references: [
    'https://supabase.com/docs/guides/database/postgres/row-level-security',
    'https://www.postgresql.org/docs/current/ddl-rowsecurity.html',
    'https://cwe.mitre.org/data/definitions/284.html',
  ],
  languages: [...SQL_LANGUAGES],
  skipFlags: [...LOGIC_SKIP_FLAGS],
  detect(ctx) {
    const project = ctx.project;
    if (!project.sqlTables.length) return [];
    const createdHere = new Set(
      project.sqlTables.filter((table) => table.file === ctx.relativePath).map((table) => table.name.toLowerCase()),
    );
    const hits: RuleHit[] = [];
    const seen = new Set<string>();
    for (const match of ctx.code.matchAll(/\bCREATE\s+(?:TEMP(?:ORARY)?\s+|UNLOGGED\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([`"[\w.${}\-]+(?:\s*\.\s*[`"[\w.${}\-]+)?)/gi)) {
      const raw = (match[1] ?? '').replace(/["'`[\]]/g, '').replace(/\s+/g, '');
      const name = raw.includes('.') ? (raw.split('.').pop() ?? raw) : raw;
      const key = name.toLowerCase();
      if (!name || seen.has(key)) continue;
      if (/^(?:auth|extensions|pg_catalog|information_schema|storage|realtime|graphql|vault|net|supabase_migrations|_)/i.test(raw)) continue;
      if (/\bCREATE\s+(?:TEMP|TEMPORARY|UNLOGGED)\s+TABLE/i.test(match[0])) continue;
      const record: SqlTableInfo | undefined = project.sqlTables.find((table) => table.name.toLowerCase() === key);
      if (!record) continue;
      if (record.internal) continue;
      if (record.rlsEnabled) continue;
      // If the table is not even created in this file, another migration owns the finding.
      if (createdHere.size > 0 && !createdHere.has(key)) continue;
      seen.add(key);
      hits.push({
        offset: match.index,
        matched: `create table ${raw}`,
        severity: isExposedBackend(ctx) ? 'critical' : 'high',
        confidence: record.policies.length > 0 ? 'high' : 'medium',
        message: `\`${raw}\` has Row Level Security disabled project-wide${
          record.grantedToPublic ? ' and is granted to anon/authenticated' : ''
        }.`,
        data: { table: raw },
      });
    }
    return hits;
  },
  remediate(_ctx, hit) {
    const table = String(hit.data?.table ?? 'public.<table>');
    return [
      `Add \`alter table ${table} enable row level security;\` immediately after the CREATE TABLE statement.`,
      `Create explicit policies for each operation you need, e.g. \`create policy "${table}_owner_select" on ${table} for select using (auth.uid() = user_id);\``,
      'Repeat for insert / update / delete. No policy means no access, which is a safe default — add them deliberately.',
      'Rotate the anon key only if you have evidence it was abused; enabling RLS is what closes the hole.',
    ];
  },
});

/** VSB-DB-002 - permissive policy that allows everyone. */
const permissivePolicy: Rule = defineRule({
  id: 'VSB-DB-002',
  slug: 'permissive-rls-policy',
  title: 'RLS policy allows every row (`USING (true)`)',
  category: 'database-exposure',
  severity: 'critical',
  confidence: 'high',
  cwe: CWES.permissiveAcl,
  description:
    'A policy of `USING (true)` combined with `FOR ALL` or `FOR SELECT` is strictly worse than no policy at all: RLS is now "enabled", the security review box is ticked, and every row is still public. This is the exact shape an agent produces when asked to "fix the RLS warning".',
  insecureExample: 'create policy "allow all" on accounts for all using (true);',
  secureExample: 'create policy "own rows" on accounts for all using (auth.uid() = user_id);',
  remediation: [
    'Replace `using (true)` with a predicate that ties the row to the caller, e.g. `using (auth.uid() = user_id)`.',
    'Split `FOR ALL` into per-operation policies so read and write rules can differ.',
    'For genuinely public tables (feature flags, published posts) restrict the policy to `FOR SELECT` and keep writes closed.',
  ],
  references: [
    'https://supabase.com/docs/guides/database/postgres/row-level-security#policies',
    'https://cwe.mitre.org/data/definitions/732.html',
  ],
  languages: [...SQL_LANGUAGES],
  skipFlags: [...LOGIC_SKIP_FLAGS],
  detect(ctx) {
    const hits: RuleHit[] = [];
    for (const policy of policiesIn(ctx.code)) {
      if (!PERMISSIVE_USING_REGEX.test(policy.body)) continue;
      hits.push({
        offset: policy.offset,
        matched: `policy ${policy.name} on ${policy.table}`,
        message: `Policy \`${policy.name}\` on \`${policy.table}\` uses a constant predicate, so every row matches.`,
        data: { table: policy.table, policy: policy.name },
      });
    }
    return hits;
  },
});

/** VSB-DB-003 - anon/authenticated policy with no caller scoping. */
const unscopedPolicy: Rule = defineRule({
  id: 'VSB-DB-003',
  slug: 'unscoped-rls-policy',
  title: 'Policy for anon/authenticated users does not scope rows to the caller',
  category: 'database-exposure',
  severity: 'high',
  confidence: 'medium',
  cwe: CWES.idor,
  description:
    'A policy granted to `anon` or `authenticated` that never references `auth.uid()`, `auth.jwt()` or a session setting applies to every row for every user — the classic "RLS is on but nothing is filtered" bug.',
  insecureExample: 'create policy "read accounts" on accounts for select to authenticated;',
  secureExample: 'create policy "read own accounts" on accounts for select to authenticated using (auth.uid() = user_id);',
  remediation: [
    'Add a `USING` (and for writes, a `WITH CHECK`) clause that compares the row to the caller: `auth.uid() = user_id`.',
    'Keep `to authenticated` — dropping it makes the policy apply to `anon` as well.',
    'For admin-only tables, gate writes on `auth.jwt() -> \'app_metadata\' ->> \'role\' = \'admin\'`.',
  ],
  references: [
    'https://supabase.com/docs/guides/database/postgres/row-level-security',
    'https://cwe.mitre.org/data/definitions/639.html',
  ],
  languages: [...SQL_LANGUAGES],
  skipFlags: [...LOGIC_SKIP_FLAGS],
  detect(ctx) {
    const hits: RuleHit[] = [];
    for (const policy of policiesIn(ctx.code)) {
      if (!/\bTO\s+(?:anon|authenticated|public|app_user|web_anon)\b/i.test(policy.body)) continue;
      if (policyScopesCaller(policy.body)) continue;
      if (PERMISSIVE_USING_REGEX.test(policy.body)) continue; // reported by VSB-DB-002
      hits.push({
        offset: policy.offset,
        matched: `policy ${policy.name} on ${policy.table}`,
        message: `Policy \`${policy.name}\` targets \`anon\`/\`authenticated\` but never scopes rows to the caller.`,
        data: { table: policy.table, policy: policy.name },
      });
    }
    return hits;
  },
});

/** VSB-DB-004 - GRANT to anon/authenticated/public. */
const publicGrant: Rule = defineRule({
  id: 'VSB-DB-004',
  slug: 'grant-to-anon-role',
  title: 'Table privileges granted to anon / authenticated / public',
  category: 'database-exposure',
  severity: 'high',
  confidence: 'high',
  cwe: CWES.permissiveAcl,
  description:
    '`GRANT ALL ON ... TO anon` hands the anonymous PostgREST role full DDL-free access to the table. With RLS off, or with a permissive policy, that is a public write API.',
  insecureExample: 'grant all on public.accounts to anon;',
  secureExample: 'grant select on public.accounts to authenticated; -- RLS still filters rows',
  remediation: [
    'Grant the minimum privilege to the minimum role: `select` to `authenticated`, never `all` to `anon`.',
    'Ensure RLS is enabled on every granted table — a grant without RLS is a public endpoint.',
    'Revoke inherited access: `revoke all on public.<table> from anon;`.',
  ],
  references: [
    'https://supabase.com/docs/guides/database/postgres/row-level-security',
    'https://cwe.mitre.org/data/definitions/732.html',
  ],
  languages: [...SQL_LANGUAGES],
  skipFlags: [...LOGIC_SKIP_FLAGS],
  detect(ctx) {
    return regexHits(
      ctx.code,
      /\bGRANT\s+([\w\s,]+?)\s+ON\s+(?:TABLE\s+|ALL\s+TABLES\s+IN\s+SCHEMA\s+)?([`"[\w.$*,\s]+?)\s+TO\s+([`"[\w\s,]+?)\s*;/gi,
      (match) => {
        const privileges = (match[1] ?? '').toUpperCase().replace(/\s+/g, ' ').trim();
        const granteeList = (match[3] ?? '')
          .toLowerCase()
          .split(',')
          .map((entry) => entry.trim().replace(/["`]/g, ''))
          .filter(Boolean);
        const grantees = granteeList.join(', ');
        if (!granteeList.some((role) => /^(?:anon|authenticated|public|web_anon|app_user)$/.test(role))) return null;
        // `authenticated` is the role *after* a successful login: granting it
        // write access is the documented Supabase pattern, and RLS still scopes
        // every row. Only `anon`/`public` writes are unconditionally dangerous.
        const publicRoles = granteeList.filter((role) => /^(?:anon|public|web_anon)$/.test(role));
        if (!publicRoles.length) return null;
        const critical = privileges === 'ALL' || /INSERT|UPDATE|DELETE|TRUNCATE/.test(privileges);
        return {
          matched: `grant ${privileges.toLowerCase()} on ${(match[2] ?? '').trim()} to ${grantees.trim()}`,
          severity: critical ? 'critical' : 'high',
          message: `\`${privileges}\` is granted to \`${grantees}\`, which includes unauthenticated callers.`,
          data: { privileges, grantees: grantees.trim() },
        };
      },
    );
  },
});

/** VSB-DB-005 - RLS explicitly disabled / bypassed. */
const rlsDisabled: Rule = defineRule({
  id: 'VSB-DB-005',
  slug: 'rls-disabled-or-bypassed',
  title: 'Row Level Security is disabled, dropped or bypassed',
  category: 'database-exposure',
  severity: 'high',
  confidence: 'high',
  cwe: CWES.rlsDisabled,
  description:
    '`DISABLE ROW LEVEL SECURITY`, `DROP POLICY` and `ALTER ROLE ... BYPASSRLS` all remove the database\'s last line of defence. An agent reaching for these typically does so to make a failing query "work".',
  insecureExample: 'alter table public.accounts disable row level security;',
  secureExample: 'alter table public.accounts enable row level security;',
  remediation: [
    'Remove the statement. If a query was failing because of RLS, fix the policy — not the protection.',
    'Use the service-role key in server code for the privileged path instead of disabling RLS for everyone.',
    'If a policy was dropped by mistake, restore it in a new migration; do not rewrite history.',
  ],
  references: [
    'https://www.postgresql.org/docs/current/sql-altertable.html',
    'https://cwe.mitre.org/data/definitions/284.html',
  ],
  languages: [...SQL_LANGUAGES],
  skipFlags: [...LOGIC_SKIP_FLAGS],
  detect(ctx) {
    const hits: RuleHit[] = [];
    for (const match of ctx.code.matchAll(/\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?([`"[\w.]+)\s+DISABLE\s+ROW\s+LEVEL\s+SECURITY/gi)) {
      hits.push({
        offset: match.index,
        matched: match[0],
        severity: 'critical',
        message: `Row Level Security is disabled on \`${match[1]}\`.`,
        data: { table: match[1] },
      });
    }
    for (const match of ctx.code.matchAll(/\b(?:ALTER\s+ROLE|ALTER\s+USER)\s+([`"[\w]+)\s+(?:WITH\s+)?BYPASSRLS/gi)) {
      hits.push({
        offset: match.index,
        matched: match[0],
        severity: 'critical',
        message: `Role \`${match[1]}\` is granted BYPASSRLS — RLS no longer applies to it.`,
        data: { role: match[1] },
      });
    }
    for (const match of ctx.code.matchAll(/\bDROP\s+POLICY\s+(?:IF\s+EXISTS\s+)?([^\s;]+)\s+ON\s+([^\s;]+)/gi)) {
      hits.push({
        offset: match.index,
        matched: match[0],
        message: `Policy \`${match[1]}\` on \`${match[2]}\` is dropped, removing a row-level restriction.`,
        data: { policy: match[1], table: match[2] },
      });
    }
    return hits;
  },
});

/** VSB-DB-006 - ORM raw-SQL escape hatches. */
const ormRawSql: Rule = defineRule({
  id: 'VSB-DB-006',
  slug: 'orm-unsafe-raw-query',
  title: 'ORM raw-SQL API called with a dynamic string',
  category: 'database-exposure',
  severity: 'critical',
  confidence: 'high',
  cwe: CWES.sqlInjection,
  description:
    '`$queryRawUnsafe`, `knex.raw`, `sequelize.query`, `.raw()` and TypeORM `query()` bypass parameter binding. When their argument is a template literal with `${}` or string concatenation, request data reaches the SQL parser.',
  insecureExample: 'await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE id = ${id}`);',
  secureExample: 'await prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`;',
  remediation: [
    'Use the tagged-template form `$queryRaw` / `$executeRaw` — Prisma binds every interpolation as a parameter.',
    'For Prisma, pass `Prisma.sql` fragments and `Prisma.join` for lists; never build SQL by concatenation.',
    'For knex/sequelize pass bindings explicitly: `knex.raw("... where id = ?", [id])`.',
    'Validate and cast the value (e.g. `z.string().uuid()`) before it reaches the query.',
  ],
  references: [
    'https://www.prisma.io/docs/orm/prisma-client/using-raw-sql/raw-queries',
    'https://knexjs.org/guide/raw.html#raw',
    'https://cwe.mitre.org/data/definitions/89.html',
  ],
  extensions: APP_EXTENSIONS,
  skipFlags: [...LOGIC_SKIP_FLAGS],
  detect(ctx) {
    const hits: RuleHit[] = [];
    const sinks: Array<{ regex: RegExp; note: string }> = [
      { regex: /\$\s*(?:query|execute)RawUnsafe\s*\(/g, note: '`$queryRawUnsafe` executes the string verbatim.' },
      { regex: /\b(?:knex|this\.knex|db\.knex)\s*\.\s*raw\s*\(/g, note: '`knex.raw()` with an interpolated string is injectable.' },
      { regex: /\bsequelize\s*\.\s*query\s*\(/g, note: '`sequelize.query()` executes raw SQL; use `replacements`/`bind`.' },
      { regex: /\b(?:prisma|typeorm|dataSource|repository|manager)\s*\.\s*query\s*\(/g, note: '`.query()` executes raw SQL without binding.' },
      { regex: /\.\s*raw\s*\(\s*`/g, note: '`.raw()` called with a template literal bypasses the query builder.' },
    ];
    for (const sink of sinks) {
      for (const match of ctx.code.matchAll(sink.regex)) {
        const open = ctx.code.indexOf('(', match.index);
        const args = balancedBlock(ctx.code, open, '(', ')');
        if (!args) continue;
        const unsafeByConstruction = /Unsafe/.test(match[0]);
        if (!unsafeByConstruction && !looksDynamic(args)) continue;
        if (unsafeByConstruction && !looksDynamic(args) && !UNTRUSTED_SOURCE_REGEX.test(args)) continue;
        hits.push({
          offset: match.index,
          matched: match[0],
          message: sink.note,
          data: { sink: match[0].replace(/\s+/g, '') },
        });
      }
    }
    return hits;
  },
});

/** VSB-DB-007 - hand-built SQL string from request input. */
const concatenatedSql: Rule = defineRule({
  id: 'VSB-DB-007',
  slug: 'sql-string-concatenation',
  title: 'SQL statement built by concatenating request data',
  category: 'database-exposure',
  severity: 'critical',
  confidence: 'high',
  cwe: CWES.sqlInjection,
  description:
    'A SQL string assembled with `+`, `${}` or `%` formatting from `req.body`/`req.query`/`searchParams` is the textbook injection. Parameterised queries make this impossible; agents still write it when a query builder feels heavy.',
  insecureExample: 'db.query("SELECT * FROM users WHERE email = \'" + req.body.email + "\'")',
  secureExample: 'db.query("SELECT * FROM users WHERE email = $1", [req.body.email])',
  remediation: [
    'Switch to parameterised queries: `$1`/`?` placeholders with a values array — never string interpolation.',
    'Use the ORM/query-builder API for the whole query (`.where({ email })`), not a hand-built fragment.',
    'If a fragment is unavoidable, build it from a hardcoded allow-list, never from request input.',
    'Add an integration test that posts `\' OR 1=1 --` and asserts the query returns nothing.',
  ],
  references: [
    'https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html',
    'https://cwe.mitre.org/data/definitions/89.html',
  ],
  extensions: [...APP_EXTENSIONS, 'java', 'kt'],
  skipFlags: [...LOGIC_SKIP_FLAGS],
  detect(ctx) {
    const hits: RuleHit[] = [];
    const sqlVerb = /\b(?:SELECT\s+[\s\S]{0,120}?\s+FROM|INSERT\s+INTO|UPDATE\s+[\w.]+\s+SET|DELETE\s+FROM)\b/i;
    // A template literal is a *tagged* template when an identifier or a member
    // expression immediately precedes the backtick. Prisma's `$queryRaw` and
    // `$executeRaw` are tagged templates that bind every interpolation as a
    // parameter — the safe form — so they are not sinks.
    for (const match of ctx.code.matchAll(/`([^`]{0,600})`/g)) {
      const body = match[1] ?? '';
      if (!sqlVerb.test(body)) continue;
      if (!/\$\{[^}]+\}/.test(body)) continue;
      const before = ctx.code.slice(Math.max(0, match.index - 40), match.index);
      if (/(?:[A-Za-z_$][\w$]*|\)|\])\s*$/.test(before)) continue;
      const interpolations = [...body.matchAll(/\$\{([^}]+)\}/g)].map((m) => m[1] ?? '');
      const tainted = interpolations.some(
        (expr) =>
          UNTRUSTED_SOURCE_REGEX.test(expr) ||
          /^(?:req|request|params|query|body|input|userId|searchParams|event)\b/.test(expr.trim()),
      );
      if (!tainted) continue;
      hits.push({
        offset: match.index,
        matched: body.slice(0, 160),
        message: 'A SQL statement is built with `${}` interpolation of request data.',
        data: { sink: 'template', interpolations: interpolations.slice(0, 3) },
      });
    }
    // `"SELECT ... " + req.body.x` concatenation.
    for (const match of ctx.code.matchAll(/(['"`])((?:[^'"`\\]|\\.){0,300}?)\1\s*\+\s*([^;\n]{0,160})/g)) {
      const literal = match[2] ?? '';
      const tail = match[3] ?? '';
      if (!sqlVerb.test(literal)) continue;
      if (!UNTRUSTED_SOURCE_REGEX.test(tail) && !/^(?:req|request|params|query|body|input|userId|searchParams)/.test(tail.trim())) continue;
      hits.push({
        offset: match.index,
        matched: `${literal.slice(0, 80)} + ${tail.slice(0, 60)}`,
        message: 'A SQL statement is concatenated with request data.',
        data: { sink: 'concat' },
      });
    }
    // Python f-strings / % formatting and PHP interpolation reaching a query.
    if (['py'].includes(ctx.extension)) {
      for (const match of ctx.code.matchAll(/\b(?:execute|executemany|raw|query)\s*\(\s*f(['"])([\s\S]{0,400}?)\1/g)) {
        const body = match[2] ?? '';
        if (!sqlVerb.test(body)) continue;
        hits.push({
          offset: match.index,
          matched: match[0].slice(0, 140),
          message: 'A Python f-string SQL statement interpolates request data directly.',
          data: { sink: 'fstring' },
        });
      }
      for (const match of ctx.code.matchAll(/\b(?:execute|executemany)\s*\(\s*(['"])([\s\S]{0,400}?)\1\s*%\s*\(/g)) {
        const body = match[2] ?? '';
        if (!sqlVerb.test(body)) continue;
        hits.push({
          offset: match.index,
          matched: match[0].slice(0, 140),
          message: 'A Python `%`-formatted SQL statement injects request data.',
          data: { sink: 'percent' },
        });
      }
    }
    if (ctx.extension === 'php') {
      for (const match of ctx.code.matchAll(/\b(?:mysqli_query|mysql_query|pg_query|->query)\s*\(\s*(["'])([\s\S]{0,400}?)\1/g)) {
        const body = match[2] ?? '';
        if (!sqlVerb.test(body)) continue;
        if (!/\$\w+/.test(body)) continue;
        hits.push({
          offset: match.index,
          matched: match[0].slice(0, 140),
          message: 'A PHP SQL string interpolates a variable — use prepared statements with bound parameters.',
          data: { sink: 'php-interpolation' },
        });
      }
    }
    return hits;
  },
});

/** VSB-DB-008 - Supabase service-role client outside the server. */
const serviceRoleMisuse: Rule = defineRule({
  id: 'VSB-DB-008',
  slug: 'supabase-service-role-misuse',
  title: 'Supabase service-role key used outside a server-only module',
  category: 'database-exposure',
  severity: 'critical',
  confidence: 'high',
  cwe: CWES.privilegeEscalation,
  description:
    'The service-role key signs a JWT with `role: service_role`, which bypasses every RLS policy. Used from a client-reachable module it is a complete database takeover; used in a server request path without an auth check it is an open admin API.',
  insecureExample: 'const supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!);',
  secureExample: 'import "server-only";\nconst supabaseAdmin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!);',
  remediation: [
    'Keep the service-role client in a module that starts with `import "server-only";` so the build fails if it leaks into the client graph.',
    'Restrict its use to server actions / route handlers that have already authenticated and authorised the caller.',
    'Prefer the anon key + RLS for anything user-facing; the service role is for migrations, cron and admin tooling.',
    'Rotate the key if it ever shipped to a client bundle.',
  ],
  references: [
    'https://supabase.com/docs/guides/api/api-keys',
    'https://cwe.mitre.org/data/definitions/250.html',
  ],
  extensions: APP_EXTENSIONS,
  skipFlags: [...LOGIC_SKIP_FLAGS],
  detect(ctx) {
    if (!/(?:SERVICE_ROLE_KEY|SERVICE_ROLE|service_role|serviceRoleKey|SUPABASE_SECRET_KEY)/.test(ctx.code)) return [];
    const hits: RuleHit[] = [];
    const isServerBoundary =
      SERVER_ONLY_GUARD_REGEX.test(ctx.code) ||
      /export\s+const\s+runtime\s*=\s*['"]nodejs['"]/.test(ctx.code) ||
      ctx.flags.isAppRouterRoute ||
      ctx.flags.isServerActionModule ||
      ctx.flags.isPagesApiRoute;
    for (const match of ctx.code.matchAll(/(?:SERVICE_ROLE_KEY|SERVICE_ROLE|service_role|serviceRoleKey|SUPABASE_SECRET_KEY)/g)) {
      const line = ctx.locate(match.index).line;
      const owner = ctx.lineText(line);
      if (!/(?:createClient|createServerClient|Authorization|Bearer|apikey|headers)/i.test(owner)) continue;
      if (isBrowserFile(ctx)) {
        hits.push({
          offset: match.index,
          matched: 'SERVICE_ROLE_KEY',
          message: 'The RLS-bypassing service-role key is referenced from browser-reachable code.',
          severity: 'critical',
          confidence: 'high',
          data: { boundary: 'client' },
        });
        continue;
      }
      if (isServerBoundary) continue;
      hits.push({
        offset: match.index,
        matched: 'SERVICE_ROLE_KEY',
        message: 'Service-role key used in a module with no server-only boundary — any importer inherits RLS bypass.',
        severity: 'critical',
        confidence: 'medium',
        data: { boundary: 'unmarked' },
      });
    }
    return hits;
  },
});

/** VSB-DB-009 - public storage bucket. */
const publicBucket: Rule = defineRule({
  id: 'VSB-DB-009',
  slug: 'public-storage-bucket',
  title: 'Storage bucket created as publicly readable',
  category: 'database-exposure',
  severity: 'medium',
  confidence: 'high',
  cwe: CWES.permissiveAcl,
  description:
    'A `public: true` Supabase Storage bucket serves every object to anyone with the URL, with no expiry and no auth. User uploads, invoices and ID scans end up in a search engine.',
  insecureExample: "await supabase.storage.createBucket('uploads', { public: true });",
  secureExample: "await supabase.storage.createBucket('uploads', { public: false });\nconst { data } = await supabase.storage.from('uploads').createSignedUrl(path, 60);",
  remediation: [
    'Create the bucket with `public: false` and serve files through short-lived signed URLs (`createSignedUrl`).',
    'Add storage RLS policies so a signed-in user can only read their own objects.',
    'If a bucket is intentionally public (marketing assets), keep it separate from user-uploaded content.',
  ],
  references: [
    'https://supabase.com/docs/guides/storage/security/access-control',
    'https://cwe.mitre.org/data/definitions/732.html',
  ],
  extensions: APP_EXTENSIONS,
  skipFlags: [...LOGIC_SKIP_FLAGS],
  detect(ctx) {
    return regexHits(
      ctx.code,
      /\bcreateBucket\s*\(\s*([^,)]{1,80}),\s*\{([^}]{0,200})\}/g,
      (match) => {
        const options = match[2] ?? '';
        if (!/\bpublic\s*:\s*true\b/.test(options)) return null;
        return {
          matched: match[0].slice(0, 140),
          message: `Bucket \`${(match[1] ?? '').trim()}\` is public: every uploaded object is world-readable.`,
          data: { bucket: (match[1] ?? '').trim() },
        };
      },
    );
  },
});

/** VSB-DB-010 - dynamic table/column/order-by identifiers. */
const dynamicIdentifiers: Rule = defineRule({
  id: 'VSB-DB-010',
  slug: 'dynamic-sql-identifier',
  title: 'Request data used as a table, column or ORDER BY identifier',
  category: 'database-exposure',
  severity: 'high',
  confidence: 'high',
  cwe: CWES.sqlInjection,
  description:
    'Parameter binding protects *values*, not identifiers. `from(req.body.table)`, `ORDER BY ${sort}` and `prisma[modelName]` let the caller choose which table or column the query touches — including `auth.users`.',
  insecureExample: "supabase.from(req.body.table).select('*')",
  secureExample: "const TABLES = { posts, comments } as const;\nsupabase.from(TABLES[req.body.table]).select('*')",
  remediation: [
    'Map the incoming identifier through a hardcoded allow-list (`const TABLES = {...}`) and reject anything else with a 400.',
    'Never interpolate `sort`, `order`, `direction` or `column` into SQL; use an enum or a `Record<string, string>` map.',
    'For dynamic ORDER BY, use the query builder (`query.order(column, { ascending })` with a validated column name).',
  ],
  references: [
    'https://supabase.com/docs/reference/javascript/select',
    'https://cwe.mitre.org/data/definitions/89.html',
  ],
  extensions: [...APP_EXTENSIONS],
  skipFlags: [...LOGIC_SKIP_FLAGS],
  detect(ctx) {
    const hits: RuleHit[] = [];
    const patterns: Array<{ regex: RegExp; note: string }> = [
      { regex: /\.\s*from\s*\(\s*(?:req|request|ctx|c|event)\b[^)]{0,80}\)/g, note: 'The table name is chosen by the caller.' },
      { regex: /\.\s*(?:orderBy|order_by|order)\s*\(\s*(?:req|request|params|query|body|searchParams)/g, note: 'The sort column is chosen by the caller.' },
      { regex: /\bORDER\s+BY\s+\$\{/gi, note: 'A template literal is interpolated into ORDER BY.' },
      { regex: /\b(?:prisma|db|this)\s*\[\s*(?:req|request|params|query|body|modelName|tableName|collection)\b[^\]]{0,40}\]/g, note: 'A data model is indexed with a caller-supplied key.' },
      { regex: /\.\s*(?:select|pluck|distinct)\s*\(\s*(?:req|request)\b[^)]{0,80}\)/g, note: 'The selected columns come from the request.' },
    ];
    for (const pattern of patterns) {
      for (const match of ctx.code.matchAll(pattern.regex)) {
        hits.push({
          offset: match.index,
          matched: match[0].slice(0, 140),
          message: pattern.note,
          data: { sink: match[0].slice(0, 60) },
        });
      }
    }
    return hits;
  },
});

export const DATABASE_EXPOSURE_RULES: readonly Rule[] = [
  tableWithoutRls,
  permissivePolicy,
  unscopedPolicy,
  publicGrant,
  rlsDisabled,
  ormRawSql,
  concatenatedSql,
  serviceRoleMisuse,
  publicBucket,
  dynamicIdentifiers,
];
