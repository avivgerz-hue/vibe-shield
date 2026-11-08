/** Local configuration signals, not proof of effective response headers or cookies. */
import { defineRule } from './helpers';
import { cwe } from './shared';
import type { FileContext, Rule, RuleHit } from '../types';

const sourceFile = (ctx: FileContext): boolean => /\.(?:[cm]?[jt]sx?)$/i.test(ctx.fileName) &&
  !ctx.flags.isTestFile && !ctx.flags.isDocumentation && !ctx.flags.isGenerated && !ctx.flags.isAgentInstructionFile;
const nextConfig = (ctx: FileContext): boolean => /^next\.config\.[cm]?[jt]s$/i.test(ctx.fileName);
const serverConfig = (ctx: FileContext): boolean => /\b(?:app|server|fastify)\.listen\s*\(/.test(ctx.code) && /\b(?:express|fastify|hono)\b/i.test(ctx.code);

const headers = [
  { id:'VSB-INFRA-010', slug:'missing-content-security-policy', name:'Content-Security-Policy', probe:/\b(?:Content-Security-Policy|contentSecurityPolicy)\b/i, hint:'Define a restrictive Content-Security-Policy appropriate to the app, including a safe script-src.', cwe:cwe('CWE-693','Protection Mechanism Failure') },
  { id:'VSB-INFRA-011', slug:'missing-frame-protection', name:'X-Frame-Options', probe:/\b(?:X-Frame-Options|frameguard|frame-ancestors)\b/i, hint:'Set X-Frame-Options or a CSP frame-ancestors directive appropriate to the application.', cwe:cwe('CWE-693','Protection Mechanism Failure') },
  { id:'VSB-INFRA-012', slug:'missing-hsts', name:'Strict-Transport-Security', probe:/\b(?:Strict-Transport-Security|hsts)\b/i, hint:'Enable HSTS at the HTTPS edge after verifying HTTPS coverage across the relevant hosts.', cwe:cwe('CWE-693','Protection Mechanism Failure') },
] as const;

const HEADER_RULES: Rule[] = headers.map(header => defineRule({
  id: header.id, slug: header.slug, title: `${header.name} not observed in server configuration`,
  category:'infrastructure', severity:'low', confidence:'low', cwe:header.cwe,
  description:`No ${header.name} configuration was observed in this server configuration file. It may be supplied by middleware, the hosting platform, or a reverse proxy; verify the deployed response.`,
  insecureExample:'// No security header configured in this file', secureExample:header.hint,
  remediation:[header.hint, 'Verify actual response headers at the deployed edge, including error responses and any proxy configuration.'],
  references:['https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html', header.cwe.url],
  appliesTo:ctx=>sourceFile(ctx) && (nextConfig(ctx) || serverConfig(ctx)),
  detect:ctx=> {
    // Helmet with no options enables these default protections. A configured or
    // indirect middleware is not assumed to do so, and the result is advisory.
    if (header.probe.test(ctx.code) || /\bhelmet\s*\(\s*\)/.test(ctx.code)) return [];
    return [{line:1,column:1,matched:ctx.lineText(1).trim(), message:`${header.name} was not observed in this file. Check middleware and deployment headers before treating this as missing.`}];
  },
}));

interface CookieCall { offset: number; options: string | null }
/** Extract top-level call arguments, respecting nested delimiters and quotes. */
function callArguments(code: string, open: number): string[] | null {
  const stack = [')'];
  const args: string[] = [];
  let start = open + 1;
  let quote = '';
  for (let i = start; i < code.length && i < open + 12_000; i += 1) {
    const ch = code[i]!;
    if (quote) {
      if (ch === '\\') { i += 1; continue; }
      if (ch === quote) quote = '';
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { quote = ch; continue; }
    if (ch === '(' || ch === '[' || ch === '{') { stack.push(ch === '(' ? ')' : ch === '[' ? ']' : '}'); continue; }
    if (ch === stack[stack.length - 1]) {
      stack.pop();
      if (!stack.length) { args.push(code.slice(start, i).trim()); return args; }
      continue;
    }
    if (ch === ',' && stack.length === 1) { args.push(code.slice(start, i).trim()); start = i + 1; }
  }
  return null;
}

function cookieCalls(ctx: FileContext): CookieCall[] {
  const calls: CookieCall[] = [];
  const pattern = /\b(?:[\w$]+\.cookie|[\w$]+\.cookies\.set|cookies\s*\(\s*\)\s*\.set|setCookie|cookie\.serialize)\s*\(/g;
  for (const match of ctx.code.matchAll(pattern)) {
    const args = callArguments(ctx.code, match.index! + match[0].lastIndexOf('('));
    if (!args || !args[0]) continue;
    const singleObject = args.length === 1 && args[0].startsWith('{');
    const required = /^setCookie\s*\(/.test(match[0]) ? 3 : 2;
    const last = args[args.length - 1]!;
    // Dynamic option expressions and object spreads may provide flags; skip
    // rather than claiming they are absent. Different setters remain separate.
    if (singleObject) {
      if (/\.\.\./.test(last)) continue;
      calls.push({ offset: match.index!, options: last });
    } else if (args.length === required) {
      calls.push({ offset: match.index!, options: null });
    } else if (args.length === required + 1 && /^\{[\s\S]*\}$/.test(last) && !/\.\.\./.test(last)) {
      calls.push({ offset: match.index!, options: last });
    }
  }
  return calls;
}

const flags = [
  { id:'VSB-INFRA-013', slug:'cookie-missing-httponly', name:'HttpOnly', key:'httpOnly', cwe:cwe('CWE-1004','Sensitive Cookie Without HttpOnly Flag'), fix:'Set httpOnly: true on sensitive cookies to limit access from browser scripts.' },
  { id:'VSB-INFRA-014', slug:'cookie-missing-secure', name:'Secure', key:'secure', cwe:cwe('CWE-614','Sensitive Cookie in HTTPS Session Without Secure Attribute'), fix:'Set secure: true on sensitive cookies served over HTTPS.' },
  { id:'VSB-INFRA-015', slug:'cookie-missing-samesite', name:'SameSite', key:'sameSite', cwe:cwe('CWE-1275','Sensitive Cookie with Improper SameSite Attribute'), fix:'Set sameSite to lax or strict where appropriate, and use CSRF protections for state-changing requests.' },
] as const;

/** Only top-level keys belong to the cookie options object. */
function hasOption(options: string, key: string): boolean {
  const properties = callArguments(`(${options.slice(1, -1)})`, 0) ?? [];
  const name = new RegExp(`^\\s*["']?${key}["']?(?:\\s*:|\\s*$)`, 'i');
  return properties.some(property => name.test(property));
}

const COOKIE_RULES: Rule[] = flags.map(flag => defineRule({
  id:flag.id, slug:flag.slug, title:`Cookie setter does not specify ${flag.name}`, category:'infrastructure',
  severity:'medium', confidence:'medium', cwe:flag.cwe,
  description:`The observed cookie setter omits ${flag.name} in its literal options. Framework defaults and shared configuration may supply it; confirm the deployed Set-Cookie header and whether the cookie is sensitive.`,
  insecureExample:"res.cookie('session', token, {})", secureExample:`res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'lax' })`,
  remediation:[flag.fix, 'Check framework defaults, shared middleware and the actual Set-Cookie response; add regression tests for the chosen attributes.'],
  references:['https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html', flag.cwe.url],
  appliesTo:sourceFile,
  detect:ctx=>cookieCalls(ctx).filter(call => !call.options || !hasOption(call.options, flag.key))
    .map((call):RuleHit=>({offset:call.offset, matched:ctx.lineText(ctx.locate(call.offset).line).trim().slice(0,120), message:`${flag.name} was not specified on this cookie setter; check defaults and the actual response.`})),
}));

export const RESPONSE_HARDENING_RULES: readonly Rule[] = [...HEADER_RULES, ...COOKIE_RULES];
