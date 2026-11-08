/** Focused, local syntax checks. These are indicators, not data-flow proofs. */
import { existsSync } from 'node:fs';
import * as path from 'node:path';
import { defineRule, regexHits } from './helpers';
import { CWES } from './shared';
import type { FileContext, Rule, RuleCategory } from '../types';

type Spec = { id: string; title: string; category: RuleCategory; pattern: RegExp; example: string; fix: string; cwe: typeof CWES[keyof typeof CWES]; scope: (ctx: FileContext) => boolean };
const code = (c: FileContext): boolean => /\.(?:[cm]?[jt]sx?|vue|svelte)$/i.test(c.fileName) && !c.flags.isDocumentation && !c.flags.isAgentInstructionFile && !c.flags.isTestFile;
const cookieCode = (c: FileContext): boolean => code(c) && /\bcookie/i.test(c.code);
const manifest = (c: FileContext): boolean => c.fileName === 'package.json' && !c.flags.isTestFile;
const docker = (c: FileContext): boolean => c.language === 'dockerfile' && !c.flags.isTestFile;
const config = (c: FileContext): boolean => /^(?:next|vite)\.config\.[cm]?[jt]s$/i.test(c.fileName);
const specs: Spec[] = [
  {id:'VSB-CLIENT-008',title:'Production source maps enabled',category:'client-exposure',pattern:/\b(?:productionBrowserSourceMaps|sourcemap)\s*:\s*true\b/g,example:'productionBrowserSourceMaps: true',fix:'Disable production source maps or upload them privately to a restricted error-monitoring service.',cwe:CWES.exposureOfSecrets,scope:config},
  {id:'VSB-AUTH-010',title:'JWT accepts the none algorithm',category:'unguarded-routes',pattern:/\balgorithms\s*:\s*\[[^\]]*['"]none['"]/gi,example:"algorithms: ['none']",fix:'Require a fixed allowlist of strong signed algorithms and verify issuer, audience and expiry.',cwe:CWES.improperCertValidation,scope:code},
  {id:'VSB-AUTH-011',title:'JWT decoded without a verification call',category:'unguarded-routes',pattern:/\bjwt\.decode\s*\(/g,example:'jwt.decode(token)',fix:'Verify the signature, allowed algorithm, issuer, audience and expiry before trusting claims.',cwe:CWES.improperCertValidation,scope:c=>code(c) && !/\bjwt\.verify\s*\(/.test(c.code)},
  {id:'VSB-INFRA-001',title:'Wildcard cross-origin response',category:'infrastructure',pattern:/['"]Access-Control-Allow-Origin['"]\s*[:,]\s*['"]\*['"]/gi,example:"'Access-Control-Allow-Origin': '*'",fix:'Restrict origins to a reviewed allowlist for sensitive responses.',cwe:CWES.browserSecurity,scope:code},
  {id:'VSB-INFRA-002',title:'Container explicitly runs as root',category:'infrastructure',pattern:/^\s*USER\s+(?:root|0)(?:\s|$)/gim,example:'USER root',fix:'Use a dedicated unprivileged runtime user and grant only required filesystem access.',cwe:CWES.privilegeEscalation,scope:docker},
  {id:'VSB-INFRA-003',title:'Secret named in container environment',category:'infrastructure',pattern:/^\s*(?:ENV|ARG)\s+\w*(?:PASSWORD|SECRET|TOKEN|PRIVATE_KEY)\w*\s*[= ]\s*[^\s$#]+/gim,example:'ENV API_SECRET=example',fix:'Use runtime secret injection or build secret mounts; rotate any baked credentials.',cwe:CWES.hardcodedCredentials,scope:docker},
  {id:'VSB-INFRA-004',title:'Redirect directly uses next parameter',category:'infrastructure',pattern:/\bredirect\s*\(\s*(?:\w+\.)?searchParams\.get\s*\(\s*['"](?:next|redirect|url)['"]\s*\)/gi,example:"redirect(searchParams.get('next'))",fix:'Allow only validated relative paths or a strict same-origin allowlist before redirecting.',cwe:CWES.openRedirect,scope:code},
  {id:'VSB-DEPS-001',title:'Wildcard package dependency',category:'dependencies',pattern:/"[^"\n]+"\s*:\s*"\*"/g,example:'"library": "*"',fix:'Pin an appropriate dependency version and commit the lockfile.',cwe:CWES.untrustedSearchPath,scope:manifest},
  {id:'VSB-DEPS-002',title:'Latest tag used for package dependency',category:'dependencies',pattern:/"[^"\n]+"\s*:\s*"latest"/gi,example:'"library": "latest"',fix:'Use a reviewed version and commit a lockfile.',cwe:CWES.untrustedSearchPath,scope:manifest},
  {id:'VSB-DEPS-003',title:'Remote package dependency',category:'dependencies',pattern:/"[^"\n]+"\s*:\s*"(?:git\+|git:|https?:\/\/)[^"\n]+"/gi,example:'"library": "https://example.invalid/library.tgz"',fix:'Review the origin and integrity, prefer a trusted registry and lock immutable versions.',cwe:CWES.dependencyConfusion,scope:manifest},
  {id:'VSB-DEPS-004',title:'Remote shell execution in install script',category:'dependencies',pattern:/"(?:preinstall|install|postinstall)"\s*:\s*"[^"\n]*(?:curl|wget)[^"\n]*\|\s*(?:ba)?sh\b/gi,example:'"postinstall": "curl example.invalid | sh"',fix:'Remove remote shell execution; review and pin any required build tooling.',cwe:CWES.commandInjection,scope:manifest},
  {id:'VSB-DEPS-005',title:'Encoded PowerShell in install script',category:'dependencies',pattern:/"(?:preinstall|install|postinstall)"\s*:\s*"[^"\n]*powershell(?:\.exe)?\s+-(?:enc|encodedcommand)\b/gi,example:'"postinstall": "powershell -enc ..."',fix:'Remove encoded lifecycle scripts and inspect their decoded content before trusting the package.',cwe:CWES.commandInjection,scope:manifest},
  {id:'VSB-CRYPTO-001',title:'Weak password digest',category:'secret-entropy',pattern:/\b(?:createHash|hashlib\.(?:new))\s*\(\s*['"](?:md5|sha1)['"]\s*\)[^\n]*(?:password|passwd|pwd)/gi,example:"createHash('sha1').update(password)",fix:'Use a modern password hashing algorithm such as Argon2id with a unique salt.',cwe:CWES.weakCrypto,scope:code},
  {id:'VSB-CRYPTO-002',title:'Predictable security token generated with Math.random',category:'secret-entropy',pattern:/(?:token|otp|csrf|reset|nonce)\w*\s*=\s*[^\n;]*\bMath\.random\s*\(/gi,example:'const token = Math.random()',fix:'Use a cryptographically secure random source such as crypto.randomBytes or crypto.randomUUID.',cwe:CWES.weakCrypto,scope:code},
  {id:'VSB-CLIENT-009',title:'Inline production source maps enabled',category:'client-exposure',pattern:/\bsourcemap\s*:\s*['"]inline['"]/gi,example:"sourcemap: 'inline'",fix:'Disable public source maps for production builds or store them privately.',cwe:CWES.exposureOfSecrets,scope:config},
  {id:'VSB-AUTH-012',title:'JWT signed with a literal secret',category:'unguarded-routes',pattern:/\bjwt\.sign\s*\([^,\n]+,\s*['"][^'"]{4,}['"]/g,example:"jwt.sign(payload, 'literal-secret')",fix:'Use a high-entropy secret from a secret manager, rotate exposed keys and specify the expected signing algorithm.',cwe:CWES.hardcodedCredentials,scope:code},
  {id:'VSB-INFRA-005',title:'Cookie explicitly disables HttpOnly',category:'infrastructure',pattern:/\bhttpOnly\s*:\s*false\b/gi,example:'httpOnly: false',fix:'Set httpOnly on session cookies so browser scripts cannot read them.',cwe:CWES.exposureOfSecrets,scope:cookieCode},
  {id:'VSB-INFRA-006',title:'Cookie explicitly disables Secure',category:'infrastructure',pattern:/\bsecure\s*:\s*false\b/gi,example:'secure: false',fix:'Set secure on sensitive cookies in production and serve exclusively over HTTPS.',cwe:CWES.exposureOfSecrets,scope:cookieCode},
  {id:'VSB-INFRA-007',title:'Cookie explicitly disables SameSite',category:'infrastructure',pattern:/\bsameSite\s*:\s*false\b/gi,example:'sameSite: false',fix:'Use SameSite Lax or Strict where compatible, and use CSRF protection for state-changing requests.',cwe:CWES.csrf,scope:cookieCode},
  {id:'VSB-INFRA-008',title:'CORS reflects origins while allowing credentials',category:'infrastructure',pattern:/\borigin\s*:\s*true\b/g,example:'cors({ origin: true, credentials: true })',fix:'Use an explicit trusted origin allowlist and verify preflight and credential handling.',cwe:CWES.browserSecurity,scope:c=>code(c) && /\bcredentials\s*:\s*true\b/.test(c.code)},
  {id:'VSB-CRYPTO-003',title:'ECB mode encryption',category:'secret-entropy',pattern:/\b(?:createCipheriv|createCipher)\s*\(\s*['"][^'"]*ecb['"]/gi,example:"createCipheriv('aes-256-ecb', key, null)",fix:'Use an authenticated encryption mode such as AES-GCM with a unique nonce.',cwe:CWES.weakCrypto,scope:code},
  {id:'VSB-CRYPTO-004',title:'TLS certificate validation disabled',category:'secret-entropy',pattern:/\brejectUnauthorized\s*:\s*false\b/g,example:'rejectUnauthorized: false',fix:'Enable certificate validation and configure the correct trusted CA for the target.',cwe:CWES.improperCertValidation,scope:code},
  {id:'VSB-CRYPTO-005',title:'TLS verification disabled by environment',category:'secret-entropy',pattern:/\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]0['"]/g,example:"process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'",fix:'Remove the override and configure a trusted CA instead of disabling certificate verification.',cwe:CWES.improperCertValidation,scope:code},
];

export const HARDENING_RULES: readonly Rule[] = specs.map(s => defineRule({
  id:s.id, slug:s.title.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/-$/,''), title:s.title,
  category:s.category, severity: s.id === 'VSB-AUTH-010' ? 'high' : 'medium', confidence:'medium', cwe:s.cwe,
  description:`${s.title}. Review the surrounding configuration and actual exposure.`,
  insecureExample:s.example, secureExample:s.fix, remediation:[s.fix, 'Review the finding in context and add a regression test for the intended security boundary.'], references:[s.cwe.url],
  appliesTo:s.scope, detect:ctx=>{
    if (!['VSB-DEPS-001','VSB-DEPS-002','VSB-DEPS-003'].includes(s.id)) return regexHits(ctx.code,s.pattern);
    try {
      const pkg = JSON.parse(ctx.content) as Record<string, unknown>;
      const values = ['dependencies','devDependencies','optionalDependencies','peerDependencies'].flatMap(key => Object.entries((pkg[key] ?? {}) as Record<string, string>));
      return regexHits(ctx.content,s.pattern, m => {
        const pair = /^"([^"]+)"\s*:\s*"([^"]+)"/.exec(m[0]);
        return pair && values.some(([key,value]) => key === pair[1] && value === pair[2]) ? {} : null;
      });
    } catch { return []; }
  },
}));

export const MISSING_LOCKFILE_RULE: Rule = defineRule({
  id:'VSB-DEPS-006', slug:'missing-node-lockfile', title:'Node project has no lockfile', category:'dependencies',
  severity:'medium', confidence:'medium', cwe:CWES.untrustedSearchPath,
  description:'A package manifest without a lockfile can resolve different dependency versions across installs.',
  insecureExample:'package.json without a lockfile', secureExample:'Commit a lockfile generated by the package manager.',
  remediation:['Commit a reviewed lockfile for the package manager used by this project.', 'Use the package manager’s frozen-lockfile mode in CI.'], references:['https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json'],
  appliesTo:ctx=>manifest(ctx) && ctx.absolutePath === path.join(ctx.project.rootDir, 'package.json'),
  detect:ctx=>['package-lock.json','npm-shrinkwrap.json','yarn.lock','pnpm-lock.yaml','bun.lock','bun.lockb'].some(n=>existsSync(path.join(ctx.project.rootDir,n))) ? [] : [{line:1,column:1,matched:'package.json'}],
});

/** Docker defaults to root when the final stage never selects a runtime user. */
export const DOCKER_DEFAULT_ROOT_RULE: Rule = defineRule({
  id:'VSB-INFRA-009', slug:'container-default-root', title:'Container has no final-stage USER', category:'infrastructure',
  severity:'medium', confidence:'medium', cwe:CWES.privilegeEscalation,
  description:'Without a USER directive in the final build stage, a container may run as root unless its base image specifies a user.',
  insecureExample:'FROM node:22-alpine', secureExample:'FROM node:22-alpine\nUSER node',
  remediation:['Select a non-root runtime user in the final stage.', 'Test file permissions and runtime access with that user.'], references:[CWES.privilegeEscalation.url],
  appliesTo:docker, detect:ctx=>{
    const stages = [...ctx.code.matchAll(/^\s*FROM\s+[^\n]+/gim)];
    const last = stages[stages.length - 1];
    if (!last || /^\s*USER\s+\S+/im.test(ctx.code.slice(last.index))) return [];
    return [{offset:last.index, matched:last[0].trim()}];
  },
});
