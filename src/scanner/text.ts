/**
 * vibe-shield :: text primitives
 * ------------------------------
 * Zero-dependency helpers shared by every rule. The most important one is
 * `maskComments`: it blanks out comments while preserving the exact character
 * length of the file, so byte offsets (and therefore line/column numbers)
 * stay identical between the raw source and the "code only" view that rules
 * match against. That single trick removes the largest class of false
 * positives (vulnerabilities that only exist inside a comment) without a
 * real parser.
 */

import type { Language } from './types';

/** Incremental offset -> line/column resolver. */
export class LineIndex {
  private readonly starts: number[] = [0];
  constructor(private readonly content: string) {
    for (let i = 0; i < content.length; i += 1) {
      if (content.charCodeAt(i) === 10 /* \n */) this.starts.push(i + 1);
    }
  }

  get lineCount(): number {
    return this.starts.length;
  }

  /** 1-based line and column for a character offset. */
  locate(offset: number): { line: number; column: number } {
    const clamped = Math.max(0, Math.min(offset, this.content.length));
    let low = 0;
    let high = this.starts.length - 1;
    while (low < high) {
      const mid = (low + high + 1) >> 1;
      const start = this.starts[mid] ?? 0;
      if (start <= clamped) low = mid;
      else high = mid - 1;
    }
    const lineStart = this.starts[low] ?? 0;
    return { line: low + 1, column: clamped - lineStart + 1 };
  }

  /** Offset of the first character of a 1-based line. */
  lineStart(line: number): number {
    return this.starts[Math.max(0, Math.min(line - 1, this.starts.length - 1))] ?? 0;
  }
}

/** Split content into lines without the trailing newline characters. */
export const splitLines = (content: string): string[] => content.split(/\r?\n/);

/**
 * Iterate every match of `regex` (which must be global) over `content`.
 * Guards against zero-length infinite loops.
 */
export function forEachMatch(
  content: string,
  regex: RegExp,
  handler: (match: RegExpExecArray) => void,
): void {
  if (!regex.global) throw new Error('forEachMatch requires a global RegExp');
  const re = new RegExp(regex.source, regex.flags);
  let match: RegExpExecArray | null;
  let guard = 0;
  const limit = content.length * 4 + 1000;
  while ((match = re.exec(content)) !== null) {
    handler(match);
    if (match[0].length === 0) re.lastIndex += 1;
    guard += 1;
    if (guard > limit) break;
  }
}

/** All matches of a global regex, as `{ text, offset }`. */
export function collectMatches(
  content: string,
  regex: RegExp,
): Array<{ text: string; offset: number; match: RegExpExecArray }> {
  const out: Array<{ text: string; offset: number; match: RegExpExecArray }> = [];
  forEachMatch(content, regex, (m) => out.push({ text: m[0], offset: m.index, match: m }));
  return out;
}

/** Shannon entropy in bits per character. */
export function shannonEntropy(value: string): number {
  if (!value.length) return 0;
  const frequencies = new Map<string, number>();
  for (const char of value) frequencies.set(char, (frequencies.get(char) ?? 0) + 1);
  let entropy = 0;
  for (const count of frequencies.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** Size of the character alphabet actually used (hex, base64, mixed-case...). */
export const alphabetSize = (value: string): number => new Set(value).size;

const PLACEHOLDER_TOKENS = [
  'your',
  'yours',
  'xxxx',
  'placeholder',
  'example',
  'sample',
  'dummy',
  'fake',
  'changeme',
  'change_me',
  'redacted',
  'replace',
  'insert',
  'todo',
  'fixme',
  'unknown',
  'none',
  'null',
  'undefined',
  'test',
  'testing',
  'vibeshield',
  'notreal',
  'not_real',
  'masked',
  'censored',
  'sanitized',
  'lorem',
  'foobar',
  'foo',
  'bar',
  'baz',
  'hunter2',
  'password123',
  'secret123',
];

/**
 * True when a candidate secret is obviously not a real credential: template
 * syntax, environment references, masked output, repeated characters or
 * documentation placeholders.
 */
export function isPlaceholderSecret(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length < 6) return true;
  if (/^[\s'"`<[{(]/.test(trimmed)) return true;
  if (/\$\{|\{\{|%s|%v|\{\d\}|<[a-z_-]+>|process\.env|import\.meta\.env|os\.environ|ENV\[/.test(trimmed)) return true;
  if (/[*•·]{2,}|_{4,}|-{4,}|x{5,}|X{5,}|\.{3,}/.test(trimmed)) return true;
  // A single repeated character (or two alternating) is never a secret.
  if (alphabetSize(trimmed.replace(/[^A-Za-z0-9]/g, '')) <= 2) return true;
  const lower = trimmed.toLowerCase();
  if (PLACEHOLDER_TOKENS.some((token) => lower.includes(token))) return true;
  // Sequential runs like 1234567890 or abcdefgh
  if (/(0123456789|9876543210|abcdefgh|abcdefghijklmnopqrstuvwxyz)/.test(lower)) return true;
  return shannonEntropy(trimmed) < 2;
}

/**
 * Mask a credential for terminal/JSON/SARIF output. Keeps a short prefix and
 * the final two characters so a human can identify *which* key leaked without
 * re-publishing the secret in a CI log.
 */
export function redactSecret(value: string, keepPrefix = 6): string {
  const trimmed = value.trim();
  if (trimmed.length <= keepPrefix + 4) {
    return `${trimmed.slice(0, Math.min(3, trimmed.length))}${'•'.repeat(Math.max(4, trimmed.length - 3))}`;
  }
  const prefix = trimmed.slice(0, keepPrefix);
  const suffix = trimmed.slice(-2);
  const masked = '•'.repeat(Math.min(24, Math.max(6, trimmed.length - keepPrefix - 2)));
  return `${prefix}${masked}${suffix}`;
}

/** Escape a string for safe inclusion in a RegExp. */
export const escapeRegExp = (value: string): string => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Build a case-insensitive "any of these words" regex source fragment. */
export const alternation = (words: readonly string[]): string => words.map(escapeRegExp).join('|');

interface MaskState {
  out: string[];
  i: number;
}

const pushMasked = (state: MaskState, source: string, from: number, to: number): void => {
  for (let i = from; i < to; i += 1) {
    const char = source[i] ?? '';
    // Preserve newlines so line numbers remain valid.
    state.out.push(char === '\n' || char === '\r' ? char : ' ');
  }
  state.i = to;
};

/**
 * Blank out comments for C-like languages (JS/TS/JSX/Java/Go/Rust/C#/PHP-ish),
 * preserving string, template-literal and (best-effort) regex-literal bodies
 * and the overall character length of the input.
 */
export function maskCStyleComments(source: string): string {
  const state: MaskState = { out: [], i: 0 };
  let lastSignificant = '';
  const n = source.length;
  while (state.i < n) {
    const i = state.i;
    const char = source[i] ?? '';
    const next = source[i + 1] ?? '';

    if (char === '/' && next === '/') {
      let end = source.indexOf('\n', i);
      if (end === -1) end = n;
      pushMasked(state, source, i, end);
      continue;
    }
    if (char === '/' && next === '*') {
      const end = source.indexOf('*/', i + 2);
      const stop = end === -1 ? n : end + 2;
      pushMasked(state, source, i, stop);
      continue;
    }
    if (char === '"' || char === "'") {
      let j = i + 1;
      while (j < n) {
        const c = source[j];
        if (c === '\\') {
          j += 2;
          continue;
        }
        if (c === char || c === '\n') break;
        j += 1;
      }
      state.out.push(...source.slice(i, Math.min(j + 1, n)).split(''));
      state.i = Math.min(j + 1, n);
      lastSignificant = char;
      continue;
    }
    if (char === '`') {
      let j = i + 1;
      let depth = 0;
      while (j < n) {
        const c = source[j];
        if (c === '\\') {
          j += 2;
          continue;
        }
        if (c === '$' && source[j + 1] === '{') {
          depth += 1;
          j += 2;
          continue;
        }
        if (depth > 0 && c === '}') {
          depth -= 1;
          j += 1;
          continue;
        }
        if (c === '`' && depth === 0) break;
        j += 1;
      }
      state.out.push(...source.slice(i, Math.min(j + 1, n)).split(''));
      state.i = Math.min(j + 1, n);
      lastSignificant = '`';
      continue;
    }
    // Best-effort regex-literal detection: `/` after an operator/keyword is a regex.
    if (char === '/' && /[=(,:[!&|?{};+\-*%~^<>]|^$/.test(lastSignificant) && lastSignificant !== ')') {
      let j = i + 1;
      let inClass = false;
      let closed = false;
      while (j < n) {
        const c = source[j];
        if (c === '\\') {
          j += 2;
          continue;
        }
        if (c === '\n') break;
        if (c === '[') inClass = true;
        else if (c === ']') inClass = false;
        else if (c === '/' && !inClass) {
          closed = true;
          j += 1;
          break;
        }
        j += 1;
      }
      if (closed) {
        while (j < n && /[a-z]/.test(source[j] ?? '')) j += 1;
        state.out.push(...source.slice(i, j).split(''));
        state.i = j;
        lastSignificant = '/';
        continue;
      }
    }
    state.out.push(char);
    state.i += 1;
    if (!/\s/.test(char)) lastSignificant = char;
  }
  return state.out.join('');
}

/** Blank out `--` and `/* *\/` comments in SQL / Prisma. */
export function maskSqlComments(source: string): string {
  const state: MaskState = { out: [], i: 0 };
  const n = source.length;
  while (state.i < n) {
    const i = state.i;
    const char = source[i] ?? '';
    const next = source[i + 1] ?? '';
    if (char === '-' && next === '-') {
      let end = source.indexOf('\n', i);
      if (end === -1) end = n;
      pushMasked(state, source, i, end);
      continue;
    }
    if (char === '/' && next === '*') {
      const end = source.indexOf('*/', i + 2);
      pushMasked(state, source, i, end === -1 ? n : end + 2);
      continue;
    }
    if (char === "'" || char === '"' || char === '`') {
      let j = i + 1;
      while (j < n) {
        const c = source[j];
        if (c === '\\') {
          j += 2;
          continue;
        }
        if (c === char) {
          if (source[j + 1] === char) {
            j += 2;
            continue;
          }
          break;
        }
        j += 1;
      }
      state.out.push(...source.slice(i, Math.min(j + 1, n)).split(''));
      state.i = Math.min(j + 1, n);
      continue;
    }
    state.out.push(char);
    state.i += 1;
  }
  return state.out.join('');
}

/** Blank out `#` comments in shell / YAML / TOML / dotenv / Dockerfile. */
export function maskHashComments(source: string): string {
  const state: MaskState = { out: [], i: 0 };
  const n = source.length;
  while (state.i < n) {
    const i = state.i;
    const char = source[i] ?? '';
    if (char === '#') {
      let end = source.indexOf('\n', i);
      if (end === -1) end = n;
      pushMasked(state, source, i, end);
      continue;
    }
    if (char === '"' || char === "'") {
      let j = i + 1;
      while (j < n) {
        const c = source[j];
        if (c === '\\') {
          j += 2;
          continue;
        }
        if (c === char || c === '\n') break;
        j += 1;
      }
      state.out.push(...source.slice(i, Math.min(j + 1, n)).split(''));
      state.i = Math.min(j + 1, n);
      continue;
    }
    state.out.push(char);
    state.i += 1;
  }
  return state.out.join('');
}

/** Blank out Python/Ruby `#` comments (strings preserved). */
export const maskPythonComments = maskHashComments;

/**
 * Pick the right comment masker for a language. Markdown, HTML and JSON are
 * returned untouched on purpose: hidden instructions inside HTML comments are
 * exactly what the agent-integrity rules need to see.
 */
export function maskComments(source: string, language: Language): string {
  switch (language) {
    case 'typescript':
    case 'javascript':
    case 'jsx':
    case 'vue':
    case 'svelte':
    case 'java':
    case 'go':
    case 'rust':
    case 'css':
      return maskCStyleComments(source);
    case 'sql':
    case 'prisma':
      return maskSqlComments(source);
    case 'python':
    case 'ruby':
    case 'shell':
    case 'yaml':
    case 'toml':
    case 'dotenv':
    case 'terraform':
    case 'dockerfile':
      return maskHashComments(source);
    case 'php':
      return maskCStyleComments(source);
    default:
      return source;
  }
}

/** Indentation-preserving trim used for snippets in reports. */
export function trimSnippet(line: string, max = 200): string {
  const collapsed = line.replace(/\t/g, '    ').trimEnd();
  const trimmed = collapsed.trimStart();
  if (trimmed.length <= max) return trimmed;
  return `${trimmed.slice(0, max - 1)}…`;
}

/** Join a window of source lines around `line` (1-based) for context blocks. */
export function contextWindow(lines: string[], line: number, radius = 2): string[] {
  const start = Math.max(0, line - 1 - radius);
  const end = Math.min(lines.length, line + radius);
  return lines.slice(start, end);
}

/**
 * Extract a balanced `{...}` / `(...)` block starting at `openIndex`.
 * Returns the slice (inclusive of both braces) or an empty string.
 */
export function balancedBlock(source: string, openIndex: number, open = '{', close = '}'): string {
  if (source[openIndex] !== open) return '';
  let depth = 0;
  for (let i = openIndex; i < source.length; i += 1) {
    const char = source[i];
    if (char === open) depth += 1;
    else if (char === close) {
      depth -= 1;
      if (depth === 0) return source.slice(openIndex, i + 1);
    }
  }
  return source.slice(openIndex, Math.min(source.length, openIndex + 400));
}

/** Find the offset of the first `{` at/after `from`. */
export const nextBrace = (source: string, from: number): number => {
  const index = source.indexOf('{', from);
  return index === -1 ? source.length : index;
};

/** Naive but effective "is this a dynamic string?" probe for injection rules. */
export const looksDynamic = (fragment: string): boolean =>
  /\$\{|\+\s*[A-Za-z_$"']|[A-Za-z_$"']\s*\+\s*|%\s*\(|\.format\(|f"|f'|\{\s*\d+\s*\}/.test(fragment);
