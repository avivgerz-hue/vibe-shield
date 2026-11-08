# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | ✅ |
| < 1.0 | ❌ |

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Email **security@vibefoundry.dev** with:

- a description of the issue and its impact
- the affected version (`npx github:avivgerz-hue/vibe-shield version`)
- a minimal reproduction (a snippet, a repository, or a failing test)
- whether you intend to publish, and any deadline you are working to

You get an acknowledgement within **48 hours** and a triage decision within
**5 business days**. If the report is valid we will:

1. confirm the severity using the CVSS v3.1 vector,
2. ship a fix in a patch release,
3. publish a GitHub Security Advisory crediting you (unless you prefer to stay
   anonymous),
4. request a CVE if the impact warrants one.

## Security model

vibe-shield is a **static analyser**. It reads files and reports what it finds.
Understanding the trust boundaries matters when you run it on untrusted input.

### What the tool does

| Behaviour | Detail |
| --- | --- |
| Network access | **None.** The runtime has zero dependencies and makes no outbound requests. There is no telemetry, no update check, no crash reporting. |
| Filesystem access | Read-only, confined to the scan root. `--cache` writes one file (`.vibe-shield-cache.json`) to the scan root; `--fix-prompt` and `--out` write exactly the paths you ask for. |
| Subprocesses | One optional `git ls-files` / `git rev-parse` call, used to determine whether a `.env` file is tracked. Disable it with `useGitIndex: false` (API) or by running outside a work tree. |
| Code execution | **None.** Scanned files are never imported, evaluated, executed or served. There is no plugin loading, no `require()` of project code, and no shell invocation derived from file content. |
| Secret handling | Secret values are matched in memory, then **redacted before they reach any output** (`redactSecret`). `SECURITY_PATCH_PROMPT.md`, JSON, SARIF and GitHub annotations all carry the masked form. The raw value never leaves the process. |

### What it deliberately does not do

- It does not resolve dependencies or run a package manager.
- It does not follow symlinks (symlinked entries are skipped, which prevents a
  scan root from being used to read outside the tree).
- It does not scan `node_modules`, build output or `.git` (pruned by name).
- It does not fetch remote rule sets. The rule catalogue is compiled into the
  package and fingerprinted so a cached result can never be reused after a rule
  change (`RULES_FINGERPRINT`).

### Running it on untrusted code

Scanning a hostile repository is safe by design: nothing is executed. The two
things to be aware of are resource-related, not exploit-related:

- **Pathological input.** Rules cap match counts (`20_000` per rule per file),
  brace-block extraction (`8_000` chars), and regex scan windows. Files above
  1.5 MB are skipped. A crafted file can make a rule slow; it cannot make it
  hang indefinitely.
- **Output size.** A repository engineered to produce thousands of findings will
  produce a large report. Use `--severity`, `--max-findings` or `--format
  summary` when the input is not trusted.

### Supply chain

- **Zero runtime dependencies.** There is no transitive package to compromise.
  The only dev dependencies are `typescript` and `vitest` (+ `@vitest/coverage-v8`).
- **Lockfile committed.** CI installs with `npm ci`, not `npm install`.
- **Publishing uses provenance.** The release workflow publishes with
  `--provenance` via GitHub OIDC, so the npm artefact is verifiably built from
  this repository's workflow run.
- **Self-scanning.** CI runs `vibe-shield scan --fail-on high` and
  `vibe-shield audit-skills --fail-on high` against this repository on every
  push. The detector catalogue is the only excluded path, documented in
  [`.vibe-shieldignore`](./.vibe-shieldignore).

### Known limitations (not vulnerabilities)

- **Static by design.** Dynamic dispatch, metaprogramming and code generated at
  runtime can hide a vulnerable shape from any static rule.
- **Heuristics have false positives.** Every rule is conservative about the
  legitimate patterns it knows (see the FAQ in the README), but a novel
  framework can still produce a finding that is not exploitable. That is a bug
  report, not a security issue — please open a normal issue.
- **The auditor reads prose.** `audit-skills` flags dangerous *language* in
  instruction files. It distinguishes prohibitions from instructions and
  documentation from commands, but an adversarially worded skill can still
  evade a regex. It is a tripwire, not a sandbox; the real defence is not
  installing skills you have not read.

## Scope

In scope:

- a rule that crashes, hangs, or reads outside the scan root
- a secret value appearing unredacted in any output stream or file
- command injection or path traversal through CLI arguments
- a `--fix-prompt` / `--out` write escaping the intended directory
- npm publish / release workflow compromise

Out of scope:

- false positives on unusual framework patterns (open a normal issue)
- false negatives on obfuscated code (static analysis is not a sandbox)
- findings in *your* repository that vibe-shield reported correctly
- vulnerabilities in `npx`'s own resolution behaviour
