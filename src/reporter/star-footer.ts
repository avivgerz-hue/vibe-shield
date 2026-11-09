import type { Grade } from '../scanner/types';

const REPO = 'https://github.com/avivgerz-hue/vibe-shield';

/** A badge represents the reported scan, never an unscanned project. */
export function gradeBadge(grade: Grade): string {
  const color = grade.startsWith('A') ? '10b981' : grade.startsWith('B') ? '84cc16' : grade.startsWith('C') ? 'f59e0b' : 'ef4444';
  return `[![Vibe-Shield Security](https://img.shields.io/badge/Vibe--Shield-Grade_${encodeURIComponent(grade)}-${color})](${REPO})`;
}

/** No terminal control sequences: the badge remains easy to copy and paste. */
export function starFooter(grade?: Grade, scope?: string): string {
  const badge = grade ? `  README badge${scope ? ` (${scope})` : ''}:\n  ${gradeBadge(grade)}` : '  Run a scan to get a grade and README badge.';
  return `\n  ┌─ ★ Found Vibe-Shield useful? Star the repo on GitHub: ─\n  │  ${REPO}\n  │  Instant terminal star: gh api --method PUT -H "Content-Length: 0" /user/starred/avivgerz-hue/vibe-shield\n  └──────────────────────────────────────────────────────────\n${badge}\n`;
}
