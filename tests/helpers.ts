/**
 * Test helpers: build a throwaway project on disk, run the real engine, and
 * make assertions about findings without ever depending on the repo's own files.
 */

import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import * as path from 'node:path';

import { scanProject, type ScanOptions } from '../src/scanner/engine';
import { createFileContext, detectProject } from '../src/scanner/context';
import type { FileContext, Finding, ProjectContext, ScanResult } from '../src/scanner/types';
import { ALL_RULES, getRule } from '../src/scanner/rules';

export interface TempProject {
  root: string;
  write(relativePath: string, contents: string): string;
  cleanup(): void;
}

/** Create a temporary project directory that cleans itself up. */
export function makeProject(files: Record<string, string> = {}): TempProject {
  const root = mkdtempSync(path.join(tmpdir(), 'vibe-shield-test-'));
  const write = (relativePath: string, contents: string): string => {
    const target = path.join(root, relativePath);
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, contents, 'utf8');
    return target;
  };
  for (const [relativePath, contents] of Object.entries(files)) write(relativePath, contents);
  return {
    root,
    write,
    cleanup: () => {
      try {
        rmSync(root, { recursive: true, force: true });
      } catch {
        // Windows can hold a handle briefly; leaking a temp dir is not a test failure.
      }
    },
  };
}

/** Run the engine against a temp project. */
export async function scan(files: Record<string, string>, options: Partial<ScanOptions> = {}): Promise<ScanResult> {
  const project = makeProject(files);
  try {
    return await scanProject({ rootDir: project.root, useGitIndex: false, ...options });
  } finally {
    project.cleanup();
  }
}

/** Findings for one rule id. */
export const byRule = (result: ScanResult, ruleId: string): Finding[] =>
  result.findings.filter((finding) => finding.ruleId === ruleId);

/** Assert that a rule fires, and return its findings. */
export function expectRule(result: ScanResult, ruleId: string): Finding[] {
  const findings = byRule(result, ruleId);
  if (!findings.length) {
    const seen = result.findings.map((finding) => `${finding.ruleId} ${finding.filePath}:${finding.line}`).join('\n  ') || '(none)';
    throw new Error(`expected ${ruleId} to fire, but only found:\n  ${seen}`);
  }
  return findings;
}

/** Assert that a rule does not fire. */
export function expectNoRule(result: ScanResult, ruleId: string): void {
  const findings = byRule(result, ruleId);
  if (findings.length) {
    const detail = findings.map((finding) => `${finding.filePath}:${finding.line} ${finding.message}`).join('\n  ');
    throw new Error(`expected ${ruleId} NOT to fire, but got:\n  ${detail}`);
  }
}

/**
 * Build a `FileContext` for a single in-memory file without touching disk.
 * Used by unit tests that target one rule in isolation.
 */
export async function makeContext(
  relativePath: string,
  content: string,
  project?: ProjectContext,
): Promise<FileContext> {
  const root = mkdtempSync(path.join(tmpdir(), 'vibe-shield-ctx-'));
  const absolutePath = path.join(root, relativePath);
  mkdirSync(path.dirname(absolutePath), { recursive: true });
  writeFileSync(absolutePath, content, 'utf8');
  try {
    const resolved = project ?? (await detectProject(root, { readGitIndex: false }));
    return createFileContext(absolutePath, root, content, resolved);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

/** Rule ids that exist in the catalogue (for the coverage test). */
export const ruleIds = (): string[] => ALL_RULES.map((rule) => rule.id);

export { ALL_RULES, getRule, scanProject };
