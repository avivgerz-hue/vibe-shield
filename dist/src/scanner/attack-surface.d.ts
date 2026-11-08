import type { AttackSurface, FileContext, ProjectContext } from './types';
export declare const emptyAttackSurface: () => AttackSurface;
export declare function inventoryFile(ctx: FileContext, surface: AttackSurface): void;
export declare function inventoryTables(surface: AttackSurface, project: ProjectContext, scannedPaths: Set<string>): void;
