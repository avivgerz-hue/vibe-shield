import type { Grade } from '../scanner/types';
/** A badge represents the reported scan, never an unscanned project. */
export declare function gradeBadge(grade: Grade): string;
/** No terminal control sequences: the badge remains easy to copy and paste. */
export declare function starFooter(grade?: Grade, scope?: string): string;
