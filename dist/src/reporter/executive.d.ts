import { type ScanResult } from '../scanner/types';
export declare function formatMarkdown(result: ScanResult): string;
/** All project content is escaped. The only script is a fixed local filter. */
export declare function formatHtml(result: ScanResult): string;
