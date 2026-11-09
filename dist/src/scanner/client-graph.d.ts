export interface SourceModule {
    path: string;
    code: string;
}
interface AliasConfig {
    baseUrl?: string;
    paths?: Record<string, string[]>;
}
/** Resolve relative and root tsconfig/jsconfig path aliases, then follow imports transitively. */
export declare function clientReachableModules(modules: readonly SourceModule[], config?: AliasConfig): string[];
export {};
