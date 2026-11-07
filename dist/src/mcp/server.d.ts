/**
 * vibe-shield :: Model Context Protocol server
 * -------------------------------------------
 * A zero-dependency MCP server over stdio, so Claude Code, Claude Desktop,
 * Cursor and Codex can call the scanner as a tool instead of shelling out and
 * parsing console output.
 *
 * Transport is newline-delimited JSON-RPC 2.0. Requests are handled in arrival
 * order and every response carries the matching `id`; notifications (no `id`)
 * are never answered, per the JSON-RPC spec.
 *
 * Three tools are exposed:
 *   - `vibe_shield_scan`          run the 60-rule scanner over a project
 *   - `vibe_shield_audit_skills`  audit the agent surface for poisoning
 *   - `vibe_shield_explain_rule`  full CWE + remediation detail for one rule
 *
 * Deliberate design constraints:
 *   - stdout is protocol-only. Diagnostics go to stderr, because a stray
 *     `console.log` corrupts the stream and breaks the client session.
 *   - No request is ever executed against a path outside the client's `roots`
 *     or the server's own cwd tree without an absolute path being explicit.
 *   - Every tool returns `isError` on failure rather than throwing, so a bad
 *     argument degrades one call instead of killing the session.
 */
/** JSON-RPC 2.0 error codes used by this server. */
export declare const RpcError: {
    readonly parseError: -32700;
    readonly invalidRequest: -32600;
    readonly methodNotFound: -32601;
    readonly invalidParams: -32602;
    readonly internalError: -32603;
};
export declare const MCP_PROTOCOL_VERSION = "2025-06-18";
export declare const SERVER_NAME = "vibe-shield";
/** The subset of `InitializeResult` this server advertises. */
export interface McpInitializeResult {
    protocolVersion: string;
    capabilities: {
        tools: {
            listChanged: boolean;
        };
    };
    serverInfo: {
        name: string;
        version: string;
        title: string;
    };
    instructions: string;
}
export interface JsonRpcRequest {
    jsonrpc: '2.0';
    id?: string | number | null;
    method: string;
    params?: Record<string, unknown>;
}
export interface JsonRpcSuccess {
    jsonrpc: '2.0';
    id: string | number | null;
    result: unknown;
}
export interface JsonRpcFailure {
    jsonrpc: '2.0';
    id: string | number | null;
    error: {
        code: number;
        message: string;
        data?: unknown;
    };
}
export type JsonRpcResponse = JsonRpcSuccess | JsonRpcFailure;
/** A single MCP tool description, as returned by `tools/list`. */
export interface McpToolDefinition {
    name: string;
    title: string;
    description: string;
    inputSchema: Record<string, unknown>;
}
export interface McpTextContent {
    type: 'text';
    text: string;
}
export interface McpToolResult {
    content: McpTextContent[];
    structuredContent?: Record<string, unknown>;
    isError?: boolean;
}
/**
 * Tool catalogue. Descriptions are written for a model deciding *whether* to
 * call, not for a human reading docs — they say when to reach for the tool.
 */
export declare const MCP_TOOLS: readonly McpToolDefinition[];
export interface McpServerOptions {
    /** Directory that relative `target` values resolve against. */
    cwd?: string;
    /** Version string reported in `initialize` and scan results. */
    version?: string;
}
/** Execute one tool by name. Never throws: failures become `isError` results. */
export declare function callTool(name: string, args: Record<string, unknown>, options?: McpServerOptions): Promise<McpToolResult>;
/**
 * Handle one decoded JSON-RPC message.
 * Returns `null` for notifications, which the spec forbids answering.
 */
export declare function handleMessage(message: unknown, options?: McpServerOptions): Promise<JsonRpcResponse | null>;
export interface McpServerIo {
    stdin: NodeJS.ReadableStream;
    stdout: {
        write(chunk: string): unknown;
    };
    stderr: {
        write(chunk: string): unknown;
    };
}
export interface McpServeOptions extends McpServerOptions {
    /** Called after the transport stops, with the number of messages handled. */
    onClose?: (handled: number) => void;
}
/**
 * Serve MCP over newline-delimited JSON-RPC until stdin closes.
 *
 * Messages are processed sequentially so responses preserve request order and a
 * slow scan cannot interleave with a later `tools/call`.
 */
export declare function serveMcp(io: McpServerIo, options?: McpServeOptions): Promise<number>;
/** Convenience wrapper used by `vibe-shield mcp`. */
export declare const startMcpServer: (options?: McpServerOptions) => Promise<number>;
export declare const MCP_TOOL_NAMES: readonly ["vibe_shield_scan", "vibe_shield_audit_skills", "vibe_shield_explain_rule"];
