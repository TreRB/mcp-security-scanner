// Module-level session cache — shared across all MCP sessions.
export const sessionTokens = new Map<string, string>();
export let currentUser: string | null = null;
const userCache: Record<string, any> = {};

export function setToken(sid: string, tok: string) {
  sessionTokens.set(sid, tok);
}
