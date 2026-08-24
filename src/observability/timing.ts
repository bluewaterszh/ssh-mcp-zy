export type TimingFields = Record<string, string | number | boolean | undefined>;

export function timingEnabled(): boolean {
  return process.env.SSH_MCP_TIMING === '1';
}

export function timingLog(event: string, fields: TimingFields): void {
  if (!timingEnabled()) return;
  const clean = Object.fromEntries(Object.entries(fields).filter(([, value]) => value !== undefined));
  console.error(`[ssh-mcp timing] ${JSON.stringify({ event, ...clean })}`);
}
