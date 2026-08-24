import { createHash } from 'crypto';

export const TOOL_DESCRIPTIONS: Record<string, string> = {
  'list-connections': 'List all configured SSH profiles and their connection status. Use this to discover available hosts before running commands.',
  'list-sessions': 'List active sessions for a given SSH profile.',
  'open-session': 'Open a named session on a remote host. The server appends a UUID to the requested name; use the exact returned name for later calls. Use type="interactive" for stateful shell (CWD/env persists between commands) or type="background" for long-running processes.',
  'close-session': 'Close a named session. A background session\'s command is signalled on the host (INT, then TERM, then KILL) before its channel is dropped; an interactive session\'s shell is ended. The response says so if the command could not be signalled or had not stopped in time.',
  'read-session-output': 'Read recent output from an interactive or background session.',
  'read-command': 'Execute a READ-ONLY command from an allowlist (ls, cat, grep, find, stat, df, etc.). This tool does NOT modify the system. Prefer this tool for all read operations.',
  'read-batch': 'Execute up to 64 read-only commands sequentially in one MCP call. Every command is independently policy-checked, quota-counted and audited.',
  'run-command': 'Execute an arbitrary shell command on the remote server. May modify the system. Destructive commands require user approval.',
  'run-batch': 'Execute up to 64 shell commands sequentially in one MCP call. Every command is independently policy-checked, quota-counted and audited.',
  'privileged-command': 'Execute a command with sudo elevation. ALWAYS requires user approval. The sudo password is piped via stdin (never visible in process list).',
  'sftp-upload': 'Upload a file to the remote server via SFTP (secure file transfer, not shell-based).',
  'sftp-download': 'Download a file from the remote server via SFTP.',
  'apply-patch': 'Apply a standard unified Git diff on the remote host via git apply --recount. Patch bytes travel over SSH stdin. Do not use the Codex *** Begin Patch dialect; use edit-file for precise text edits.',
  'edit-file': 'Apply one or more exact oldText-to-newText replacements over SFTP. Every oldText must match exactly once; all edits are validated before any file is written.',
  'signal-process': 'Send a signal (INT, TERM, KILL) to a remote process by PID.',
  'write-session-input': 'Write one policy-checked line to an interactive session and press Enter. Optionally wait briefly and return recent session output in the same MCP call.',
};

export function getToolHashes(): Record<string, string> {
  const hashes: Record<string, string> = {};
  for (const [name, desc] of Object.entries(TOOL_DESCRIPTIONS)) {
    hashes[name] = createHash('sha256').update(desc).digest('hex').slice(0, 16);
  }
  return hashes;
}
