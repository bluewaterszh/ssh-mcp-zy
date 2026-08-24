import { McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js';
import { posix, win32 } from 'path';

const CONTROL_CHARS = /[\r\n\u2028\u2029\x00]/g;
const REMOTE_PATH_CONTROL_CHARS = /[\x00-\x1F\x7F\u2028\u2029]/;
const MAX_REMOTE_PATH_BYTES = 32 * 1024;

export function sanitizeCommand(command: unknown, maxChars: number): string {
  if (typeof command !== 'string') {
    throw new McpError(ErrorCode.InvalidParams, 'Command must be a string');
  }
  const cleaned = command.replace(CONTROL_CHARS, ' ').trim();
  if (!cleaned) {
    throw new McpError(ErrorCode.InvalidParams, 'Command cannot be empty');
  }
  if (Number.isFinite(maxChars) && cleaned.length > maxChars) {
    throw new McpError(ErrorCode.InvalidParams, `Command is too long (max ${maxChars} characters)`);
  }
  return cleaned;
}

export function sanitizeSessionName(name: string): string {
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(name)) {
    throw new McpError(
      ErrorCode.InvalidParams,
      'Session name must be 1-64 chars, alphanumeric/dash/underscore only',
    );
  }
  return name;
}

export function validateRemotePath(path: unknown, field = 'Remote path'): string {
  if (typeof path !== 'string' || path.length === 0) {
    throw new McpError(ErrorCode.InvalidParams, `${field} must be a non-empty string`);
  }
  // SFTP paths are not shell commands, so characters such as spaces, quotes,
  // semicolons and dollar signs are valid and must not be "sanitized" away.
  // Control characters are different: they make logs/audit text ambiguous and
  // can split protocol/command contexts when the same path is later quoted.
  if (REMOTE_PATH_CONTROL_CHARS.test(path)) {
    throw new McpError(ErrorCode.InvalidParams, `${field} must not contain control characters`);
  }
  const bytes = Buffer.byteLength(path, 'utf8');
  if (bytes > MAX_REMOTE_PATH_BYTES) {
    throw new McpError(
      ErrorCode.InvalidParams,
      `${field} is too long (${bytes} bytes; max ${MAX_REMOTE_PATH_BYTES})`,
    );
  }
  // Validation deliberately preserves the input byte-for-byte. Path resolution
  // is a separate step because it needs the profile workdir and remote path style.
  return path;
}

const WINDOWS_DRIVE_ABSOLUTE = /^[A-Za-z]:[\\/]/;
const WINDOWS_UNC_ABSOLUTE = /^(?:\\\\|\/\/)[^\\/]+[\\/][^\\/]+(?:[\\/]|$)/;

function isWindowsAbsolute(path: string): boolean {
  return WINDOWS_DRIVE_ABSOLUTE.test(path) || WINDOWS_UNC_ABSOLUTE.test(path);
}

function normalizeWindowsRemotePath(path: string): string {
  // SFTP on Windows OpenSSH accepts forward slashes. Emitting one canonical
  // separator keeps audit/log output stable while win32 handles drive/UNC/..
  // semantics independently of the OS on which ssh-mcp itself is running.
  return win32.normalize(path).replace(/\\/g, '/');
}

/**
 * Resolve a remote file path without applying the local machine's path rules.
 *
 * Absolute POSIX and Windows paths stay absolute. Relative paths are resolved
 * against the profile workdir when one exists; otherwise they keep SFTP's
 * normal relative-to-server-home semantics. `..` is intentionally allowed:
 * workdir is a convenience CWD, not a sandbox (run-command can `cd ..` too).
 */
export function resolveRemotePath(path: unknown, workdir?: string, field = 'Remote path'): string {
  const input = validateRemotePath(path, field);
  const base = workdir === undefined ? undefined : validateRemotePath(workdir, 'profile workdir');

  if (isWindowsAbsolute(input)) return normalizeWindowsRemotePath(input);
  if (input.startsWith('/')) return posix.normalize(input);

  if (base) {
    if (isWindowsAbsolute(base)) return normalizeWindowsRemotePath(win32.join(base, input));
    if (base.startsWith('/')) return posix.normalize(posix.join(base, input));
    return posix.normalize(posix.join(base, input));
  }

  // Without an explicit workdir, keep SFTP's existing relative semantics while
  // still collapsing harmless ./ and duplicate POSIX separators. Windows SFTP
  // callers can always use canonical C:/... absolute paths.
  return posix.normalize(input);
}

export function shellSingleQuote(s: string): string {
  return `'${s.replace(/'/g, "'\\''")}'`;
}
