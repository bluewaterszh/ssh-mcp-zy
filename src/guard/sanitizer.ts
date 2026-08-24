import { McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js';

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

function windowsSeparators(path: string): string {
  // Windows OpenSSH SFTP accepts forward slashes, and using one separator avoids
  // leaking backslash ambiguity into logs/tool results. Do not collapse dot
  // segments: remote symlinks/junctions can make lexical `..` rewriting change
  // which object the server actually resolves.
  return path.replace(/\\/g, '/');
}

function appendRemote(base: string, relative: string, windows: boolean): string {
  const normalizedBase = windows ? windowsSeparators(base) : base;
  const normalizedRelative = windows ? windowsSeparators(relative) : relative;
  const separator = normalizedBase.endsWith('/') ? '' : '/';
  return normalizedBase + separator + normalizedRelative;
}

/**
 * Resolve a remote file path without applying the local machine's path rules.
 *
 * Absolute POSIX paths stay byte-for-byte intact; Windows absolute paths only
 * canonicalize separators. Relative paths are anchored under profile.workdir
 * when one exists. `.` and `..` are deliberately left for the remote SFTP
 * server to resolve, preserving symlink/junction semantics. workdir is a CWD
 * convenience, not a sandbox (run-command can `cd ..` too).
 */
export function resolveRemotePath(path: unknown, workdir?: string, field = 'Remote path'): string {
  const input = validateRemotePath(path, field);
  const base = workdir === undefined ? undefined : validateRemotePath(workdir, 'profile workdir');

  if (isWindowsAbsolute(input)) return windowsSeparators(input);
  if (input.startsWith('/')) return input;

  if (base) {
    return appendRemote(base, input, isWindowsAbsolute(base));
  }

  // No workdir means normal SFTP relative-to-server-home semantics.
  return input;
}

export function shellSingleQuote(s: string): string {
  return `'${s.replace(/'/g, "'\\''")}'`;
}
