import { describe, it, expect } from 'vitest';
import {
  sanitizeCommand,
  sanitizeSessionName,
  validateRemotePath,
  resolveRemotePath,
} from '../../../src/guard/sanitizer.js';

describe('sanitizeCommand', () => {
  it('trims whitespace', () => {
    expect(sanitizeCommand('  ls -la  ', 1000)).toBe('ls -la');
  });

  it('rejects empty command', () => {
    expect(() => sanitizeCommand('   ', 1000)).toThrow();
  });

  it('rejects command exceeding maxChars', () => {
    expect(() => sanitizeCommand('a'.repeat(1001), 1000)).toThrow();
  });

  it('rejects non-string input', () => {
    expect(() => sanitizeCommand(null as any, 1000)).toThrow();
  });
});

describe('validateRemotePath', () => {
  it('preserves shell metacharacters and path syntax byte-for-byte', () => {
    const path = "../dir with spaces/$HOME;$(not-a-command)/a'b.txt";
    expect(validateRemotePath(path)).toBe(path);
  });

  it.each(['a\nb', 'a\rb', 'a\0b', 'a\tb', 'a\u2028b', 'a\x7fb'])(
    'rejects control characters in %j',
    (path) => expect(() => validateRemotePath(path)).toThrow(/control characters/i),
  );

  it('rejects empty and excessively long paths', () => {
    expect(() => validateRemotePath('')).toThrow(/non-empty/i);
    expect(() => validateRemotePath('x'.repeat(33 * 1024))).toThrow(/too long/i);
  });
});

describe('resolveRemotePath', () => {
  it('resolves POSIX relative paths against the profile workdir', () => {
    expect(resolveRemotePath('./src/../a.ts', '/repo/project')).toBe('/repo/project/./src/../a.ts');
    expect(resolveRemotePath('../shared/a.ts', '/repo/project')).toBe('/repo/project/../shared/a.ts');
  });

  it('preserves and normalizes absolute POSIX paths independently of the local OS', () => {
    expect(resolveRemotePath('/repo//src/../a.ts', 'C:/ignored')).toBe('/repo//src/../a.ts');
  });

  it('handles Windows drive and UNC paths with remote Windows semantics', () => {
    expect(resolveRemotePath('src\\..\\a.ts', 'C:\\repo\\project')).toBe('C:/repo/project/src/../a.ts');
    expect(resolveRemotePath('C:\\repo\\src\\..\\a.ts', '/ignored')).toBe('C:/repo/src/../a.ts');
    expect(resolveRemotePath('\\\\server\\share\\dir\\..\\a.ts')).toBe('//server/share/dir/../a.ts');
  });

  it('keeps relative SFTP semantics when no workdir is configured', () => {
    expect(resolveRemotePath('./dir/../a.ts')).toBe('./dir/../a.ts');
  });
});

describe('sanitizeSessionName', () => {
  it('accepts valid names', () => {
    expect(sanitizeSessionName('deploy-1')).toBe('deploy-1');
    expect(sanitizeSessionName('my_session')).toBe('my_session');
  });

  it('rejects names with special characters', () => {
    expect(() => sanitizeSessionName('session;rm -rf')).toThrow();
    expect(() => sanitizeSessionName('session\nname')).toThrow();
  });

  it('rejects names exceeding 64 chars', () => {
    expect(() => sanitizeSessionName('a'.repeat(65))).toThrow();
  });
});
