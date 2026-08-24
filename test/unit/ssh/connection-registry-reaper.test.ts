import { describe, it, expect, vi } from 'vitest';
import { ConnectionRegistry } from '../../../src/ssh/connection-registry.js';
import type { AppConfig, Profile } from '../../../src/types.js';

const profile = {
  name: 'p', host: 'h', port: 22, user: 'u', auth: 'password', group: 'dev', tty: false,
  timeout: 60_000, maxChars: 1000, maxOutputBytes: 1024, role: 'admin', readOnly: false,
  approvalPolicy: 'auto', cert: false, sessionMaxPerConnection: 5, sessionIdleTimeoutMs: 60_000,
  sessionBackgroundMaxMs: 3_600_000, commandQuotaPerDay: 0,
} as Profile;

function config(): AppConfig {
  return {
    defaults: {
      defaultProfile: 'p', sessionMaxPerConnection: 5, sessionIdleTimeoutMs: 60_000,
      sessionBackgroundMaxMs: 3_600_000, commandTimeoutMs: 60_000,
      commandMaxChars: 1000, commandMaxOutputBytes: 1024, httpMaxBodyBytes: 1024,
      httpSessionIdleTimeoutMs: 60_000, applyPatchMaxBytes: 1024,
      connectionIdleReapMs: 1000, commandQuotaPerDay: 0, approvalGrantTtlMs: 0,
      approvalMode: 'auto',
    },
    profiles: [profile],
  };
}

describe('ConnectionRegistry idle reaper', () => {
  it('does not close a connection while a command channel is active', () => {
    const registry = new ConnectionRegistry(config(), 'insecure');
    const close = vi.fn(async () => {});
    const fake = {
      toInfo: () => ({
        profile: 'p', host: 'h', port: 22, user: 'u', status: 'connected',
        sessionCount: 0, activeChannels: 1, lastActivity: new Date(Date.now() - 10_000),
      }),
      close,
    };
    (registry as any).connections.set('p', fake);

    registry.reapIdleConnections();
    expect(close).not.toHaveBeenCalled();
    expect((registry as any).connections.has('p')).toBe(true);
  });

  it('still reaps a genuinely idle connection', () => {
    const registry = new ConnectionRegistry(config(), 'insecure');
    const close = vi.fn(async () => {});
    const fake = {
      toInfo: () => ({
        profile: 'p', host: 'h', port: 22, user: 'u', status: 'connected',
        sessionCount: 0, activeChannels: 0, lastActivity: new Date(Date.now() - 10_000),
      }),
      close,
    };
    (registry as any).connections.set('p', fake);

    registry.reapIdleConnections();
    expect(close).toHaveBeenCalledTimes(1);
    expect((registry as any).connections.has('p')).toBe(false);
  });
});
