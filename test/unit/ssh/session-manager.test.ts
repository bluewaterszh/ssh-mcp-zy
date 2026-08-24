import { describe, it, expect } from 'vitest';
import { EventEmitter } from 'events';
import { SessionManager } from '../../../src/ssh/session-manager.js';
import type { Profile } from '../../../src/types.js';

const profile: Profile = {
  name: 'p', host: 'h', port: 22, user: 'u', auth: 'agent', tty: false,
  timeout: 60_000, maxChars: 5000, maxOutputBytes: 1024, role: 'admin',
  readOnly: false, approvalPolicy: 'auto', cert: false, sessionMaxPerConnection: 5,
  sessionIdleTimeoutMs: 60_000, sessionBackgroundMaxMs: 3_600_000, commandQuotaPerDay: 0,
};

function fakeChannel() {
  return Object.assign(new EventEmitter(), { end() {}, signal() {}, writable: true, outgoing: { state: 'open' } }) as any;
}

describe('SessionManager disconnect cleanup', () => {
  it('releases session slots immediately when the SSH transport disconnects', async () => {
    const oldStream = fakeChannel();
    let nextStream = oldStream;
    const manager = new SessionManager({
      profile: () => profile,
      openShell: async () => fakeChannel(),
      openExec: async () => nextStream,
      onChannelOpened() { return () => {}; },
    });

    const oldSession = await manager.open({ name: 'work', type: 'background', command: 'sleep 1' });
    expect(manager.size).toBe(1);

    manager.markAllDisconnected();
    expect(oldSession.status).toBe('disconnected');
    expect(manager.size).toBe(0);

    // Reuse the name immediately. If the old channel reports close late, its guarded
    // handler must not evict this new session.
    const newStream = fakeChannel();
    nextStream = newStream;
    const reopened = await manager.open({ name: 'work', type: 'background', command: 'sleep 1' });
    oldStream.emit('close');

    expect(manager.get('work')).toBe(reopened);
    expect(manager.size).toBe(1);
  });
});
