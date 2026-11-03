import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { buildAppConfig, parseArgv } from '../../src/cli.js';
import { loadConfig } from '../../src/config/loader.js';
import { ConfigNotFoundError } from '../../src/errors.js';

vi.mock('../../src/config/loader.js', () => ({
  loadConfig: vi.fn(),
  getConfigPath: () => '/missing/config.toml',
}));

beforeEach(() => {
  vi.stubEnv('SSH_MCP_SUDO', '');
  vi.mocked(loadConfig).mockRejectedValue(new ConfigNotFoundError('/missing/config.toml'));
});

afterEach(() => vi.unstubAllEnvs());

describe('automatic sudo CLI option', () => {
  it.each(['true', '1'])('enables sudo from SSH_MCP_SUDO=%s', async (value) => {
    vi.stubEnv('SSH_MCP_SUDO', value);
    const config = await buildAppConfig(parseArgv(['--host=localhost', '--user=deploy', '--group=dev']));
    expect(config.profiles[0].sudo).toBe(true);
  });

  it.each(['false', '0', ''])('disables sudo from SSH_MCP_SUDO=%j', async (value) => {
    vi.stubEnv('SSH_MCP_SUDO', value);
    const config = await buildAppConfig(parseArgv(['--host=localhost', '--user=deploy', '--group=dev']));
    expect(config.profiles[0].sudo).toBe(false);
  });

  it('gives an explicit CLI setting priority over the environment', async () => {
    vi.stubEnv('SSH_MCP_SUDO', 'true');
    const config = await buildAppConfig(parseArgv([
      '--host=localhost', '--user=deploy', '--group=dev', '--sudo=false',
    ]));
    expect(config.profiles[0].sudo).toBe(false);
  });

  it('keeps a loaded TOML profile authoritative', async () => {
    vi.stubEnv('SSH_MCP_SUDO', 'true');
    const fileConfig = { defaults: {}, profiles: [{ name: 'file-profile', sudo: false }] };
    vi.mocked(loadConfig).mockResolvedValue(fileConfig as Awaited<ReturnType<typeof loadConfig>>);
    const config = await buildAppConfig(parseArgv(['--config=/existing/config.toml']));
    expect(config).toBe(fileConfig);
    expect(config.profiles[0].sudo).toBe(false);
  });

  it.each([
    [[], false],
    [['--sudo'], true],
    [['--sudo=true'], true],
    [['--sudo=false'], false],
    [['--sudo=0'], false],
  ])('passes %j through to the profile', async (flags, expected) => {
    const config = await buildAppConfig(parseArgv([
      '--host=localhost', '--user=deploy', '--group=dev', ...flags,
    ]));
    expect(config.profiles[0].sudo).toBe(expected);
    expect(config.profiles[0].user).toBe('deploy');
    expect(config.profiles[0].approvalPolicy).toBe('ask-destructive');
  });
});
