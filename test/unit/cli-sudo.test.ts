import { beforeEach, describe, expect, it, vi } from 'vitest';
import { buildAppConfig, parseArgv } from '../../src/cli.js';
import { loadConfig } from '../../src/config/loader.js';
import { ConfigNotFoundError } from '../../src/errors.js';

vi.mock('../../src/config/loader.js', () => ({
  loadConfig: vi.fn(),
  getConfigPath: () => '/missing/config.toml',
}));

beforeEach(() => {
  vi.mocked(loadConfig).mockRejectedValue(new ConfigNotFoundError('/missing/config.toml'));
});

describe('automatic sudo CLI option', () => {
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
