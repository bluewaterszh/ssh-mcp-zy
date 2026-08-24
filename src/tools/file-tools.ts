import { z } from 'zod';
import { redactText } from '../guard/redactor.js';
import { shellSingleQuote } from '../guard/sanitizer.js';
import { SftpClient } from '../ssh/sftp.js';
import { TOOL_DESCRIPTIONS as D } from './descriptions.js';
import { commandOutput, syntheticSuccess, textResult } from './results.js';
import type { ToolDeps, Pipeline } from './pipeline.js';

/** SFTP transfer tools. */
export function registerFileTools(
  { server, applyPatchMaxBytes = 16_777_216 }: ToolDeps,
  pipeline: Pipeline,
) {
  const { runAudited } = pipeline;

  // ─── sftp-upload ───────────────────────────────────────────────────────
  server.tool(
    'sftp-upload',
    D["sftp-upload"],
    {
      remotePath: z.string().describe('Remote file path'),
      content: z.string().describe('File content to upload'),
      profile: z.string().optional().describe('Profile name'),
    },
    { destructiveHint: true },
    async ({ remotePath, content, profile }, extra) => {
      return runAudited(
        `sftp:upload ${remotePath}`,
        { toolName: 'sftp-upload', failureClass: 'destructive', profile, extra, synthetic: true },
        async (rt) => {
          await new SftpClient(rt.conn).upload({ remotePath, content });
          return {
            audited: syntheticSuccess(rt.profileName),
            output: textResult(`Uploaded ${content.length} bytes to ${remotePath}`),
          };
        },
      );
    },
  );



  // ─── apply-patch ───────────────────────────────────────────────────────
  server.tool(
    'apply-patch',
    D["apply-patch"],
    {
      patch: z.string().min(1).describe('Unified Git patch content'),
      workdir: z.string().min(1).optional().describe('Repository/work tree directory; defaults to the profile workdir or remote shell directory'),
      check: z.boolean().optional().describe('Validate the patch with git apply --check without modifying files'),
      profile: z.string().optional().describe('Profile name'),
    },
    { destructiveHint: true },
    async ({ patch, workdir, check, profile }, extra) => {
      const bytes = Buffer.byteLength(patch, 'utf8');
      const command = [
        'git',
        workdir ? `-C ${shellSingleQuote(workdir)}` : '',
        'apply',
        check ? '--check' : '',
        '--whitespace=nowarn',
        '-',
      ].filter(Boolean).join(' ');

      return runAudited(
        command,
        {
          toolName: 'apply-patch',
          failureClass: 'safe',
          profile,
          extra,
          synthetic: true,
          preCheck: () => {
            if (bytes > applyPatchMaxBytes) {
              throw new Error(
                `Patch is too large: ${bytes} bytes exceeds applyPatchMaxBytes=${applyPatchMaxBytes}.`,
              );
            }
          },
        },
        async (rt) => {
          // The patch body is SSH stdin, not part of the shell command. That keeps newlines,
          // quotes, backslashes and dollar signs byte-for-byte intact through the command
          // parser/classifier/shell layers that make heredoc-based patching fragile.
          const audited = await rt.conn.exec(rt.command, {
            stdin: patch,
            onProgress: rt.onProgress,
            abortSignal: rt.abortSignal,
          });
          const output = commandOutput(audited);
          if (output.isError) return { audited, output };
          const text = check
            ? `Patch check passed (${bytes} bytes).`
            : `Applied patch (${bytes} bytes).`;
          return { audited, output: textResult(text) };
        },
      );
    },
  );

  // ─── sftp-download ─────────────────────────────────────────────────────
  server.tool(
    'sftp-download',
    D["sftp-download"],
    {
      remotePath: z.string().describe('Remote file path to download'),
      profile: z.string().optional().describe('Profile name'),
    },
    { readOnlyHint: true },
    async ({ remotePath, profile }, extra) => {
      return runAudited(
        `sftp:download ${remotePath}`,
        { toolName: 'sftp-download', failureClass: 'read-only', profile, extra, synthetic: true },
        async (rt) => {
          const data = await new SftpClient(rt.conn).download({ remotePath });
          return {
            audited: syntheticSuccess(rt.profileName),
            output: textResult(redactText(data.toString('utf8'), { entropyScan: true })),
          };
        },
      );
    },
  );
}
