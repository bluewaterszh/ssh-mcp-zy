import { z } from 'zod';
import { TextDecoder } from 'util';
import { redactText } from '../guard/redactor.js';
import { shellSingleQuote } from '../guard/sanitizer.js';
import { SftpClient } from '../ssh/sftp.js';
import { TOOL_DESCRIPTIONS as D } from './descriptions.js';
import { commandOutput, syntheticSuccess, textResult } from './results.js';
import type { ToolDeps, Pipeline } from './pipeline.js';

function countOccurrences(text: string, needle: string): number {
  let count = 0;
  let from = 0;
  while (true) {
    const at = text.indexOf(needle, from);
    if (at === -1) return count;
    count++;
    if (count > 1) return count;
    from = at + needle.length;
  }
}

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



  // ─── edit-file ─────────────────────────────────────────────────────────
  server.tool(
    'edit-file',
    D["edit-file"],
    {
      edits: z.array(z.object({
        path: z.string().min(1).describe('Remote file path'),
        oldText: z.string().min(1).describe('Exact text that must occur once'),
        newText: z.string().describe('Replacement text'),
      })).min(1).max(128).describe('Exact replacements, applied in order'),
      check: z.boolean().default(false).describe('Validate every replacement without writing files'),
      profile: z.string().optional().describe('Profile name'),
    },
    { destructiveHint: true },
    async ({ edits, check, profile }, extra) => {
      const payloadBytes = edits.reduce(
        (n, e) => n + Buffer.byteLength(e.path) + Buffer.byteLength(e.oldText) + Buffer.byteLength(e.newText),
        0,
      );
      const paths = [...new Set(edits.map((e) => e.path))];
      const auditCommand = `sftp:edit ${paths.map((p) => JSON.stringify(p)).join(' ')}`;

      return runAudited(
        auditCommand,
        {
          toolName: 'edit-file', failureClass: 'destructive', profile, extra, synthetic: true,
          preCheck: () => {
            if (payloadBytes > applyPatchMaxBytes) {
              throw new Error(
                `Edit payload is too large: ${payloadBytes} bytes exceeds applyPatchMaxBytes=${applyPatchMaxBytes}.`,
              );
            }
          },
        },
        async (rt) => {
          const sftp = new SftpClient(rt.conn);
          const decoder = new TextDecoder('utf-8', { fatal: true });
          const files = new Map<string, { original: string; content: string; mode: number }>();
          let loadedBytes = 0;

          for (const edit of edits) {
            let file = files.get(edit.path);
            if (!file) {
              const stat = await sftp.stat(edit.path);
              if (!stat.isFile) throw new Error(`edit-file only supports regular files: ${edit.path}`);
              loadedBytes += stat.size;
              if (loadedBytes > applyPatchMaxBytes) {
                throw new Error(
                  `Files selected for editing exceed the ${applyPatchMaxBytes} byte in-memory limit.`,
                );
              }
              const data = await sftp.download({ remotePath: edit.path, maxBytes: applyPatchMaxBytes });
              let content: string;
              try {
                content = decoder.decode(data);
              } catch {
                throw new Error(`edit-file only supports UTF-8 text files: ${edit.path}`);
              }
              file = { original: content, content, mode: stat.mode & 0o7777 };
              files.set(edit.path, file);
            }

            const matches = countOccurrences(file.content, edit.oldText);
            if (matches !== 1) {
              throw new Error(
                `Expected oldText to match exactly once in ${edit.path}, found ${matches}. ` +
                'No files were changed.',
              );
            }
            file.content = file.content.replace(edit.oldText, edit.newText);
          }

          const outputBytes = [...files.values()].reduce(
            (n, f) => n + Buffer.byteLength(f.content, 'utf8'), 0,
          );
          if (outputBytes > applyPatchMaxBytes) {
            throw new Error(
              `Edited files would occupy ${outputBytes} bytes, exceeding the ${applyPatchMaxBytes} byte limit.`,
            );
          }

          if (check) {
            return {
              audited: syntheticSuccess(rt.profileName),
              output: textResult(`Edit check passed (${edits.length} replacements across ${files.size} files).`),
            };
          }

          const attempted: string[] = [];
          try {
            for (const [path, file] of files) {
              attempted.push(path);
              await sftp.upload({ remotePath: path, content: file.content, mode: file.mode });
            }
          } catch (err) {
            const rollbackErrors: string[] = [];
            for (const path of [...attempted].reverse()) {
              const file = files.get(path)!;
              try {
                await sftp.upload({ remotePath: path, content: file.original, mode: file.mode });
              } catch (rollbackErr) {
                rollbackErrors.push(
                  `${path}: ${rollbackErr instanceof Error ? rollbackErr.message : String(rollbackErr)}`,
                );
              }
            }
            const cause = err instanceof Error ? err.message : String(err);
            throw new Error(
              `edit-file write failed: ${cause}.` +
              (rollbackErrors.length
                ? ` Rollback was incomplete: ${rollbackErrors.join('; ')}`
                : ' Previously attempted files were rolled back.'),
            );
          }

          return {
            audited: syntheticSuccess(rt.profileName),
            output: textResult(`Applied ${edits.length} replacements across ${files.size} files.`),
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
      patch: z.string().min(1).describe(
        'Standard unified Git diff accepted by git apply (diff --git / --- +++ / @@). ' +
        'Do NOT use the Codex *** Begin Patch / *** Update File dialect; use edit-file for precise text edits.',
      ),
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
        '--recount',
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
