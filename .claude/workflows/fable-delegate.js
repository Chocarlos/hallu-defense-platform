export const meta = {
  name: 'fable-delegate',
  description: 'Delegate one scoped repository task to Fable in an isolated worktree',
  whenToUse: 'Use when Codex needs a Claude Fable teammate for a bounded repository task.',
  phases: [
    { title: 'Delegate', detail: 'Run one Fable agent with git worktree isolation', model: 'fable' },
  ],
}

const task = typeof args?.task === 'string' ? args.task.trim() : ''
if (!task) {
  throw new Error('Pass args.task with the exact delegated task.')
}

const mode = args?.mode === 'write' ? 'write' : 'read'
const validation =
  typeof args?.validation === 'string' && args.validation.trim()
    ? args.validation.trim()
    : 'Run the smallest deterministic validation that proves the delegated result.'

phase('Delegate')

const prompt = `You are Claude Fable 5 working as a scoped teammate on this enterprise anti-hallucination repository.

Task:
${task}

Mode:
${mode}

Repository rules:
- Read AGENTS.md, docs/PLAN_MASTER.md, docs/TRACEABILITY_MATRIX.md, and docs/WORKLOG.md before making changes.
- Keep edits tightly scoped to the delegated task.
- Do not use destructive git commands, do not weaken security defaults, do not delete or weaken tests, and do not log secrets or sensitive payloads.
- You are not alone in the codebase. Work with existing changes and do not revert changes you did not make.
- If mode is "read", do not edit files.
- If mode is "write", implement only the delegated slice, add or update focused tests, and update docs only when required by repository rules.

Expected validation:
${validation}

Return a concise integration report. Include changed files, validation commands and outcomes, residual risks, and any notes Codex needs before integrating your work.`

const result = await agent(prompt, {
  label: 'fable-delegate',
  phase: 'Delegate',
  model: 'fable',
  effort: 'max',
  isolation: 'worktree',
  schema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      success: { type: 'boolean' },
      mode: { type: 'string' },
      cwd: { type: 'string' },
      summary: { type: 'string' },
      changedFiles: {
        type: 'array',
        items: { type: 'string' },
      },
      validation: {
        type: 'array',
        items: {
          type: 'object',
          additionalProperties: false,
          properties: {
            command: { type: 'string' },
            outcome: { type: 'string' },
          },
          required: ['command', 'outcome'],
        },
      },
      risks: {
        type: 'array',
        items: { type: 'string' },
      },
      integrationNotes: { type: 'string' },
    },
    required: [
      'success',
      'mode',
      'cwd',
      'summary',
      'changedFiles',
      'validation',
      'risks',
      'integrationNotes',
    ],
  },
})

return result
