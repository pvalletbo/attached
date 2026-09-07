# AGENTS.md

## Project documentation

The .md files of these documents are written by humans only, unless specifically stated in the document itself. 
Any collaboration from an AI agent must no result in updating, or creating, .md documents unless
explicitly told by the human operator. In that case, the document must state that an AI agent has
contributed to the document. 

## Agentic contributions

This section was updated with AI assistance.

### Branch and worktree selection

Before modifying any files, check the current branch and determine
whether the request continues unmerged work or starts a new change.

- Never modify files on `main` unless the human explicitly authorizes it.
- For every new feature or standalone fix, create a new worktree and
  branch from `main`. This also applies to documentation and maintenance changes.
- A fix to functionality already merged into `main` is a new change:
  create a new worktree, branch, and PR.
- When the human requests follow-up changes to a feature or fix we are
  currently implementing together, continue in its existing worktree
  and branch and update its existing PR, provided it is still unmerged.
- Once that work has merged, any further changes require a new worktree,
  branch, and PR.
- If it is unclear which ongoing branch the request belongs to, ask
  before editing. Do not default to working on `main`.

### Delivery requirements

For every implementation change, including follow-up fixes:

1. Add or update tests to verify the behavior.
2. Run the relevant tests.
3. Commit using conventional commits and push to the working branch.
4. Create a PR against `main`, or update the existing unmerged PR.
5. Include a brief explanation, test results, and any details needed
   for human review in the PR description.
6. Report the branch, worktree, and PR URL to the human.

For documentation-only changes, review the diff and check formatting instead
of adding or running behavior tests; the remaining delivery steps still apply.

Do not consider the task complete until these steps are done. If a step
is blocked, explain the blocker and what remains.
