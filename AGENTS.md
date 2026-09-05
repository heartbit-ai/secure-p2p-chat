# Project agent instructions

## GraphPact development lifecycle

This project is **managed with GraphPact**. Non-trivial work must go through a lifecycle
contract under `.lifecycle/changes/`.

- Use the `development-lifecycle` skill for ambiguous, cross-component, public-interface,
  architectural, security-sensitive, stateful, destructive, or production changes.
- Skip lifecycle artifacts for clearly local, low-risk changes.
- For structured or critical work, keep one contract at
  `.lifecycle/changes/<id>/change.json` and validate it with
  `python3 .lifecycle/check.py <path>` (add `--repo .` before completion).
- Keep contracts concise. Git is the history; do not create a parallel attempt log.
- Classify every contract with `project.field`. Treat a change as brownfield unless
  it is a new isolated component with no existing behavior to preserve. Brownfield
  contracts must record a baseline revision, frozen invariants, and at least one
  continuity check that pins existing behavior; greenfield contracts omit them. See
  the lifecycle skill's brownfield continuity reference.
- After bootstrap, prefer **brownfield** contracts that freeze the HTTP peer protocol,
  crypto labels (`p2p-chat-send-v1` / `p2p-chat-recv-v1`), and Tauri command names as
  invariants unless the change explicitly versions them.
- Use dependency graphs only when at least three meaningful work units justify one.
- Grill structured and critical changes before locking the contract: explore first,
  ask only for user-only inputs, run a short pre-mortem, and let the grill's output
  define the acceptance, invariants, and the division into lots (`tasks`).
- Select `sequential`, `parallel-read`, or `parallel-worktrees` from those lots.
  Parallel writes require an approved contract, independent tasks, disjoint mutable
  scopes, local verification, one recorded Git base, and real worktree isolation;
  otherwise stay sequential.
- When `parallel-worktrees` is selected, follow the lifecycle skill's conditional
  worktree reference. Keep one integration owner and do not assume ordinary Codex
  CLI subagents have separate checkouts.
- Graphify is an optional navigation aid. If it is already available, use it for
  multi-hop or blast-radius analysis and verify important inferred edges in the code.
  Propose installing it only when the user wants that depth; never interrupt work to
  set up third-party tooling on your own initiative.
- Treat full-access or YOLO tool permissions as execution capability, not approval for
  production, destructive, paid, or externally visible actions.

## Verification

- Follow existing conventions, avoid speculative abstractions and unrelated
  refactors, and do not leave placeholders, false success paths, swallowed errors,
  permanent test doubles, debug code, or dead code.
- Never weaken tests, types, linters, security controls, or error handling merely
  to make a change pass.
- Run relevant repository checks and inspect the final diff.
- Report commands, exit codes, and remaining uncertainty. Claims are not evidence.
