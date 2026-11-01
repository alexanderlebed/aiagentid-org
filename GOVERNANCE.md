# Governance

## Today

- **Standard:** Agent ID 1.0, maintained by its author, Alexander Lebed. Changes are published as new versions; a published version is never edited.
- **Registry:** aiagentid.org, operated from this public repository. Its signing key is listed at `/.well-known/aiid-registry.json`; keys are added, never removed.
- **Operator of the first agents:** LARZEQ, the author's company, registers its own agents through the same public process and the same rules as anyone else.

## What keeps the registry honest

- Every record and every change is in an append-only, hash-chained log; anyone can replay it (`tools/aiid.py verify-log`).
- The head of the log is anchored in Bitcoin, so the registry cannot rewrite its own past.
- A number is never reused or reassigned. A record can be suspended or revoked, never erased.
- Anyone can publish a self-declared record on their own domain without asking the registry.

## Contributions

Criticism, implementations and proposals are welcome as issues or pull requests. Registration requests: `register.html`.

## Later

If other parties adopt the format, the standard and the registry key are meant to pass to a neutral body: a working group or a foundation. Until then, the author is responsible for both, publicly.
