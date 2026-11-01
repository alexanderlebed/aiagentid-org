# Roadmap

Where Agent ID stands, and what comes next. Nothing below is promised by a date.

## Done — Standard 1.0 (October 2026)

- One-page standard: identifier, record, signature, log, status, attribution, private principals, self-declared records, how an agent presents its ID.
- A public registry at aiagentid.org: signed records, an append-only log, the head anchored in Bitcoin.
- Verification by anyone, in the browser or with one open script (`tools/aiid.py`).
- The first platform registering its agents automatically (LARZEQ).

## Next

1. **Agents present their ID where they act.** E-mail header `Agent-ID`, the A2A agent card field `agent_id`.
2. **Proof that the agent in front of you is the registered one.** Today a ✓ proves the record, not the speaker. The direction: records list the channels the agent speaks from (addresses, domains), so a letter signed by its domain (DKIM) and carrying its ID can be matched to the record.
3. **A Verifiable Credential form of the record**, for systems built on W3C VCs.
4. **More than one operator.** Other platforms registering their agents; registries other than aiagentid.org following the same format.
5. **Independent stewardship** of the standard and the registry key (see GOVERNANCE.md).

## Not planned

Rating or certifying behaviour; logging anyone in or granting access; anything that needs a wallet or a particular blockchain.
