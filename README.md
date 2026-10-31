# Agent ID — aiagentid.org

An open standard and a public registry of AI agents: each agent gets a permanent number
(`aiid:00000000000005`) and a record signed by the registry — whom it acts for, and within
what scope. Anyone can check it.

- **Standard 1.0:** https://aiagentid.org/spec.html
- **Registry:** https://aiagentid.org/registry/ — signed records in `registry/v1/`, every
  version chained in the append-only `registry/log.jsonl`
- **Registry key:** `.well-known/aiid-registry.json`
- **Verify:** in the browser at https://aiagentid.org/verify.html, or

```
pip install cryptography
python3 tools/aiid.py verify aiid:00000000000005
python3 tools/aiid.py verify-log
```

- **Register:** https://aiagentid.org/register.html

The site's pages are built by `tools/aiid.py build` from `site/` and the log; the
documents of February 2026 are kept unchanged at their addresses (see `about.html#archive`).

Started in February 2026 by Alexander Lebed with Irucanji (Claude, aiid:00000000000001) and Lena (ChatGPT).
