#!/usr/bin/env python3
"""aiid — issue, sign and verify Agent ID records (Agent ID Standard 1.0).

    aiid verify aiid:00000000000005      check one record against the registry key
    aiid verify https://x.org/agent.json  check a self-declared record against its own key
    aiid verify-log                       replay the whole registry chain
    aiid keygen my.key                    a key pair for a self-declared record
    aiid sign record.json --key my.key --key-id https://x.org/.well-known/aiid-keys.json#1

Registry operator only:
    aiid issue spec.json --key registry.key --root .
    aiid status aiid:00000000000005 suspended "reason" --key registry.key --root .
    aiid build --root .

Needs Python 3.10+ and `pip install cryptography`.
"""
import argparse
import base64
import datetime as dt
import hashlib
import html
import json
import os
import sys
import urllib.request
from pathlib import Path

REGISTRY = "https://aiagentid.org"
KEYS_URL = REGISTRY + "/.well-known/aiid-registry.json"
STANDARD = "aiid/1.0"
STATUSES = ("active", "suspended", "revoked")


# --- the bytes that are signed -------------------------------------------------------

def canonical(obj) -> bytes:
    """RFC 8785 for the values records hold (strings, integers, booleans, null)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def digest(record: dict) -> str:
    return "sha256:" + hashlib.sha256(canonical(record)).hexdigest()


def unsigned(record: dict) -> dict:
    return {k: v for k, v in record.items() if k != "proof"}


def number(aiid: str) -> str:
    n = aiid.split(":", 1)[-1]
    if not (len(n) == 14 and n.isdigit()):
        raise SystemExit(f"not an Agent ID: {aiid!r}")
    return n


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# --- keys ------------------------------------------------------------------------------

def private_key(path: str):
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    return load_pem_private_key(Path(path).read_bytes(), password=None)


def public_raw(key) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def sign(record: dict, key, key_id: str) -> dict:
    body = unsigned(record)
    return {**body, "proof": {"alg": "Ed25519", "key": key_id,
                              "value": b64(key.sign(canonical(body)))}}


def fetch(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "aiid/1.0"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)


def key_for(key_id: str, keys: dict | None = None) -> bytes:
    """The public key a proof names: <url of a key set>#<id>."""
    url, _, kid = key_id.partition("#")
    keyset = keys if keys is not None and url == KEYS_URL else fetch(url)
    for k in keyset.get("keys", []):
        if k.get("id") == kid and k.get("alg") == "Ed25519":
            return unb64(k["public"])
    raise ValueError(f"no Ed25519 key {kid!r} at {url}")


def check(record: dict, keys: dict | None = None) -> str | None:
    """None when the signature holds; otherwise what is wrong."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    proof = record.get("proof") or {}
    if proof.get("alg") != "Ed25519" or not proof.get("key") or not proof.get("value"):
        return "the record carries no Ed25519 proof"
    try:
        pub = Ed25519PublicKey.from_public_bytes(key_for(proof["key"], keys))
        pub.verify(unb64(proof["value"]), canonical(unsigned(record)))
    except InvalidSignature:
        return "the signature does not match the record: it was changed after signing"
    except Exception as e:                                        # noqa: BLE001
        return f"the key could not be read: {e}"
    return None


# --- the registry on disk --------------------------------------------------------------

class Registry:
    def __init__(self, root: str):
        self.root = Path(root)
        self.v1 = self.root / "registry" / "v1"
        self.log = self.root / "registry" / "log.jsonl"
        self.keys_file = self.root / ".well-known" / "aiid-registry.json"

    def entries(self) -> list[dict]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines() if line.strip()]

    def current(self) -> dict[str, dict]:
        latest = {}
        for e in self.entries():
            latest[e["aiid"]] = e
        return latest

    def keys(self) -> dict:
        return json.loads(self.keys_file.read_text())

    def key_id(self) -> str:
        return KEYS_URL + "#" + self.keys()["keys"][-1]["id"]

    def append(self, record: dict, key) -> dict:
        entries = self.entries()
        record = {**record, "seq": len(entries) + 1,
                  "prev": digest(entries[-1]) if entries else None}
        signed = sign(record, key, self.key_id())
        problem = check(signed, self.keys())
        if problem:
            raise SystemExit(f"refused: {problem} (is this the registry key?)")
        self.v1.mkdir(parents=True, exist_ok=True)
        with self.log.open("a") as f:
            f.write(json.dumps(signed, ensure_ascii=False, sort_keys=True) + "\n")
        return signed

    def next_aiid(self) -> str:
        taken = [int(number(a)) for a in self.current()] + [4]   # 1–4: the records of February
        return f"aiid:{max(taken) + 1:014d}"


def issue(reg: Registry, spec: dict, key) -> dict:
    aiid = spec.get("aiid") or reg.next_aiid()
    number(aiid)
    if aiid in reg.current():
        raise SystemExit(f"{aiid} is already in the registry; use `status` to change it")
    for field in ("name", "kind", "principal", "scope"):
        if not spec.get(field):
            raise SystemExit(f"the spec needs {field!r}")
    stamp = now()
    record = {
        "standard": STANDARD, "aiid": aiid, "version": 1,
        "name": spec["name"], "kind": spec["kind"], "status": "active",
        "principal": spec["principal"], "operator": spec.get("operator"),
        "scope": spec["scope"],
        "registered_at": spec.get("registered_at") or stamp, "updated_at": stamp,
    }
    for extra in ("anchors", "legacy", "contact"):
        if spec.get(extra):
            record[extra] = spec[extra]
    return reg.append(record, key)


def set_status(reg: Registry, aiid: str, status: str, reason: str, key) -> dict:
    if status not in STATUSES:
        raise SystemExit(f"status is one of {', '.join(STATUSES)}")
    old = reg.current().get(aiid)
    if old is None:
        raise SystemExit(f"{aiid} is not in the registry")
    if old["status"] == "revoked":
        raise SystemExit(f"{aiid} is revoked; a revoked identity stays revoked")
    record = {**unsigned(old), "status": status, "status_reason": reason,
              "version": old["version"] + 1, "updated_at": now()}
    return reg.append(record, key)


def verify_log(entries: list[dict], keys: dict) -> list[str]:
    problems, prev = [], None
    for i, e in enumerate(entries, 1):
        if e.get("seq") != i:
            problems.append(f"entry {i}: its seq is {e.get('seq')}")
        if e.get("prev") != prev:
            problems.append(f"entry {i} ({e.get('aiid')}): the chain is broken before it")
        problem = check(e, keys)
        if problem:
            problems.append(f"entry {i} ({e.get('aiid')}): {problem}")
        prev = digest(e)
    return problems


# --- the pages -------------------------------------------------------------------------

def esc(v) -> str:
    return html.escape(str(v if v is not None else ""))


def page(title: str, body: str, desc: str = "", depth: int = 0) -> str:
    up = "../" * depth
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
<meta name="description" content="{esc(desc)}">
<link rel="stylesheet" href="{up}assets/aiid.css">
</head>
<body>
<header class="top"><a class="brand" href="{up}index.html">Agent ID</a>
<nav><a href="{up}registry/index.html">Registry</a><a href="{up}verify.html">Verify</a><a href="{up}register.html">Register</a><a href="{up}spec.html">Standard</a><a href="{up}compare.html">Compare</a><a href="{up}about.html">About</a></nav></header>
<main>
{body}
</main>
<footer>aiagentid.org · open standard and public registry · <a href="https://github.com/alexanderlebed/aiagentid-org">source</a> · <a href="mailto:contact@aiagentid.org">contact@aiagentid.org</a></footer>
</body>
</html>
"""


def who(p: dict | None) -> str:
    if not p:
        return "—"
    if p.get("disclosed") is False:
        kind = "person" if p.get("type") == "human" else p.get("type", "person")
        return f"A private {esc(kind)} (not disclosed)"
    name = esc(p.get("name", "—"))
    if p.get("url"):
        name = f'<a href="{esc(p["url"])}">{name}</a>'
    return f"{name} <span class=dim>({esc(p.get('type', ''))})</span>"


def items(xs) -> str:
    return "".join(f"<li>{esc(x)}</li>" for x in xs or [])


def record_page(r: dict) -> str:
    n = number(r["aiid"])
    s = r["scope"]
    rows = [("Agent ID", f"<code>{esc(r['aiid'])}</code>"), ("Kind", esc(r["kind"])),
            ("Status", f'<span class="st {esc(r["status"])}">{esc(r["status"])}</span>'
             + (f" — {esc(r['status_reason'])}" if r.get("status_reason") else "")),
            ("Principal", who(r["principal"])), ("Operator", who(r.get("operator"))),
            ("Registered", esc(r["registered_at"][:10])),
            ("Version", f"{r['version']} · updated {esc(r['updated_at'][:10])}")]
    if r.get("contact"):
        rows.append(("Contact", esc(r["contact"])))
    for a in r.get("anchors") or []:
        rows.append(("Anchor", f"{esc(a.get('network'))}: <code class=wrap>{esc(a.get('tx'))}</code>"))
    if r.get("legacy"):
        rows.append(("First record", f'<a href="{esc(r["legacy"])}">February 2026 record</a>'))
    table = "".join(f"<tr><th>{k}</th><td>{v}</td></tr>" for k, v in rows)
    lists = ""
    for label, key in (("May", "may"), ("May not", "may_not"), ("Conditions", "conditions")):
        if s.get(key):
            lists += f"<h3>{label}</h3><ul>{items(s[key])}</ul>"
    body = f"""<p class=crumb><a href="../index.html">Registry</a> / {esc(r['aiid'])}</p>
<h1>{esc(r['name'])}</h1>
<p class=lead>{esc(s.get('summary', ''))}</p>
<div class=verify data-record="{n}.json">
<button type=button>Verify this record</button><span class=out>Checks the registry's signature in your browser.</span>
</div>
<table class=rec>{table}</table>
<h2>Delegated scope</h2>
{lists}
<h2>Machine-readable</h2>
<p><a href="{n}.json">{n}.json</a> — signed by the registry key, sequence {r['seq']} in the <a href="../log.jsonl">append-only log</a>.</p>
<script src="../../assets/verify.js"></script>"""
    return page(f"{r['name']} — {r['aiid']}", body, s.get("summary", ""), depth=2)


def registry_page(records: list[dict], head: str) -> str:
    rows = "".join(
        f'<tr><td><a href="v1/{number(r["aiid"])}.html"><code>{esc(r["aiid"])}</code></a></td>'
        f'<td><a href="v1/{number(r["aiid"])}.html">{esc(r["name"])}</a></td><td>{esc(r["kind"])}</td>'
        f'<td>{who(r["principal"])}</td><td><span class="st {esc(r["status"])}">{esc(r["status"])}</span></td>'
        f'<td class=nw>{esc(r["registered_at"][:10])}</td></tr>' for r in records)
    body = f"""<h1>Registry</h1>
<p class=lead>{len(records)} agents. Every record is signed by the registry key and chained to the one before it, so no record can be changed or removed without it showing.</p>
<div class=scroll><table class=list><thead><tr><th>Agent ID</th><th>Name</th><th>Kind</th><th>Principal</th><th>Status</th><th>Registered</th></tr></thead><tbody>{rows}</tbody></table></div>
<p class=dim>Head of the chain: <code class=wrap>{esc(head)}</code><br>
Machine-readable: <a href="registry.json">registry.json</a> · <a href="log.jsonl">log.jsonl</a> · <a href="../.well-known/aiid-registry.json">registry key</a><br>
The records of February 2026, before signatures: <a href="aiid-00000000000001.html">1</a> · <a href="aiid-00000000000002.html">2</a> · <a href="aiid-00000000000003.html">3</a> · <a href="aiid-00000000000004.html">4</a> · <a href="dar-00000000000001.html">dar 1</a></p>"""
    return page("Agent ID Registry", body, "The public registry of artificial agents: who acts, for whom, within what.", depth=1)


def build(reg: Registry) -> int:
    entries = reg.entries()
    problems = verify_log(entries, reg.keys())
    if problems:
        raise SystemExit("the log does not verify:\n  " + "\n  ".join(problems))
    current = sorted(reg.current().values(), key=lambda r: r["aiid"])
    reg.v1.mkdir(parents=True, exist_ok=True)
    for r in current:
        n = number(r["aiid"])
        (reg.v1 / f"{n}.json").write_text(json.dumps(r, ensure_ascii=False, indent=2) + "\n")
        (reg.v1 / f"{n}.html").write_text(record_page(r))
    head = digest(entries[-1]) if entries else ""
    index = {"standard": STANDARD, "registry": REGISTRY, "count": len(current),
             "entries": len(entries), "head": head, "keys": KEYS_URL,
             "records": [{"aiid": r["aiid"], "name": r["name"], "kind": r["kind"],
                          "status": r["status"], "registered_at": r["registered_at"],
                          "url": f"{REGISTRY}/registry/v1/{number(r['aiid'])}.json"}
                         for r in current]}
    (reg.root / "registry" / "registry.json").write_text(json.dumps(index, ensure_ascii=False, indent=2) + "\n")
    (reg.root / "registry" / "index.html").write_text(registry_page(current, head))
    for src in sorted((reg.root / "site").glob("*.html")):
        # each source: a first line <!-- title | description -->, then the body
        first, _, body = src.read_text().partition("\n")
        title, _, desc = first.strip().removeprefix("<!--").removesuffix("-->").partition("|")
        body = body.replace("{{count}}", str(len(current))).replace("{{head}}", esc(head))
        (reg.root / src.name).write_text(page(title.strip(), body, desc.strip()))
    return len(current)


# --- command line ----------------------------------------------------------------------

def load_target(target: str) -> dict:
    if target.startswith("aiid:"):
        return fetch(f"{REGISTRY}/registry/v1/{number(target)}.json")
    if target.startswith(("http://", "https://")):
        return fetch(target)
    return json.loads(Path(target).read_text())


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="aiid", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="check a record's signature")
    v.add_argument("target", help="aiid:NNNNNNNNNNNNNN, a URL or a file")
    vl = sub.add_parser("verify-log", help="replay the registry chain")
    vl.add_argument("--root", help="a local copy of the registry (default: aiagentid.org)")
    kg = sub.add_parser("keygen", help="make a key pair for a self-declared record")
    kg.add_argument("out")
    sg = sub.add_parser("sign", help="sign a self-declared record")
    sg.add_argument("record"), sg.add_argument("--key", required=True), sg.add_argument("--key-id", required=True)
    for name in ("issue", "status", "build"):
        p = sub.add_parser(name)
        p.add_argument("--root", default=".")
        if name != "build":
            p.add_argument("--key", required=True)
        if name == "issue":
            p.add_argument("spec", help="a JSON file, or - for stdin")
        if name == "status":
            p.add_argument("aiid"), p.add_argument("status"), p.add_argument("reason")
    a = ap.parse_args(argv)

    if a.cmd == "verify":
        r = load_target(a.target)
        problem = check(r)
        if problem:
            print(f"✗ {r.get('aiid', a.target)}: {problem}")
            return 1
        by = r["proof"]["key"]
        print(f"✓ {r['aiid']} {r['name']} — {r['status']}\n  signed by {by}")
        print(f"  principal: {r['principal'].get('name') or 'not disclosed'}; "
              f"scope: {r['scope'].get('summary', '')}")
        return 0
    if a.cmd == "verify-log":
        if a.root:
            reg = Registry(a.root)
            entries, keys = reg.entries(), reg.keys()
        else:
            raw = urllib.request.urlopen(REGISTRY + "/registry/log.jsonl", timeout=20).read().decode()
            entries, keys = [json.loads(x) for x in raw.splitlines() if x.strip()], fetch(KEYS_URL)
        problems = verify_log(entries, keys)
        print("\n".join(f"✗ {p}" for p in problems) or
              f"✓ {len(entries)} entries, chain whole, every signature valid; head {digest(entries[-1])}")
        return 1 if problems else 0
    if a.cmd == "keygen":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
        key = Ed25519PrivateKey.generate()
        fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        print(json.dumps({"id": "1", "alg": "Ed25519", "public": b64(public_raw(key))}))
        return 0
    if a.cmd == "sign":
        r = json.loads(Path(a.record).read_text())
        print(json.dumps(sign(r, private_key(a.key), a.key_id), ensure_ascii=False, indent=2))
        return 0
    reg = Registry(a.root)
    if a.cmd == "issue":
        spec = json.load(sys.stdin if a.spec == "-" else open(a.spec))
        r = issue(reg, spec, private_key(a.key))
        build(reg)
        print(r["aiid"])
        return 0
    if a.cmd == "status":
        r = set_status(reg, a.aiid, a.status, a.reason, private_key(a.key))
        build(reg)
        print(r["aiid"], r["status"])
        return 0
    print(build(reg), "records")
    return 0


if __name__ == "__main__":
    sys.exit(main())
