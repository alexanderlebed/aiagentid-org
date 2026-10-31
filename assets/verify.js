// Agent ID — checks a record's Ed25519 signature in the browser (Agent ID Standard 1.0).
(function () {
  function canonical(v) {
    if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
    if (v && typeof v === "object")
      return "{" + Object.keys(v).sort().map(function (k) {
        return JSON.stringify(k) + ":" + canonical(v[k]);
      }).join(",") + "}";
    return JSON.stringify(v);
  }
  function unb64(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    return Uint8Array.from(atob(s), function (c) { return c.charCodeAt(0); });
  }
  async function getJSON(url) {
    var r = await fetch(url, { cache: "no-store" });
    if (!r.ok) throw new Error(url + " answered " + r.status);
    return r.json();
  }
  // Resolves to the record when its signature holds; throws saying what is wrong.
  async function verify(record) {
    var proof = record.proof || {};
    if (proof.alg !== "Ed25519" || !proof.key || !proof.value)
      throw new Error("the record carries no Ed25519 proof");
    var parts = proof.key.split("#");
    var keys = await getJSON(parts[0]);
    var k = (keys.keys || []).filter(function (x) { return x.id === parts[1] && x.alg === "Ed25519"; })[0];
    if (!k) throw new Error("no key " + parts[1] + " at " + parts[0]);
    var body = {};
    Object.keys(record).forEach(function (f) { if (f !== "proof") body[f] = record[f]; });
    var pub = await crypto.subtle.importKey("raw", unb64(k.public), { name: "Ed25519" }, false, ["verify"]);
    var ok = await crypto.subtle.verify({ name: "Ed25519" }, pub, unb64(proof.value),
                                        new TextEncoder().encode(canonical(body)));
    if (!ok) throw new Error("the signature does not match: the record was changed after signing");
    return record;
  }
  async function load(target) {
    target = target.trim();
    var m = target.match(/^(?:aiid:)?(\d{14})$/);
    if (m) return getJSON(new URL("/registry/v1/" + m[1] + ".json", location.origin).href);
    if (/^https?:\/\//.test(target)) return getJSON(target);
    return JSON.parse(target);
  }
  window.AgentID = { verify: verify, load: load, canonical: canonical };

  function say(out, ok, text) {
    out.className = "out " + (ok ? "ok" : "bad");
    out.textContent = (ok ? "✓ " : "✗ ") + text;
  }
  document.querySelectorAll(".verify[data-record]").forEach(function (box) {
    var out = box.querySelector(".out");
    box.querySelector("button").addEventListener("click", async function () {
      out.className = "out"; out.textContent = "Checking…";
      try {
        var r = await verify(await getJSON(box.getAttribute("data-record")));
        say(out, true, "Signed by the registry key. Status: " + r.status + ", version " + r.version + ".");
      } catch (e) { say(out, false, e.message); }
    });
  });
  var form = document.getElementById("check");
  if (form) form.addEventListener("submit", async function (ev) {
    ev.preventDefault();
    var out = document.getElementById("result");
    out.className = "out"; out.textContent = "Checking…";
    try {
      var r = await verify(await load(form.target_.value));
      var p = r.principal || {};
      say(out, true, r.aiid + " · " + r.name + " · " + r.status + " — acts for " +
          (p.disclosed === false ? "a private " + (p.type === "organization" ? "organization" : "person") + " (not disclosed)" : (p.name || "?")) +
          ". Scope: " + ((r.scope || {}).summary || "") + " Signed by " + r.proof.key);
    } catch (e) { say(out, false, e.message); }
  });
})();
