// js/generator.js (REPLACE ENTIRE FILE)
// Works with your current IDs + adds OPTIONAL presets + warnings (safe if HTML elements don't exist)

(() => {
  const $ = (id) => document.getElementById(id);

  // ===== Generator (existing IDs) =====
  const genDomain = $("genDomain");
  const genSelector = $("genSelector");
  const genClearBtn = $("genClearBtn");

  const spfIps = $("spfIps");
  const spfIncludes = $("spfIncludes");
  const spfQualifier = $("spfQualifier");
  const spfOut = $("spfOut");
  const copySpfBtn = $("copySpfBtn");

  const dmarcPolicy = $("dmarcPolicy");
  const dmarcRua = $("dmarcRua");
  const dmarcPct = $("dmarcPct");
  const dmarcOut = $("dmarcOut");
  const copyDmarcBtn = $("copyDmarcBtn");

  const dkimHostLabel = $("dkimHostLabel");
  const dkimValOut = $("dkimValOut");
  const copyDkimHostBtn = $("copyDkimHostBtn");
  const copyDkimValBtn = $("copyDkimValBtn");

  // ===== OPTIONAL UI (only works if these IDs exist in HTML) =====
  // Provider SPF preset dropdown: <select id="spfPreset">...</select>
  const spfPreset = $("spfPreset");
  // DMARC preset dropdown: <select id="dmarcPreset">...</select>
  const dmarcPreset = $("dmarcPreset");
  // Warnings container: <div id="genWarnings"></div>
  const genWarnings = $("genWarnings");

  // ===== Presets (edit if you want) =====
  const SPF_PRESETS = {
    custom: { label: "Custom", includes: "" },

    google: { label: "Google Workspace", includes: "_spf.google.com" },
    m365: { label: "Microsoft 365", includes: "spf.protection.outlook.com" },

    // Common marketing/transactional senders (examples)
    mailgun: { label: "Mailgun (common)", includes: "mailgun.org" },
    sendgrid: { label: "SendGrid (example)", includes: "sendgrid.net" }
  };

  const DMARC_PRESETS = {
    enforce_quarantine: { label: "Enforce (Quarantine)", policy: "quarantine", pct: "100", fo: "1" },
    enforce_reject: { label: "Enforce (Reject)", policy: "reject", pct: "100", fo: "1" },
    monitor: { label: "Monitor only (p=none)", policy: "none", pct: "100", fo: "1" }
  };

  function normalizeDomain(v) {
    let s = (v || "").trim().toLowerCase();
    s = s.replace(/^https?:\/\//, "");
    s = s.split("/")[0];
    s = s.replace(/\.$/, "");
    return s;
  }

  function normalizeCsv(s) {
    return (s || "")
      .split(",")
      .map(x => x.trim())
      .filter(Boolean);
  }

  // ===== SPF / DMARC / DKIM builders =====
  function buildSpfRecord() {
    const ips = normalizeCsv(spfIps?.value);
    const incs = normalizeCsv(spfIncludes?.value);
    const qualifier = (spfQualifier?.value || "-all").trim() || "-all";

    const parts = ["v=spf1"];

    // NOTE: This keeps your original behavior (ip4:...), but ALSO supports if user types "ip6:" manually.
    ips.forEach(ip => {
      const lower = ip.toLowerCase();
      if (lower.startsWith("ip6:") || lower.startsWith("ip4:")) parts.push(ip);
      else if (ip.includes(":")) parts.push(`ip6:${ip}`); // basic guess
      else parts.push(`ip4:${ip}`);
    });

    incs.forEach(inc => parts.push(`include:${inc}`));

    parts.push(qualifier);
    return parts.join(" ").replace(/\s+/g, " ").trim();
  }

  function buildDmarcRecord(domain) {
    const p = (dmarcPolicy?.value || "quarantine").trim() || "quarantine";
    const pct = (dmarcPct?.value || "100").trim() || "100";
    const ruaEmail = (dmarcRua?.value || "").trim();

    const parts = ["v=DMARC1", `p=${p}`];

    if (ruaEmail) {
      parts.push(`rua=mailto:${ruaEmail}`);
    } else if (domain) {
      // keep your auto-fill behavior
      parts.push(`rua=mailto:dmarc-reports@${domain}`);
    }

    parts.push("fo=1");
    parts.push(`pct=${pct}`);

    return parts.join("; ");
  }

  function buildDkimHost(domain, selector) {
    const d = domain || "example.com";
    const s = selector || "selector1";
    return `${s}._domainkey.${d}`;
  }

  // ===== Validation / Warnings =====
  function estimateSpfDnsLookups() {
    // With our builder, the only DNS-lookups come from include:
    // (Real SPF is more complex, but this is still useful)
    const incs = normalizeCsv(spfIncludes?.value);
    return incs.length;
  }

  function renderWarnings(domain, selector) {
    if (!genWarnings) return;

    const warnings = [];

    // SPF warnings
    const ips = normalizeCsv(spfIps?.value);
    const incs = normalizeCsv(spfIncludes?.value);
    const qual = (spfQualifier?.value || "-all").trim() || "-all";
    const spfLookups = estimateSpfDnsLookups();

    if (!ips.length && !incs.length) {
      warnings.push({
        level: "warn",
        text: "SPF: You have no authorized senders (record will be “v=spf1 -all”). Add IPs or includes."
      });
    }

    if (spfLookups > 10) {
      warnings.push({
        level: "bad",
        text: `SPF: You may exceed the SPF 10 DNS lookup limit (includes=${spfLookups}). Reduce includes or flatten SPF.`
      });
    } else if (spfLookups >= 8) {
      warnings.push({
        level: "warn",
        text: `SPF: You are close to the SPF 10 DNS lookup limit (includes=${spfLookups}).`
      });
    }

    if (!["-all", "~all", "?all", "+all"].includes(qual)) {
      warnings.push({
        level: "warn",
        text: `SPF: “${qual}” is unusual. Typical endings are -all (strict), ~all (soft), ?all (neutral).`
      });
    }

    // DMARC warnings
    const p = (dmarcPolicy?.value || "quarantine").trim().toLowerCase();
    const pct = parseInt((dmarcPct?.value || "100").trim(), 10);
    const rua = (dmarcRua?.value || "").trim();

    if (!rua) {
      warnings.push({
        level: "warn",
        text: `DMARC: rua is auto-filled to dmarc-reports@${domain || "your-domain"} — ensure that mailbox exists or set your own rua.`
      });
    }

    if (p === "none") {
      warnings.push({
        level: "warn",
        text: "DMARC: p=none is monitoring only (not enforcing). Consider quarantine/reject once confident."
      });
    }

    if ((p === "reject" || p === "quarantine") && Number.isFinite(pct) && pct < 100) {
      warnings.push({
        level: "warn",
        text: `DMARC: You are enforcing with pct=${pct}. That’s okay for rollout, but full enforcement is pct=100.`
      });
    }

    // DKIM warnings
    if (!selector) {
      warnings.push({
        level: "bad",
        text: "DKIM: Selector is required to form the DNS host (selector._domainkey.domain)."
      });
    } else if (selector.length > 63) {
      warnings.push({
        level: "warn",
        text: "DKIM: Selector looks unusually long. Keep it simple (e.g., selector1, s2026)."
      });
    }

    // Render (minimal styling using your existing badge classes)
    if (!warnings.length) {
      genWarnings.innerHTML = "";
      genWarnings.style.display = "none";
      return;
    }

    genWarnings.style.display = "block";
    genWarnings.innerHTML = `
      <div class="muted-small" style="margin-top:10px;">
        <strong>Checks & Tips</strong>
        <div style="margin-top:8px; display:flex; flex-direction:column; gap:8px;">
          ${warnings
            .map(w => {
              const cls = w.level === "bad" ? "bad" : "warn";
              const label = w.level === "bad" ? "IMPORTANT" : "NOTE";
              return `
                <div style="display:flex; gap:10px; align-items:flex-start;">
                  <span class="badge ${cls}" style="margin-top:0;">${label}</span>
                  <div>${escapeHtml(w.text)}</div>
                </div>
              `;
            })
            .join("")}
        </div>
      </div>
    `;
  }

  function escapeHtml(str) {
    return String(str || "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  // ===== Output refresh =====
  function refreshOutputs() {
    const domain = normalizeDomain(genDomain?.value);
    const selector = (genSelector?.value || "selector1").trim();

    if (spfOut) spfOut.textContent = buildSpfRecord();
    if (dmarcOut) dmarcOut.textContent = buildDmarcRecord(domain);

    const host = buildDkimHost(domain, selector || "selector1");
    if (dkimHostLabel) dkimHostLabel.textContent = host;

    // DKIM value is a template (don’t show real public keys here)
    if (dkimValOut) {
      dkimValOut.textContent = "v=DKIM1; k=rsa; p=REPLACE_WITH_PUBLIC_KEY_FROM_PROVIDER";
    }

    renderWarnings(domain, selector);
  }

  // ===== Preset handlers (OPTIONAL) =====
  function applySpfPreset(key) {
    const preset = SPF_PRESETS[key];
    if (!preset) return;

    if (key === "custom") return; // don't override
    // Put the include domain(s) into includes input
    if (spfIncludes) spfIncludes.value = preset.includes || "";
  }

  function applyDmarcPreset(key) {
    const preset = DMARC_PRESETS[key];
    if (!preset) return;

    if (dmarcPolicy) dmarcPolicy.value = preset.policy;
    if (dmarcPct) dmarcPct.value = preset.pct;
    // fo is hardcoded as fo=1 in builder, so no extra field required
  }

  // ===== Copy helpers =====
  async function copyText(text) {
    const t = String(text || "");
    if (!t) return false;

    try {
      await navigator.clipboard.writeText(t);
      return true;
    } catch {
      try {
        const ta = document.createElement("textarea");
        ta.value = t;
        ta.style.position = "fixed";
        ta.style.left = "-9999px";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
        return true;
      } catch {
        return false;
      }
    }
  }

  function bindCopy(btn, getValueFn) {
    if (!btn) return;
    btn.addEventListener("click", async () => {
      const ok = await copyText(getValueFn());
      const old = btn.textContent;
      btn.textContent = ok ? "Copied!" : "Copy failed";
      setTimeout(() => (btn.textContent = old), 900);
    });
  }

  // ===== Clear =====
  function clearAll() {
    if (genDomain) genDomain.value = "";
    if (genSelector) genSelector.value = "selector1";

    if (spfIps) spfIps.value = "";
    if (spfIncludes) spfIncludes.value = "";
    if (spfQualifier) spfQualifier.value = "-all";

    if (dmarcPolicy) dmarcPolicy.value = "quarantine";
    if (dmarcRua) dmarcRua.value = "";
    if (dmarcPct) dmarcPct.value = "100";

    // Optional presets reset
    if (spfPreset) spfPreset.value = "custom";
    if (dmarcPreset) dmarcPreset.value = "enforce_quarantine";

    refreshOutputs();
  }

  // ===== Events =====
  [
    genDomain, genSelector,
    spfIps, spfIncludes, spfQualifier,
    dmarcPolicy, dmarcRua, dmarcPct
  ].forEach(el => el?.addEventListener("input", refreshOutputs));

  // OPTIONAL: auto-apply presets on change (no “Generate” button needed)
  spfPreset?.addEventListener("change", () => {
    applySpfPreset(spfPreset.value);
    refreshOutputs();
  });

  dmarcPreset?.addEventListener("change", () => {
    applyDmarcPreset(dmarcPreset.value);
    refreshOutputs();
  });

  genClearBtn?.addEventListener("click", clearAll);

  bindCopy(copySpfBtn, () => spfOut?.textContent || "");
  bindCopy(copyDmarcBtn, () => dmarcOut?.textContent || "");
  bindCopy(copyDkimHostBtn, () => dkimHostLabel?.textContent || "");
  bindCopy(copyDkimValBtn, () => dkimValOut?.textContent || "");

  window.addEventListener("load", () => {
    // If optional preset dropdowns exist but not populated, we do nothing
    refreshOutputs();
  });
})();
