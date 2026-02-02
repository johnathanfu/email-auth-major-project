// server.js (REPLACE ENTIRE FILE)

const express = require("express");

const app = express();

// Serve EVERYTHING in the current folder (html, css, js, images, etc.)
app.use(express.static(__dirname));

// If you want, you can set a default home page:
// app.get("/", (req, res) => res.sendFile(__dirname + "/homepage.html"));

// ---------- API: /api/check ----------
async function dohTxt(name) {
  const url = `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=TXT`;
  const res = await fetch(url);
  const data = await res.json();

  const answers = Array.isArray(data.Answer) ? data.Answer : [];
  return answers
    .filter(a => a.type === 16 && typeof a.data === "string")
    .map(a => a.data.replace(/^"|"$/g, "").replace(/"\s+"/g, ""));
}

function parseTags(record) {
  const tags = {};
  record.split(";").map(x => x.trim()).filter(Boolean).forEach(part => {
    const idx = part.indexOf("=");
    if (idx > 0) tags[part.slice(0, idx).trim().toLowerCase()] = part.slice(idx + 1).trim();
  });
  return tags;
}

app.get("/api/check", async (req, res) => {
  try {
    const domain = (req.query.domain || "").trim().toLowerCase();
    const selector = (req.query.selector || "selector1").trim();

    if (!domain) return res.status(400).json({ error: "Missing domain" });

    // SPF
    const rootTxt = await dohTxt(domain);
    const spfRecords = rootTxt.filter(t => t.toLowerCase().startsWith("v=spf1"));
    const spf = {
      found: spfRecords.length > 0,
      record: spfRecords[0] || null,
      warnings: spfRecords.length > 1 ? ["Multiple SPF records found (should be 1)."] : []
    };

    // DMARC
    const dmarcTxt = await dohTxt(`_dmarc.${domain}`);
    const dmarcRecord = dmarcTxt.find(t => t.toLowerCase().startsWith("v=dmarc1")) || null;
    const dmarcTags = dmarcRecord ? parseTags(dmarcRecord) : null;
    const policy = dmarcTags?.p ? dmarcTags.p.toLowerCase() : null;

    const dmarc = {
      found: !!dmarcRecord,
      record: dmarcRecord,
      policy,
      enforcing: policy === "quarantine" || policy === "reject",
      warnings: []
    };

    if (dmarcRecord && policy === "none") dmarc.warnings.push("DMARC is monitoring only (p=none).");

    // DKIM (DNS readiness check)
    const dkimName = `${selector}._domainkey.${domain}`;
    const dkimTxt = await dohTxt(dkimName);
    const dkimRecord = dkimTxt.find(t => t.toLowerCase().includes("v=dkim1")) || null;

    const dkim = {
      found: !!dkimRecord,
      selector,
      name: dkimName,
      record: dkimRecord,
      warnings: dkimRecord ? ["DNS key exists (readiness). True DKIM PASS requires a signed email header."] : []
    };

    res.json({ domain, spf, dkim, dmarc });
  } catch (e) {
    res.status(500).json({ error: e.message || "Server error" });
  }
});

app.listen(3000, () => {
  console.log("Server running:");
  console.log("  http://localhost:3000/visualization.html");
});
