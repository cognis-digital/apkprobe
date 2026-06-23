/**
 * TypeScript port of apkprobe's component-evidence harvester + OSV correlation
 * helpers (see apkprobe/components.py + apkprobe/vulnmatch.py). Defensive,
 * offline: extracts component/advisory evidence from text and bands CVSS
 * vectors. The full ~262k-record OSV corpus stays with the Python reference;
 * this port mirrors the harvesting + scoring surface so non-Python toolchains
 * can pre-process evidence and consume a DB query result. No network.
 */

export type EvidenceKind = "cve" | "ghsa" | "maven" | "npm" | "native";

export interface ComponentEvidence {
  kind: EvidenceKind;
  name: string;
  version: string;
  where: string;
  ecosystem: string;
}

const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;
const GHSA_RE = /\bGHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}\b/gi;
const MAVEN_RE =
  /\b([a-z0-9_.\-]+(?:\.[a-z0-9_\-]+)+):([a-z0-9_.\-]+)(?::([0-9][0-9A-Za-z.\-+]*))?\b/gi;

function ev(
  kind: EvidenceKind,
  name: string,
  version = "",
  where = "",
  ecosystem = "",
): ComponentEvidence {
  return { kind, name, version, where, ecosystem };
}

/** Harvest CVE/GHSA ids and Maven coordinates from a single text entry. */
export function extractFromText(where: string, text: string): ComponentEvidence[] {
  const out: ComponentEvidence[] = [];
  const seen = new Set<string>();
  const push = (e: ComponentEvidence) => {
    const k = `${e.kind}|${e.name}|${e.version}|${e.where}`;
    if (!seen.has(k)) {
      seen.add(k);
      out.push(e);
    }
  };
  for (const m of text.matchAll(CVE_RE)) push(ev("cve", m[0].toUpperCase(), "", where));
  for (const m of text.matchAll(GHSA_RE)) push(ev("ghsa", m[0].toUpperCase(), "", where));
  for (const m of text.matchAll(MAVEN_RE)) {
    const group = m[1];
    const artifact = m[2];
    if (group.startsWith("android") || group.startsWith("http") || group.startsWith("www")) {
      continue;
    }
    push(ev("maven", `${group}:${artifact}`, m[3] ?? "", where, "Maven"));
  }
  return out;
}

/** CVSS v3.x base-score component weights (enough to derive a band). */
const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC: Record<string, number> = { L: 0.77, H: 0.44 };
const PR_U: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
const PR_C: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };
const UI: Record<string, number> = { N: 0.85, R: 0.62 };
const CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0.0 };

const roundup = (x: number): number => Math.ceil(x * 10) / 10;

/** Compute a CVSS v3.x base score from a vector string, or null. */
export function cvss3BaseScore(vector: string): number | null {
  const parts: Record<string, string> = {};
  for (const kv of vector.split("/")) {
    const i = kv.indexOf(":");
    if (i > 0) parts[kv.slice(0, i)] = kv.slice(i + 1);
  }
  const scopeChanged = parts["S"] === "C";
  const av = AV[parts["AV"]];
  const ac = AC[parts["AC"]];
  const ui = UI[parts["UI"]];
  const pr = (scopeChanged ? PR_C : PR_U)[parts["PR"]];
  const c = CIA[parts["C"]];
  const i = CIA[parts["I"]];
  const a = CIA[parts["A"]];
  if ([av, ac, ui, pr, c, i, a].some((v) => v === undefined)) return null;
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = scopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  if (impact <= 0) return 0.0;
  const expl = 8.22 * av * ac * pr * ui;
  const base = scopeChanged ? Math.min(1.08 * (impact + expl), 10) : Math.min(impact + expl, 10);
  return roundup(base);
}

/** Map a CVSS vector (or bare label) to CRITICAL/HIGH/MEDIUM/LOW or "". */
export function cvssLabel(severity: string): string {
  if (!severity) return "";
  const s = severity.trim().toUpperCase();
  if (["CRITICAL", "HIGH", "MEDIUM", "MODERATE", "LOW"].includes(s)) {
    return s === "MODERATE" ? "MEDIUM" : s;
  }
  if (s.startsWith("CVSS:3")) {
    const score = cvss3BaseScore(severity);
    if (score === null) return "";
    if (score >= 9.0) return "CRITICAL";
    if (score >= 7.0) return "HIGH";
    if (score >= 4.0) return "MEDIUM";
    if (score > 0.0) return "LOW";
    return "";
  }
  if (s.startsWith("CVSS:4")) {
    const parts: Record<string, string> = {};
    for (const kv of s.split("/")) {
      const i = kv.indexOf(":");
      if (i > 0) parts[kv.slice(0, i)] = kv.slice(i + 1);
    }
    const highs = ["VC", "VI", "VA"].filter((k) => parts[k] === "H").length;
    if (highs >= 2 && parts["AV"] === "N" && parts["AC"] === "L") return "HIGH";
    if (highs >= 1) return "MEDIUM";
    return "LOW";
  }
  return "";
}
