"use strict";
const test = require("node:test");
const assert = require("node:assert");
const {
  extractFromText,
  cvss3BaseScore,
  cvssLabel,
} = require("../dist/vulnmatch.js");

test("extract CVE id", () => {
  const ev = extractFromText("notes.txt", "fixed CVE-2021-44228 here");
  const cve = ev.find((e) => e.kind === "cve");
  assert.equal(cve.name, "CVE-2021-44228");
  assert.equal(cve.where, "notes.txt");
});

test("CVE is uppercased", () => {
  const ev = extractFromText("n.txt", "cve-2019-10744");
  assert.ok(ev.some((e) => e.name === "CVE-2019-10744"));
});

test("extract GHSA id", () => {
  const ev = extractFromText("n.txt", "GHSA-jfh8-c2jp-5v3q");
  assert.ok(ev.some((e) => e.kind === "ghsa" && e.name === "GHSA-JFH8-C2JP-5V3Q"));
});

test("extract Maven coordinate with version", () => {
  const ev = extractFromText("d.txt", "org.apache.logging.log4j:log4j-core:2.14.1");
  const m = ev.find((e) => e.kind === "maven");
  assert.equal(m.name, "org.apache.logging.log4j:log4j-core");
  assert.equal(m.version, "2.14.1");
  assert.equal(m.ecosystem, "Maven");
});

test("Maven skips android namespace", () => {
  const ev = extractFromText("m.xml", 'android:name="x" android:exported="true"');
  assert.ok(!ev.some((e) => e.kind === "maven" && e.name.startsWith("android")));
});

test("no evidence in prose", () => {
  assert.deepEqual(extractFromText("r.txt", "just prose"), []);
});

test("evidence deduped", () => {
  const ev = extractFromText("x.txt", "CVE-2021-44228 CVE-2021-44228");
  assert.equal(ev.filter((e) => e.kind === "cve").length, 1);
});

test("CVSS log4shell is 10.0", () => {
  assert.equal(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0);
});

test("CVSS jackson xxe is 7.5", () => {
  assert.equal(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"), 7.5);
});

test("CVSS lodash redos is 5.3", () => {
  assert.equal(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"), 5.3);
});

test("CVSS no impact is 0", () => {
  assert.equal(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0.0);
});

test("CVSS unparseable is null", () => {
  assert.equal(cvss3BaseScore("garbage"), null);
});

test("label CRITICAL", () => {
  assert.equal(cvssLabel("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), "CRITICAL");
});

test("label HIGH", () => {
  assert.equal(cvssLabel("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"), "HIGH");
});

test("label empty for blank", () => {
  assert.equal(cvssLabel(""), "");
});

test("label passthrough words", () => {
  assert.equal(cvssLabel("high"), "HIGH");
  assert.equal(cvssLabel("Moderate"), "MEDIUM");
});

test("label cvss4 high", () => {
  assert.equal(
    cvssLabel("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
    "HIGH",
  );
});
