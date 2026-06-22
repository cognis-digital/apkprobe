"use strict";
const test = require("node:test");
const assert = require("node:assert");
const { analyzeManifest, run, SENSITIVE_PERMISSIONS } = require("../dist/rules.js");

function byTitle(fs) {
  const m = {};
  for (const f of fs) m[f.title] = f;
  return m;
}

test("debuggable is HIGH", () => {
  const fs = analyzeManifest({ debuggable: true });
  assert.equal(byTitle(fs)["Application is debuggable"].severity, "HIGH");
});

test("allow_backup is MEDIUM", () => {
  const fs = analyzeManifest({ allow_backup: true });
  assert.ok(byTitle(fs)["ADB backup allowed"]);
});

test("cleartext true flagged", () => {
  const fs = analyzeManifest({ uses_cleartext_traffic: true });
  assert.ok(byTitle(fs)["Cleartext (HTTP) traffic permitted"]);
});

test("cleartext false suppresses NSC", () => {
  const fs = analyzeManifest({ target_sdk: 33, uses_cleartext_traffic: false });
  assert.ok(!byTitle(fs)["No Network Security Config"]);
});

test("NSC flagged when target high and unset", () => {
  const fs = analyzeManifest({ target_sdk: 30 });
  assert.ok(byTitle(fs)["No Network Security Config"]);
});

test("NSC present suppresses", () => {
  const fs = analyzeManifest({ target_sdk: 30, network_security_config: "@xml/nsc" });
  assert.ok(!byTitle(fs)["No Network Security Config"]);
});

test("exported with filter is MEDIUM", () => {
  const fs = analyzeManifest({
    components: [{ kind: "activity", name: ".Main", exported: true, has_permission: false, intent_filters: 1 }],
  });
  assert.equal(byTitle(fs)["Exported activity without permission: .Main"].severity, "MEDIUM");
});

test("exported no filter is LOW", () => {
  const fs = analyzeManifest({
    components: [{ kind: "service", name: ".Sync", exported: true, has_permission: false, intent_filters: 0 }],
  });
  assert.equal(byTitle(fs)["Exported service without permission: .Sync"].severity, "LOW");
});

test("guarded component not flagged", () => {
  const fs = analyzeManifest({
    components: [{ kind: "activity", name: ".G", exported: true, has_permission: true, intent_filters: 1 }],
  });
  assert.equal(fs.length, 0);
});

test("sensitive permissions sorted unique", () => {
  const fs = analyzeManifest({
    permissions: [
      "android.permission.READ_SMS",
      "android.permission.CAMERA",
      "android.permission.READ_SMS",
      "android.permission.INTERNET",
    ],
  });
  const ev = fs.filter((f) => f.title.startsWith("Sensitive permission")).map((f) => f.evidence);
  assert.deepEqual(ev, ["android.permission.CAMERA", "android.permission.READ_SMS"]);
});

test("low minSdk flagged", () => {
  const fs = analyzeManifest({ min_sdk: 19 });
  assert.ok(byTitle(fs)["Low minSdkVersion (19)"]);
});

test("high minSdk not flagged", () => {
  const fs = analyzeManifest({ min_sdk: 28 });
  assert.ok(!byTitle(fs)["Low minSdkVersion (28)"]);
});

test("hardened manifest is clean", () => {
  const fs = analyzeManifest({
    package: "com.acme.app",
    min_sdk: 28,
    target_sdk: 33,
    allow_backup: false,
    network_security_config: "@xml/nsc",
    uses_cleartext_traffic: false,
  });
  assert.equal(fs.length, 0);
});

test("run emits JSON array", () => {
  const out = run(JSON.stringify({ package: "com.x", debuggable: true, allow_backup: false }));
  const fs = JSON.parse(out);
  assert.equal(fs.length, 1);
  assert.equal(fs[0].severity, "HIGH");
});

test("run empty is empty array", () => {
  const out = run(JSON.stringify({ package: "com.x", allow_backup: false }));
  assert.deepEqual(JSON.parse(out), []);
});

test("sensitive set has 10 entries", () => {
  assert.equal(SENSITIVE_PERMISSIONS.size, 10);
});
