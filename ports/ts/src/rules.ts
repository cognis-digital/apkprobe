/**
 * TypeScript port of apkprobe's core MASVS/MASTG manifest rule engine
 * (see apkprobe/rules.py). Consumes a normalized manifest object and emits the
 * same findings as the Python reference. Defensive, offline: no network, no
 * device access.
 */

export interface Component {
  kind: string;
  name: string;
  exported: boolean;
  has_permission: boolean;
  intent_filters: number;
}

export interface Manifest {
  package?: string;
  min_sdk?: number;
  target_sdk?: number;
  debuggable?: boolean;
  allow_backup?: boolean;
  uses_cleartext_traffic?: boolean | null;
  network_security_config?: string;
  permissions?: string[];
  components?: Component[];
}

export interface Finding {
  title: string;
  severity: string;
  masvs: string;
  mastg_test: string;
  evidence: string;
}

export const SENSITIVE_PERMISSIONS: ReadonlySet<string> = new Set([
  "android.permission.READ_SMS",
  "android.permission.SEND_SMS",
  "android.permission.READ_CONTACTS",
  "android.permission.ACCESS_FINE_LOCATION",
  "android.permission.RECORD_AUDIO",
  "android.permission.READ_EXTERNAL_STORAGE",
  "android.permission.WRITE_EXTERNAL_STORAGE",
  "android.permission.READ_PHONE_STATE",
  "android.permission.CAMERA",
  "android.permission.REQUEST_INSTALL_PACKAGES",
]);

export function analyzeManifest(m: Manifest): Finding[] {
  const out: Finding[] = [];
  const add = (
    title: string,
    severity: string,
    masvs: string,
    mastg_test: string,
    evidence: string,
  ): void => {
    out.push({ title, severity, masvs, mastg_test, evidence });
  };

  const targetSdk = m.target_sdk ?? 0;
  const minSdk = m.min_sdk ?? 0;
  const cleartext = m.uses_cleartext_traffic ?? null;
  const nsc = m.network_security_config ?? "";

  if (m.debuggable) {
    add(
      "Application is debuggable",
      "HIGH",
      "MASVS-RESILIENCE-2",
      "MASTG-TEST-0026",
      'android:debuggable="true"',
    );
  }
  if (m.allow_backup) {
    add(
      "ADB backup allowed",
      "MEDIUM",
      "MASVS-STORAGE-2",
      "MASTG-TEST-0009",
      'android:allowBackup="true"',
    );
  }
  if (cleartext === true) {
    add(
      "Cleartext (HTTP) traffic permitted",
      "HIGH",
      "MASVS-NETWORK-1",
      "MASTG-TEST-0019",
      'android:usesCleartextTraffic="true"',
    );
  }
  if (targetSdk >= 24 && nsc === "" && cleartext !== false) {
    add(
      "No Network Security Config",
      "LOW",
      "MASVS-NETWORK-2",
      "MASTG-TEST-0020",
      `targetSdk=${targetSdk}, no android:networkSecurityConfig`,
    );
  }
  for (const c of m.components ?? []) {
    if (c.exported && !c.has_permission) {
      const sev = c.intent_filters > 0 ? "MEDIUM" : "LOW";
      add(
        `Exported ${c.kind} without permission: ${c.name}`,
        sev,
        "MASVS-PLATFORM-1",
        "MASTG-TEST-0024",
        `${c.kind} ${c.name} exported=true, permission=none, intent-filters=${c.intent_filters}`,
      );
    }
  }
  const present = Array.from(
    new Set((m.permissions ?? []).filter((p) => SENSITIVE_PERMISSIONS.has(p))),
  ).sort();
  for (const p of present) {
    add(
      `Sensitive permission requested: ${p}`,
      "INFO",
      "MASVS-PLATFORM-1",
      "MASTG-TEST-0024",
      p,
    );
  }
  if (minSdk > 0 && minSdk < 24) {
    add(
      `Low minSdkVersion (${minSdk})`,
      "LOW",
      "MASVS-RESILIENCE-1",
      "",
      `minSdkVersion=${minSdk}`,
    );
  }
  return out;
}

export function run(input: string): string {
  const m = JSON.parse(input) as Manifest;
  return JSON.stringify(analyzeManifest(m), null, 2);
}
