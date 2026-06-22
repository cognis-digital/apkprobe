// Command apkprobe-rules is a Go port of apkprobe's core MASVS/MASTG manifest
// rule engine (see apkprobe/rules.py). It consumes a normalized manifest JSON
// and emits the same findings as the Python reference. Defensive, offline, no
// network or device access.
package main

import "sort"

// Component mirrors apkprobe.manifest.Component.
type Component struct {
	Kind          string `json:"kind"`
	Name          string `json:"name"`
	Exported      bool   `json:"exported"`
	HasPermission bool   `json:"has_permission"`
	IntentFilters int    `json:"intent_filters"`
}

// Manifest mirrors apkprobe.manifest.AppManifest (normalized).
// UsesCleartextTraffic is a *bool: nil = unset.
type Manifest struct {
	Package               string     `json:"package"`
	MinSDK                int        `json:"min_sdk"`
	TargetSDK             int        `json:"target_sdk"`
	Debuggable            bool       `json:"debuggable"`
	AllowBackup           bool       `json:"allow_backup"`
	UsesCleartextTraffic  *bool      `json:"uses_cleartext_traffic"`
	NetworkSecurityConfig string     `json:"network_security_config"`
	Permissions           []string   `json:"permissions"`
	Components            []Component `json:"components"`
}

// Finding mirrors the subset of fields the ports agree on.
type Finding struct {
	Title     string `json:"title"`
	Severity  string `json:"severity"`
	MASVS     string `json:"masvs"`
	MASTGTest string `json:"mastg_test"`
	Evidence  string `json:"evidence"`
}

// SensitivePermissions matches rules.SENSITIVE_PERMISSIONS.
var SensitivePermissions = map[string]bool{
	"android.permission.READ_SMS":                true,
	"android.permission.SEND_SMS":                true,
	"android.permission.READ_CONTACTS":           true,
	"android.permission.ACCESS_FINE_LOCATION":    true,
	"android.permission.RECORD_AUDIO":            true,
	"android.permission.READ_EXTERNAL_STORAGE":   true,
	"android.permission.WRITE_EXTERNAL_STORAGE":  true,
	"android.permission.READ_PHONE_STATE":        true,
	"android.permission.CAMERA":                  true,
	"android.permission.REQUEST_INSTALL_PACKAGES": true,
}

// AnalyzeManifest runs the MASVS/MASTG checks over m, in the same order as the
// Python reference.
func AnalyzeManifest(m Manifest) []Finding {
	var out []Finding
	add := func(title, sev, masvs, mastg, ev string) {
		out = append(out, Finding{Title: title, Severity: sev, MASVS: masvs, MASTGTest: mastg, Evidence: ev})
	}

	if m.Debuggable {
		add("Application is debuggable", "HIGH", "MASVS-RESILIENCE-2", "MASTG-TEST-0026",
			`android:debuggable="true"`)
	}
	if m.AllowBackup {
		add("ADB backup allowed", "MEDIUM", "MASVS-STORAGE-2", "MASTG-TEST-0009",
			`android:allowBackup="true"`)
	}
	if m.UsesCleartextTraffic != nil && *m.UsesCleartextTraffic {
		add("Cleartext (HTTP) traffic permitted", "HIGH", "MASVS-NETWORK-1", "MASTG-TEST-0019",
			`android:usesCleartextTraffic="true"`)
	}
	if m.TargetSDK >= 24 && m.NetworkSecurityConfig == "" &&
		!(m.UsesCleartextTraffic != nil && !*m.UsesCleartextTraffic) {
		add("No Network Security Config", "LOW", "MASVS-NETWORK-2", "MASTG-TEST-0020",
			"targetSdk="+itoa(m.TargetSDK)+", no android:networkSecurityConfig")
	}
	for _, c := range m.Components {
		if c.Exported && !c.HasPermission {
			sev := "LOW"
			if c.IntentFilters > 0 {
				sev = "MEDIUM"
			}
			add("Exported "+c.Kind+" without permission: "+c.Name, sev,
				"MASVS-PLATFORM-1", "MASTG-TEST-0024",
				c.Kind+" "+c.Name+" exported=true, permission=none, intent-filters="+itoa(c.IntentFilters))
		}
	}
	// sorted(set(permissions) & SENSITIVE)
	seen := map[string]bool{}
	var sensitive []string
	for _, p := range m.Permissions {
		if SensitivePermissions[p] && !seen[p] {
			seen[p] = true
			sensitive = append(sensitive, p)
		}
	}
	sort.Strings(sensitive)
	for _, p := range sensitive {
		add("Sensitive permission requested: "+p, "INFO",
			"MASVS-PLATFORM-1", "MASTG-TEST-0024", p)
	}
	if m.MinSDK > 0 && m.MinSDK < 24 {
		add("Low minSdkVersion ("+itoa(m.MinSDK)+")", "LOW", "MASVS-RESILIENCE-1", "",
			"minSdkVersion="+itoa(m.MinSDK))
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
