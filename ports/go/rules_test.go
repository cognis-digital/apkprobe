package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func boolPtr(b bool) *bool { return &b }

func titles(fs []Finding) map[string]Finding {
	m := map[string]Finding{}
	for _, f := range fs {
		m[f.Title] = f
	}
	return m
}

func TestDebuggable(t *testing.T) {
	fs := AnalyzeManifest(Manifest{Debuggable: true})
	f, ok := titles(fs)["Application is debuggable"]
	if !ok || f.Severity != "HIGH" {
		t.Fatalf("expected HIGH debuggable finding, got %#v", fs)
	}
}

func TestAllowBackup(t *testing.T) {
	fs := AnalyzeManifest(Manifest{AllowBackup: true})
	if _, ok := titles(fs)["ADB backup allowed"]; !ok {
		t.Fatal("expected ADB backup finding")
	}
}

func TestCleartextTrue(t *testing.T) {
	fs := AnalyzeManifest(Manifest{UsesCleartextTraffic: boolPtr(true)})
	if _, ok := titles(fs)["Cleartext (HTTP) traffic permitted"]; !ok {
		t.Fatal("expected cleartext finding")
	}
}

func TestCleartextFalseSuppressesNSC(t *testing.T) {
	fs := AnalyzeManifest(Manifest{TargetSDK: 33, UsesCleartextTraffic: boolPtr(false)})
	if _, ok := titles(fs)["No Network Security Config"]; ok {
		t.Fatal("cleartext=false should suppress NSC finding")
	}
}

func TestNSCWhenTargetHighAndUnset(t *testing.T) {
	fs := AnalyzeManifest(Manifest{TargetSDK: 30})
	if _, ok := titles(fs)["No Network Security Config"]; !ok {
		t.Fatal("expected NSC finding")
	}
}

func TestNSCNotFlaggedWhenConfigured(t *testing.T) {
	fs := AnalyzeManifest(Manifest{TargetSDK: 30, NetworkSecurityConfig: "@xml/nsc"})
	if _, ok := titles(fs)["No Network Security Config"]; ok {
		t.Fatal("NSC present should suppress finding")
	}
}

func TestExportedComponentWithFilter(t *testing.T) {
	fs := AnalyzeManifest(Manifest{Components: []Component{
		{Kind: "activity", Name: ".Main", Exported: true, IntentFilters: 1},
	}})
	f, ok := titles(fs)["Exported activity without permission: .Main"]
	if !ok || f.Severity != "MEDIUM" {
		t.Fatalf("expected MEDIUM exported finding, got %#v", fs)
	}
}

func TestExportedComponentNoFilter(t *testing.T) {
	fs := AnalyzeManifest(Manifest{Components: []Component{
		{Kind: "service", Name: ".Sync", Exported: true, IntentFilters: 0},
	}})
	f := titles(fs)["Exported service without permission: .Sync"]
	if f.Severity != "LOW" {
		t.Fatalf("expected LOW, got %q", f.Severity)
	}
}

func TestGuardedComponentNotFlagged(t *testing.T) {
	fs := AnalyzeManifest(Manifest{Components: []Component{
		{Kind: "activity", Name: ".G", Exported: true, HasPermission: true, IntentFilters: 1},
	}})
	if len(fs) != 0 {
		t.Fatalf("guarded exported component should not be flagged, got %#v", fs)
	}
}

func TestSensitivePermissionSortedUnique(t *testing.T) {
	fs := AnalyzeManifest(Manifest{Permissions: []string{
		"android.permission.READ_SMS", "android.permission.CAMERA",
		"android.permission.READ_SMS", "android.permission.INTERNET",
	}})
	var got []string
	for _, f := range fs {
		if strings.HasPrefix(f.Title, "Sensitive permission") {
			got = append(got, f.Evidence)
		}
	}
	want := []string{"android.permission.CAMERA", "android.permission.READ_SMS"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("want sorted unique %v, got %v", want, got)
	}
}

func TestLowMinSdk(t *testing.T) {
	fs := AnalyzeManifest(Manifest{MinSDK: 19})
	if _, ok := titles(fs)["Low minSdkVersion (19)"]; !ok {
		t.Fatal("expected low minSdk finding")
	}
}

func TestHighMinSdkNotFlagged(t *testing.T) {
	fs := AnalyzeManifest(Manifest{MinSDK: 28})
	if _, ok := titles(fs)["Low minSdkVersion (28)"]; ok {
		t.Fatal("minSdk 28 should not be flagged")
	}
}

func TestHardenedManifestClean(t *testing.T) {
	fs := AnalyzeManifest(Manifest{
		Package: "com.acme.app", MinSDK: 28, TargetSDK: 33,
		AllowBackup: false, NetworkSecurityConfig: "@xml/nsc",
		UsesCleartextTraffic: boolPtr(false),
	})
	if len(fs) != 0 {
		t.Fatalf("hardened manifest should be clean, got %#v", fs)
	}
}

func TestRunJSON(t *testing.T) {
	in := strings.NewReader(`{"package":"com.x","debuggable":true,"allow_backup":false}`)
	var out bytes.Buffer
	if err := Run(in, &out); err != nil {
		t.Fatal(err)
	}
	var fs []Finding
	if err := json.Unmarshal(out.Bytes(), &fs); err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Severity != "HIGH" {
		t.Fatalf("expected one HIGH finding, got %#v", fs)
	}
}

func TestRunEmptyArrayNotNull(t *testing.T) {
	in := strings.NewReader(`{"package":"com.x","allow_backup":false}`)
	var out bytes.Buffer
	if err := Run(in, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "[]") {
		t.Fatalf("expected empty JSON array, got %s", out.String())
	}
}

func TestItoa(t *testing.T) {
	cases := map[int]string{0: "0", 7: "7", 24: "24", -5: "-5", 1000: "1000"}
	for n, want := range cases {
		if got := itoa(n); got != want {
			t.Fatalf("itoa(%d)=%q want %q", n, got, want)
		}
	}
}
