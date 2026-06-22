use apkprobe_rules::{analyze_manifest, json, manifest_from_json, run, Component, Manifest};

fn base() -> Manifest {
    Manifest::default()
}

#[test]
fn debuggable_high() {
    let mut m = base();
    m.debuggable = true;
    let fs = analyze_manifest(&m);
    assert!(fs.iter().any(|f| f.title == "Application is debuggable" && f.severity == "HIGH"));
}

#[test]
fn allow_backup_medium() {
    let mut m = base();
    m.allow_backup = true;
    let fs = analyze_manifest(&m);
    assert!(fs.iter().any(|f| f.title == "ADB backup allowed" && f.severity == "MEDIUM"));
}

#[test]
fn cleartext_true() {
    let mut m = base();
    m.uses_cleartext_traffic = Some(true);
    let fs = analyze_manifest(&m);
    assert!(fs.iter().any(|f| f.title == "Cleartext (HTTP) traffic permitted"));
}

#[test]
fn cleartext_false_suppresses_nsc() {
    let mut m = base();
    m.target_sdk = 33;
    m.uses_cleartext_traffic = Some(false);
    let fs = analyze_manifest(&m);
    assert!(!fs.iter().any(|f| f.title == "No Network Security Config"));
}

#[test]
fn nsc_when_target_high_and_unset() {
    let mut m = base();
    m.target_sdk = 30;
    let fs = analyze_manifest(&m);
    assert!(fs.iter().any(|f| f.title == "No Network Security Config"));
}

#[test]
fn nsc_present_suppresses() {
    let mut m = base();
    m.target_sdk = 30;
    m.network_security_config = "@xml/nsc".into();
    let fs = analyze_manifest(&m);
    assert!(!fs.iter().any(|f| f.title == "No Network Security Config"));
}

#[test]
fn exported_with_filter_medium() {
    let mut m = base();
    m.components.push(Component {
        kind: "activity".into(),
        name: ".Main".into(),
        exported: true,
        has_permission: false,
        intent_filters: 1,
    });
    let fs = analyze_manifest(&m);
    let f = fs.iter().find(|f| f.title.contains(".Main")).unwrap();
    assert_eq!(f.severity, "MEDIUM");
}

#[test]
fn exported_no_filter_low() {
    let mut m = base();
    m.components.push(Component {
        kind: "service".into(),
        name: ".Sync".into(),
        exported: true,
        has_permission: false,
        intent_filters: 0,
    });
    let fs = analyze_manifest(&m);
    let f = fs.iter().find(|f| f.title.contains(".Sync")).unwrap();
    assert_eq!(f.severity, "LOW");
}

#[test]
fn guarded_component_not_flagged() {
    let mut m = base();
    m.components.push(Component {
        kind: "activity".into(),
        name: ".G".into(),
        exported: true,
        has_permission: true,
        intent_filters: 1,
    });
    assert!(analyze_manifest(&m).is_empty());
}

#[test]
fn sensitive_permissions_sorted_unique() {
    let mut m = base();
    m.permissions = vec![
        "android.permission.READ_SMS".into(),
        "android.permission.CAMERA".into(),
        "android.permission.READ_SMS".into(),
        "android.permission.INTERNET".into(),
    ];
    let evidences: Vec<String> = analyze_manifest(&m)
        .into_iter()
        .filter(|f| f.title.starts_with("Sensitive permission"))
        .map(|f| f.evidence)
        .collect();
    assert_eq!(
        evidences,
        vec![
            "android.permission.CAMERA".to_string(),
            "android.permission.READ_SMS".to_string()
        ]
    );
}

#[test]
fn low_min_sdk() {
    let mut m = base();
    m.min_sdk = 19;
    let fs = analyze_manifest(&m);
    assert!(fs.iter().any(|f| f.title == "Low minSdkVersion (19)"));
}

#[test]
fn high_min_sdk_clean() {
    let mut m = base();
    m.min_sdk = 28;
    assert!(analyze_manifest(&m).iter().all(|f| !f.title.starts_with("Low minSdk")));
}

#[test]
fn hardened_manifest_clean() {
    let mut m = base();
    m.package = "com.acme.app".into();
    m.min_sdk = 28;
    m.target_sdk = 33;
    m.allow_backup = false;
    m.network_security_config = "@xml/nsc".into();
    m.uses_cleartext_traffic = Some(false);
    assert!(analyze_manifest(&m).is_empty());
}

#[test]
fn json_parse_roundtrip() {
    let v = json::parse(r#"{"package":"com.x","debuggable":true,"min_sdk":21}"#).unwrap();
    let m = manifest_from_json(&v);
    assert_eq!(m.package, "com.x");
    assert!(m.debuggable);
    assert_eq!(m.min_sdk, 21);
}

#[test]
fn json_null_cleartext_is_none() {
    let v = json::parse(r#"{"uses_cleartext_traffic":null}"#).unwrap();
    let m = manifest_from_json(&v);
    assert_eq!(m.uses_cleartext_traffic, None);
}

#[test]
fn json_components_parsed() {
    let v = json::parse(
        r#"{"components":[{"kind":"activity","name":".A","exported":true,"intent_filters":2}]}"#,
    )
    .unwrap();
    let m = manifest_from_json(&v);
    assert_eq!(m.components.len(), 1);
    assert_eq!(m.components[0].intent_filters, 2);
}

#[test]
fn run_emits_array() {
    let out = run(r#"{"package":"com.x","debuggable":true,"allow_backup":false}"#).unwrap();
    assert!(out.contains("Application is debuggable"));
    assert!(out.starts_with('['));
}

#[test]
fn run_empty_is_empty_array() {
    let out = run(r#"{"package":"com.x","allow_backup":false}"#).unwrap();
    assert_eq!(out, "[]");
}

#[test]
fn json_escape_quotes() {
    assert_eq!(json::escape("a\"b\\c"), "a\\\"b\\\\c");
}
