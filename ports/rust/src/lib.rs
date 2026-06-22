//! Rust port of apkprobe's core MASVS/MASTG manifest rule engine
//! (see `apkprobe/rules.py`). Consumes a normalized manifest JSON and emits the
//! same findings as the Python reference. Defensive, offline: no network, no
//! device. Dependency-free (hand-rolled minimal JSON) so CI needs no crates.

use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq)]
pub struct Component {
    pub kind: String,
    pub name: String,
    pub exported: bool,
    pub has_permission: bool,
    pub intent_filters: i64,
}

#[derive(Debug, Clone, Default)]
pub struct Manifest {
    pub package: String,
    pub min_sdk: i64,
    pub target_sdk: i64,
    pub debuggable: bool,
    pub allow_backup: bool,
    pub uses_cleartext_traffic: Option<bool>,
    pub network_security_config: String,
    pub permissions: Vec<String>,
    pub components: Vec<Component>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub title: String,
    pub severity: String,
    pub masvs: String,
    pub mastg_test: String,
    pub evidence: String,
}

pub fn sensitive_permissions() -> BTreeSet<&'static str> {
    [
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
    ]
    .into_iter()
    .collect()
}

pub fn analyze_manifest(m: &Manifest) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut add = |title: String, sev: &str, masvs: &str, mastg: &str, ev: String| {
        out.push(Finding {
            title,
            severity: sev.to_string(),
            masvs: masvs.to_string(),
            mastg_test: mastg.to_string(),
            evidence: ev,
        });
    };

    if m.debuggable {
        add(
            "Application is debuggable".into(),
            "HIGH",
            "MASVS-RESILIENCE-2",
            "MASTG-TEST-0026",
            "android:debuggable=\"true\"".into(),
        );
    }
    if m.allow_backup {
        add(
            "ADB backup allowed".into(),
            "MEDIUM",
            "MASVS-STORAGE-2",
            "MASTG-TEST-0009",
            "android:allowBackup=\"true\"".into(),
        );
    }
    if m.uses_cleartext_traffic == Some(true) {
        add(
            "Cleartext (HTTP) traffic permitted".into(),
            "HIGH",
            "MASVS-NETWORK-1",
            "MASTG-TEST-0019",
            "android:usesCleartextTraffic=\"true\"".into(),
        );
    }
    if m.target_sdk >= 24
        && m.network_security_config.is_empty()
        && m.uses_cleartext_traffic != Some(false)
    {
        add(
            "No Network Security Config".into(),
            "LOW",
            "MASVS-NETWORK-2",
            "MASTG-TEST-0020",
            format!("targetSdk={}, no android:networkSecurityConfig", m.target_sdk),
        );
    }
    for c in &m.components {
        if c.exported && !c.has_permission {
            let sev = if c.intent_filters > 0 { "MEDIUM" } else { "LOW" };
            add(
                format!("Exported {} without permission: {}", c.kind, c.name),
                sev,
                "MASVS-PLATFORM-1",
                "MASTG-TEST-0024",
                format!(
                    "{} {} exported=true, permission=none, intent-filters={}",
                    c.kind, c.name, c.intent_filters
                ),
            );
        }
    }
    let sensitive = sensitive_permissions();
    let present: BTreeSet<String> = m
        .permissions
        .iter()
        .filter(|p| sensitive.contains(p.as_str()))
        .cloned()
        .collect();
    for p in &present {
        add(
            format!("Sensitive permission requested: {}", p),
            "INFO",
            "MASVS-PLATFORM-1",
            "MASTG-TEST-0024",
            p.clone(),
        );
    }
    if m.min_sdk > 0 && m.min_sdk < 24 {
        add(
            format!("Low minSdkVersion ({})", m.min_sdk),
            "LOW",
            "MASVS-RESILIENCE-1",
            "",
            format!("minSdkVersion={}", m.min_sdk),
        );
    }
    out
}

// ---------------------------------------------------------------------------
// Minimal JSON: just enough to parse the normalized manifest and serialize
// findings. Dependency-free so the port builds with no crate downloads.
// ---------------------------------------------------------------------------

pub mod json {
    use std::collections::BTreeMap;

    #[derive(Debug, Clone, PartialEq)]
    pub enum Value {
        Null,
        Bool(bool),
        Num(f64),
        Str(String),
        Arr(Vec<Value>),
        Obj(BTreeMap<String, Value>),
    }

    impl Value {
        pub fn get(&self, k: &str) -> Option<&Value> {
            match self {
                Value::Obj(m) => m.get(k),
                _ => None,
            }
        }
        pub fn as_bool(&self) -> Option<bool> {
            match self {
                Value::Bool(b) => Some(*b),
                _ => None,
            }
        }
        pub fn as_i64(&self) -> Option<i64> {
            match self {
                Value::Num(n) => Some(*n as i64),
                _ => None,
            }
        }
        pub fn as_str(&self) -> Option<&str> {
            match self {
                Value::Str(s) => Some(s),
                _ => None,
            }
        }
        pub fn as_arr(&self) -> Option<&Vec<Value>> {
            match self {
                Value::Arr(a) => Some(a),
                _ => None,
            }
        }
    }

    pub fn parse(s: &str) -> Result<Value, String> {
        let bytes: Vec<char> = s.chars().collect();
        let mut p = Parser { c: bytes, i: 0 };
        p.skip_ws();
        let v = p.value()?;
        p.skip_ws();
        Ok(v)
    }

    struct Parser {
        c: Vec<char>,
        i: usize,
    }

    impl Parser {
        fn peek(&self) -> Option<char> {
            self.c.get(self.i).copied()
        }
        fn next(&mut self) -> Option<char> {
            let ch = self.c.get(self.i).copied();
            self.i += 1;
            ch
        }
        fn skip_ws(&mut self) {
            while let Some(ch) = self.peek() {
                if ch.is_whitespace() {
                    self.i += 1;
                } else {
                    break;
                }
            }
        }
        fn value(&mut self) -> Result<Value, String> {
            self.skip_ws();
            match self.peek() {
                Some('{') => self.object(),
                Some('[') => self.array(),
                Some('"') => Ok(Value::Str(self.string()?)),
                Some('t') | Some('f') => self.boolean(),
                Some('n') => self.null(),
                Some(c) if c == '-' || c.is_ascii_digit() => self.number(),
                other => Err(format!("unexpected token: {:?}", other)),
            }
        }
        fn object(&mut self) -> Result<Value, String> {
            self.next(); // {
            let mut map = BTreeMap::new();
            self.skip_ws();
            if self.peek() == Some('}') {
                self.next();
                return Ok(Value::Obj(map));
            }
            loop {
                self.skip_ws();
                let key = self.string()?;
                self.skip_ws();
                if self.next() != Some(':') {
                    return Err("expected ':'".into());
                }
                let val = self.value()?;
                map.insert(key, val);
                self.skip_ws();
                match self.next() {
                    Some(',') => continue,
                    Some('}') => break,
                    other => return Err(format!("expected ',' or '}}', got {:?}", other)),
                }
            }
            Ok(Value::Obj(map))
        }
        fn array(&mut self) -> Result<Value, String> {
            self.next(); // [
            let mut arr = Vec::new();
            self.skip_ws();
            if self.peek() == Some(']') {
                self.next();
                return Ok(Value::Arr(arr));
            }
            loop {
                let v = self.value()?;
                arr.push(v);
                self.skip_ws();
                match self.next() {
                    Some(',') => continue,
                    Some(']') => break,
                    other => return Err(format!("expected ',' or ']', got {:?}", other)),
                }
            }
            Ok(Value::Arr(arr))
        }
        fn string(&mut self) -> Result<String, String> {
            if self.next() != Some('"') {
                return Err("expected string".into());
            }
            let mut s = String::new();
            while let Some(ch) = self.next() {
                match ch {
                    '"' => return Ok(s),
                    '\\' => match self.next() {
                        Some('"') => s.push('"'),
                        Some('\\') => s.push('\\'),
                        Some('/') => s.push('/'),
                        Some('n') => s.push('\n'),
                        Some('t') => s.push('\t'),
                        Some('r') => s.push('\r'),
                        Some('b') => s.push('\u{0008}'),
                        Some('f') => s.push('\u{000C}'),
                        Some('u') => {
                            let mut code = 0u32;
                            for _ in 0..4 {
                                let d = self.next().ok_or("bad \\u")?;
                                code = code * 16 + d.to_digit(16).ok_or("bad hex")?;
                            }
                            s.push(char::from_u32(code).unwrap_or('\u{FFFD}'));
                        }
                        other => return Err(format!("bad escape {:?}", other)),
                    },
                    c => s.push(c),
                }
            }
            Err("unterminated string".into())
        }
        fn boolean(&mut self) -> Result<Value, String> {
            if self.c[self.i..].starts_with(&['t', 'r', 'u', 'e']) {
                self.i += 4;
                Ok(Value::Bool(true))
            } else if self.c[self.i..].starts_with(&['f', 'a', 'l', 's', 'e']) {
                self.i += 5;
                Ok(Value::Bool(false))
            } else {
                Err("bad bool".into())
            }
        }
        fn null(&mut self) -> Result<Value, String> {
            if self.c[self.i..].starts_with(&['n', 'u', 'l', 'l']) {
                self.i += 4;
                Ok(Value::Null)
            } else {
                Err("bad null".into())
            }
        }
        fn number(&mut self) -> Result<Value, String> {
            let start = self.i;
            if self.peek() == Some('-') {
                self.i += 1;
            }
            while let Some(ch) = self.peek() {
                if ch.is_ascii_digit() || ch == '.' || ch == 'e' || ch == 'E' || ch == '+' || ch == '-' {
                    self.i += 1;
                } else {
                    break;
                }
            }
            let raw: String = self.c[start..self.i].iter().collect();
            raw.parse::<f64>().map(Value::Num).map_err(|e| e.to_string())
        }
    }

    pub fn escape(s: &str) -> String {
        let mut out = String::with_capacity(s.len() + 2);
        for ch in s.chars() {
            match ch {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\t' => out.push_str("\\t"),
                '\r' => out.push_str("\\r"),
                c => out.push(c),
            }
        }
        out
    }
}

pub fn manifest_from_json(v: &json::Value) -> Manifest {
    let mut m = Manifest::default();
    if let Some(s) = v.get("package").and_then(|x| x.as_str()) {
        m.package = s.to_string();
    }
    m.min_sdk = v.get("min_sdk").and_then(|x| x.as_i64()).unwrap_or(0);
    m.target_sdk = v.get("target_sdk").and_then(|x| x.as_i64()).unwrap_or(0);
    m.debuggable = v.get("debuggable").and_then(|x| x.as_bool()).unwrap_or(false);
    m.allow_backup = v.get("allow_backup").and_then(|x| x.as_bool()).unwrap_or(false);
    m.uses_cleartext_traffic = match v.get("uses_cleartext_traffic") {
        Some(json::Value::Bool(b)) => Some(*b),
        _ => None,
    };
    if let Some(s) = v.get("network_security_config").and_then(|x| x.as_str()) {
        m.network_security_config = s.to_string();
    }
    if let Some(arr) = v.get("permissions").and_then(|x| x.as_arr()) {
        for p in arr {
            if let Some(s) = p.as_str() {
                m.permissions.push(s.to_string());
            }
        }
    }
    if let Some(arr) = v.get("components").and_then(|x| x.as_arr()) {
        for c in arr {
            m.components.push(Component {
                kind: c.get("kind").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                name: c.get("name").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                exported: c.get("exported").and_then(|x| x.as_bool()).unwrap_or(false),
                has_permission: c.get("has_permission").and_then(|x| x.as_bool()).unwrap_or(false),
                intent_filters: c.get("intent_filters").and_then(|x| x.as_i64()).unwrap_or(0),
            });
        }
    }
    m
}

pub fn findings_to_json(fs: &[Finding]) -> String {
    let mut parts = Vec::new();
    for f in fs {
        parts.push(format!(
            "{{\"title\":\"{}\",\"severity\":\"{}\",\"masvs\":\"{}\",\"mastg_test\":\"{}\",\"evidence\":\"{}\"}}",
            json::escape(&f.title),
            json::escape(&f.severity),
            json::escape(&f.masvs),
            json::escape(&f.mastg_test),
            json::escape(&f.evidence),
        ));
    }
    format!("[{}]", parts.join(","))
}

pub fn run(input: &str) -> Result<String, String> {
    let v = json::parse(input)?;
    let m = manifest_from_json(&v);
    Ok(findings_to_json(&analyze_manifest(&m)))
}
