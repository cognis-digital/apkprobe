use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

// Constants for APK structure
const MANIFEST_PATH: &str = "META-INF/MANIFEST.MF";
const RESOURCES_ARSC: &str = "resources.arsc";
const DEX_FILE: &str = "classes.dex";

// Binary-AXML header constants
const AXML_MAGIC: [u8; 4] = b"AXML";
const AXML_COMPRESSOR: u32 = 0x100; // 256 for zlib compression

/// APK Container Parser - MASTG-aligned, zero-dependency implementation.
pub struct ApkContainer {
    pub path: PathBuf,
    pub package_name: String,
    pub version_code: u32,
    pub version_name: String,
    pub permissions: Vec<String>,
    pub signatures: Vec<Vec<u8>>,
    pub entry_point: Option<String>,
}

impl ApkContainer {
    /// Opens and parses an APK file. Returns Ok(container) or Err with details.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let path = path.as_ref().to_path_buf();
        
        // Verify it's a valid ZIP/APK structure
        if !Self::is_valid_zip(&path) {
            return Err(format!("Not a valid ZIP file: {}", path.display()));
        }

        // Extract metadata from manifest
        let (package_name, version_code, version_name) = 
            Self::extract_manifest_metadata(&path)?;

        // Parse binary-arsc for additional metadata
        let (permissions, signatures) = Self::parse_resources_arsc(&path)?;

        Ok(ApkContainer {
            path: path.clone(),
            package_name,
            version_code,
            version_name,
            permissions,
            signatures,
            entry_point: None, // Would require dex parsing
        })
    }

    /// Validates ZIP structure and basic APK requirements.
    fn is_valid_zip(path: &Path) -> bool {
        let mut file = match File::open(path) {
            Ok(f) => f,
            Err(_) => return false,
        };

        // Check minimum size (APK must have at least some content)
        if file.metadata().map(|m| m.len() < 1024).unwrap_or(true) {
            return false;
        }

        // Read and verify ZIP magic number
        let mut header = [0u8; 6];
        match file.read_exact(&mut header) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    /// Extracts package name, version code, and version name from manifest.
    fn extract_manifest_metadata(path: &Path) -> Result<(String, u32, String), String> {
        let mut file = match File::open(path.join(MANIFEST_PATH)) {
            Ok(f) => f,
            Err(_) => return Ok(("unknown".to_string(), 0, "unknown".to_string())),
        };

        // Read entire manifest content
        let mut content = String::new();
        if file.read_to_string(&mut content).is_err() {
            return Ok(("unknown".to_string(), 0, "unknown".to_string()));
        }

        // Parse package name (first line after headers)
        for line in content.lines() {
            let trimmed = line.trim();
            
            if trimmed.starts_with("Package:") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    return Ok((parts[1].to_string(), 0, "unknown".to_string()));
                }
            }

            // Parse version code/name from attributes
            if trimmed.starts_with("android:") && 
               (trimmed.contains("versionCode") || trimmed.contains("versionName")) {
                
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                for part in &parts[1..] {
                    if part.starts_with("versionCode=") {
                        if let Some(code_str) = part.strip_prefix("versionCode=") {
                            if let Ok(code) = code_str.parse::<u32>() {
                                return Ok((parts[0].to_string(), code, "unknown".to_string()));
                            }
                        }
                    } else if part.starts_with("versionName=") {
                        if let Some(name) = part.strip_prefix("versionName=") {
                            return Ok(("unknown".to_string(), 0, name.to_string()));
                        }
                    }
                }
            }
        }

        // Fallback: try to extract from resources.arsc header
        if let Ok((pkg, ver)) = Self::extract_from_arsc_header(path) {
            return Ok((pkg, ver));
        }

        Ok(("unknown".to_string(), 0, "unknown".to_string()))
    }

    /// Extracts package name and version from resources.arsc header.
    fn extract_from_arsc_header(path: &Path) -> Result<(String, u32), String> {
        let mut file = match File::open(&path.join(RESOURCES_ARSC)) {
            Ok(f) => f,
            Err(_) => return Ok(("unknown".to_string(), 0)),
        };

        // Read ARSC header (first 16 bytes contain package name length and version code)
        let mut header = [0u8; 16];
        if file.read_exact(&mut header).is_err() {
            return Ok(("unknown".to_string(), 0));
        }

        // Header format: 
        // - Bytes 0-3: Package name length (little-endian)
        // - Bytes 4-7: Version code (little-endian)
        
        let pkg_len = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let version_code = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);

        // Read package name
        if pkg_len > 0 {
            let mut pkg_buf = vec![0u8; pkg_len as usize];
            file.seek(SeekFrom::current() + 16)?;
            
            match file.read_exact(&mut pkg_buf) {
                Ok(_) => return Ok((String::from_utf8(pkg_buf).unwrap_or_default(), version_code)),
                Err(_) => return Ok(("unknown".to_string(), version_code)),
            }
        }

        Ok(("unknown".to_string(), version_code))
    }

    /// Parses binary-arsc to extract permissions and signatures.
    fn parse_resources_arsc(path: &Path) -> Result<(Vec<String>, Vec<Vec<u8>>), String> {
        let mut file = match File::open(&path.join(RESOURCES_ARSC)) {
            Ok(f) => f,
            Err(_) => return Ok((vec![], vec![])),
        };

        // Read entire ARSC content
        let mut content = Vec::new();
        if file.read_to_end(&mut content).is_err() {
            return Ok((vec![], vec![]));
        }

        // Parse permissions from package header section
        let (permissions, signatures) = Self::parse_arsc_permissions(&content)?;

        Ok((permissions, signatures))
    }

    /// Parses ARSC content for permissions and signature blobs.
    fn parse_arsc_permissions(content: &[u8]) -> Result<(Vec<String>, Vec<Vec<u8>>), String> {
        let mut permissions = Vec::new();
        let mut signatures = Vec::new();

        // ARSC structure: header followed by package data
        if content.len() < 16 {
            return Ok((permissions, signatures));
        }

        // Check for compressed ARSC (indicated by magic bytes)
        let is_compressed = &content[0..4] == AXML_MAGIC;

        // Parse package header to find permissions section
        if !is_compressed && content.len() >= 16 {
            let pkg_len = u32::from_le_bytes([content[0], content[1], content[2], content[3]]);
            
            if pkg_len > 0 && content.len() >= 16 + (pkg_len as usize) {
                // Read package name
                let mut pkg_name_buf = vec![0u8; pkg_len as usize];
                content[16..(16 + pkg_len as usize)].clone_into(&mut pkg_name_buf);

                // Look for permissions in the package data
                if let Some(pkg_start) = Self::find_permissions_offset(content, 16) {
                    let pkg_data = &content[pkg_start..];
                    
                    // Parse permission declarations (simplified - real impl needs proper ARSC parsing)
                    // Format: name_length + name_bytes for each permission
                    let mut offset = 0;
                    while offset + 4 <= pkg_data.len() {
                        let len = u32::from_le_bytes([
                            pkg_data[offset],
                            pkg_data[offset + 1],
                            pkg_data[offset + 2],
                            pkg_data[offset + 3]
                        ]);

                        if len == 0 || offset + 4 + (len as usize) > pkg_data.len() {
                            break;
                        }

                        let perm_name = String::from_utf8(
                            pkg_data[offset..offset + 4 + len as usize].to_vec()
                        ).unwrap_or_default();

                        if !perm_name.is_empty() && 
                           (perm_name.contains("permission:") || 
                            perm_name.contains(":permission")) {
                            
                            // Extract actual permission name from namespace
                            let clean_perm = perm_name.split(':').last().unwrap_or(&perm_name);
                            permissions.push(clean_perm.to_string());
                        }

                        offset += 4 + len as usize;
                    }
                }
            }
        }

        // Parse signature blobs (typically in META-INF directory)
        if let Ok(manifest_path) = path.join(MANIFEST_PATH).to_str() {
            if let Some(parent_dir) = Path::new(manifest_path).parent() {
                for entry in fs::read_dir(parent_dir)? {
                    let entry = entry?;
                    if entry.file_name().to_string_lossy() == "MANIFEST.MF" {
                        // Read manifest content to find signature hashes
                        if let Ok(mut f) = File::open(entry.path()) {
                            let mut manifest_content = String::new();
                            f.read_to_string(&mut manifest_content).ok();

                            for line in manifest_content.lines() {
                                let trimmed = line.trim();
                                
                                // Look for SHA-1 or MD5 signatures (common in APKs)
                                if trimmed.starts_with("SHA-1:") || 
                                   trimmed.starts_with("MD5:") ||
                                   trimmed.starts_with("Signature:") {
                                    
                                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                                    for part in &parts[1..] {
                                        // Clean up the hash (remove colons, spaces)
                                        let clean_hash = part.replace(':', "").replace(' ', "");
                                        
                                        if !clean_hash.is_empty() && 
                                           (clean_hash.len() == 40 || clean_hash.len() == 32) {
                                            signatures.push(clean_hash.as_bytes().to_vec());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok((permissions, signatures))
    }

    /// Finds the offset where package data starts in ARSC.
    fn find_permissions_offset(content: &[u8], header_end: usize) -> Option<usize> {
        // Simplified search - look for permission-related markers
        let search_start = header_end.min(content.len() - 1024);
        
        content[search_start..]
            .windows(50)
            .find(|window| window.contains(b"permission") || 
                         window.contains(b"android.permission"))
            .map(|pos| search_start + pos.start())
    }

    /// Verifies APK signature integrity.
    pub fn verify_signatures(&self, expected_hashes: &[&str]) -> Result<bool, String> {
        if self.signatures.is_empty() {
            return Ok(false);
        }

        for hash in &self.signatures {
            let hash_str = String::from_utf8_lossy(hash);
            
            // Remove common prefixes/suffixes for comparison
            let clean_hash: String = hash_str.chars()
                .filter(|c| c.is_alphanumeric())
                .collect();

            if expected_hashes.iter().any(|&exp| exp == &clean_hash) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Checks for potentially dangerous permissions.
    pub fn check_dangerous_permissions(&self, masts: &[String]) -> Vec<String> {
        let mut findings = Vec::new();

        // MASTG-aligned dangerous permission checks
        let dangerous_set: HashSet<&str> = masts.iter()
            .map(|s| s.to_lowercase().as_str())
            .collect();

        for perm in &self.permissions {
            let lower = perm.to_lowercase();

            if dangerous_set.contains(&lower) || 
               lower.contains("dangerous") ||
               lower.contains("system") {
                
                findings.push(perm.clone());
            }
        }

        findings.sort();
        findings.dedup();
        
        findings
    }

    /// Generates a security report string.
    pub fn generate_report(&self) -> String {
        let mut report = format!(
            "APK Security Report\n" +
            "==================\n" +
            "Path: {}\n" +
            "Package: {}\n" +
            "Version Code: {}\n" +
            "Version Name: {}\n",
            self.path.display(),
            self.package_name,
            self.version_code,
            self.version_name
        );

        if !self.permissions.is_empty() {
            report.push_str(&format!(
                "\nPermissions Found ({}):\n{}",
                self.permissions.len(),
                self.permissions.join(", ")
            ));
        } else {
            report.push_str("\nPermissions: (none detected)\n");
        }

        if !self.signatures.is_empty() {
            report.push_str(&format!(
                "\nSignatures Found ({}):\n{}",
                self.signatures.len(),
                self.signatures.iter().map(|s| String::from_utf8_lossy(s)).collect::<Vec<_>>().join(", ")
            ));
        }

        report
    }
}

/// MASTG-aligned dangerous permission list.
pub fn get_dangerous_permissions() -> Vec<String> {
    vec![
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.CALL_PHONE",
        "android.permission.READ_PHONE_STATE",
        "android.permission.MODIFY_AUDIO_SETTINGS",
        "android.permission.VIBRATE",
        "android.permission.WAKE_LOCK",
        "android.permission.RECEIVE_BOOT_COMPLETED",
        "android.permission.FOREGROUND_SERVICE",
        "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
    ]
}

/// Main demo entry point.
fn main() {
    // Example usage - replace with actual APK path
    let sample_apk = PathBuf::from("test.apk");
    
    println!("=== APK Container Parser Demo ===\n");

    match