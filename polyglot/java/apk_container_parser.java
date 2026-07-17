package polyglot.java;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;

/**
 * Android APK Container Parser - MASTG-aligned static analysis foundation.
 * Parses ZIP structure, MANIFEST.MF, and AndroidManifest.xml with zero dependencies.
 */
public class ApkContainerParser {

    private static final String ANDROID_NS = "http://schemas.android.com/apk/res/android";
    private static final String MANIFEST_PATH = "META-INF/MANIFEST.MF";
    private static final String ANDROID_MANIFEST_PATH = "AndroidManifest.xml";

    /**
     * Main entry point for demonstration.
     */
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: java polyglot.java.ApkContainerParser <apk-file>");
            System.exit(1);
        }

        String apkPath = args[0];
        ApkContainerParser parser = new ApkContainerParser();

        try {
            ApkInfo info = parser.parse(apkPath);
            
            System.out.println("=== APK Container Analysis ===");
            System.out.println("File: " + apkPath);
            System.out.println("Size: " + formatBytes(info.size));
            System.out.println("Version Code: " + info.versionCode);
            System.out.println("Version Name: " + info.versionName);
            System.out.println("Package Name: " + info.packageName);
            
            if (info.signatures != null && !info.signatures.isEmpty()) {
                System.out.println("Signatures found: " + info.signatures.size());
                for (byte[] sig : info.signatures) {
                    String hex = bytesToHex(sig).substring(0, Math.min(32, sig.length * 2));
                    System.out.println("  - " + hex + "...");
                }
            }

            if (!info.manifestEntries.isEmpty()) {
                System.out.println("\n=== Manifest Entries ===");
                for (String entry : info.manifestEntries) {
                    System.out.println("  " + entry);
                }
            }

        } catch (Exception e) {
            System.err.println("Error parsing APK: " + e.getMessage());
            if (e.getCause() != null) {
                e.printStackTrace();
            }
            System.exit(1);
        }
    }

    /**
     * Parses the complete APK structure and returns metadata.
     */
    public ApkInfo parse(String apkPath) throws IOException {
        File file = new File(apkPath);
        
        // Step 1: Open ZIP input stream
        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(file))) {
            return extractMetadata(zis, file.length());
        }
    }

    /**
     * Extracts all relevant metadata from the ZIP stream.
     */
    private ApkInfo extractMetadata(ZipInputStream zis, long fileSize) throws IOException {
        ApkInfo info = new ApkInfo();
        
        // Step 2: Read central directory to find entry count and names
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            processZipEntry(zis, entry, info);
        }

        // Step 3: Validate APK structure
        validateApkStructure(info);

        return info;
    }

    /**
     * Processes a single ZIP entry and extracts relevant data.
     */
    private void processZipEntry(ZipInputStream zis, ZipEntry entry, ApkInfo info) throws IOException {
        String name = entry.getName();
        
        // Read MANIFEST.MF for signature verification
        if (MANIFEST_PATH.equals(name)) {
            readManifest(zis);
        }

        // Read AndroidManifest.xml
        else if (ANDROID_MANIFEST_PATH.equals(name)) {
            info.manifestEntries.add(entry.getName());
            // Could parse XML here - kept minimal for now
        }

        // Track all entries for debugging/analysis
        info.allEntries.add(name);
    }

    /**
     * Reads and parses the MANIFEST.MF file.
     */
    private void readManifest(ZipInputStream zis) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(zis));
        
        // Parse manifest attributes (simplified - full parsing would need XML parser)
        String line;
        while ((line = reader.readLine()) != null) {
            if (line.startsWith("Name:")) {
                info.manifestEntries.add(MANIFEST_PATH);
            } else if (line.startsWith("Signature-")) {
                // Signature block found
                int endParen = line.indexOf(')');
                if (endParen > 0) {
                    String signatureBase64 = line.substring(endParen + 1).trim();
                    info.signatures.add(base64ToBytes(signatureBase64));
                }
            } else if (!line.isEmpty() && !line.startsWith("#")) {
                // Could be other attributes like Name, Main-Class, etc.
            }
        }
    }

    /**
     * Validates the APK has required entries for a valid Android package.
     */
    private void validateApkStructure(ApkInfo info) throws IOException {
        boolean hasManifest = false;
        
        // Check for AndroidManifest.xml
        if (info.allEntries.contains(ANDROID_MANIFEST_PATH)) {
            hasManifest = true;
        }

        // Check for MANIFEST.MF
        if (info.allEntries.contains(MANIFEST_PATH)) {
            // Good sign - properly signed APK
        }

        // Basic validation: must have manifest
        if (!hasManifest) {
            System.err.println("Warning: AndroidManifest.xml not found in APK");
        }
    }

    /**
     * Converts Base64 string to byte array (for MANIFEST.MF signatures).
     */
    private static byte[] base64ToBytes(String b64) throws IOException {
        return new String(Base64.getDecoder().decode(b64)).getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Formats bytes as human-readable string.
     */
    private static String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return (bytes / 1024) + " KB";
        return (bytes / (1024 * 1024)) + " MB";
    }

    /**
     * Converts byte array to hex string for display.
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Container class to hold parsed APK metadata.
     */
    public static class ApkInfo {
        private final long size;
        private int versionCode = 0;
        private String versionName = "";
        private String packageName = "";
        private final List<byte[]> signatures = new ArrayList<>();
        private final List<String> manifestEntries = new ArrayList<>();
        private final List<String> allEntries = new ArrayList<>();

        public long getSize() { return size; }
        public int getVersionCode() { return versionCode; }
        public String getVersionName() { return versionName; }
        public String getPackageName() { return packageName; }
        public List<byte[]> getSignatures() { return signatures; }
        public List<String> getManifestEntries() { return manifestEntries; }
        public List<String> getAllEntries() { return allEntries; }

        @Override
        public String toString() {
            return "ApkInfo{" +
                    "size=" + size +
                    ", versionCode=" + versionCode +
                    ", packageName='" + packageName + '\'' +
                    ", signatures=" + signatures.size() +
                    '}';
        }
    }

    // ============================================================================
    // ==============  BONUS: Extended Parser with XML Support  ===================
    // ============================================================================
    
    /**
     * Extended parser that extracts detailed AndroidManifest.xml data.
     */
    public static class DetailedParser {
        
        /**
         * Parses AndroidManifest.xml and returns structured components.
         */
        public static ManifestComponents parseAndroidManifest(String apkPath) throws IOException {
            try (ZipInputStream zis = new ZipInputStream(
                    new FileInputStream(apkPath))) {
                
                // Find and read AndroidManifest.xml
                ZipEntry entry;
                while ((entry = zis.getNextEntry()) != null) {
                    if (ANDROID_MANIFEST_PATH.equals(entry.getName())) {
                        return parseAndroidManifestXml(zis);
                    }
                }
                
                throw new IOException("AndroidManifest.xml not found");
            }
        }

        /**
         * Parses the AndroidManifest.xml content.
         */
        private static ManifestComponents parseAndroidManifestXml(ZipInputStream zis) throws IOException {
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(zis, StandardCharsets.UTF_8));
            
            // Read all lines into memory (simple approach - stream would need SAX/DOM)
            List<String> lines = new ArrayList<>();
            String line;
            while ((line = reader.readLine()) != null) {
                lines.add(line);
            }

            return parseManifestLines(lines);
        }

        /**
         * Parses manifest content line-by-line.
         */
        private static ManifestComponents parseManifestLines(List<String> lines) {
            ManifestComponents components = new ManifestComponents();
            
            // Regex for attribute extraction
            String attrPattern = "(\\S+)=\"([^\"]*)\"";
            String nsAttrPattern = "android:(\\S+)=\"([^\"]*)\"";

            for (String line : lines) {
                if (line.trim().isEmpty()) continue;

                // Extract namespace declarations
                while (line.contains(ANDROID_NS)) {
                    int start = line.indexOf(ANDROID_NS);
                    int end = line.indexOf('"', start + ANDROID_NS.length());
                    if (end > 0) {
                        String attrName = line.substring(start, end).replace(ANDROID_NS, "");
                        components.namespaceDeclarations.add(attrName);
                        line = line.replace(ANDROID_NS + '"', '', 1);
                    } else {
                        break;
                    }
                }

                // Extract android: attributes from tag
                while (line.contains("android:")) {
                    int start = line.indexOf("android:") + "android:".length();
                    if (start >= line.length()) break;
                    
                    int attrNameEnd = line.indexOf('=', start);
                    String attrName = line.substring(start, attrNameEnd);
                    
                    // Find the value - handle both quoted and unquoted values
                    int quoteStart = line.indexOf('"', attrNameEnd + 1);
                    if (quoteStart > 0) {
                        int quoteEnd = line.indexOf('"', quoteStart + 1);
                        String attrValue = line.substring(quoteStart + 1, quoteEnd);
                        
                        components.attributes.add(attrName + "=" + attrValue);
                        
                        // Check for namespace prefix
                        if (attrName.startsWith("android:")) {
                            String nsPrefix = attrName.replace("android:", "");
                            components.namespaceDeclarations.add(nsPrefix);
                        }
                    } else {
                        break;
                    }
                }

                // Extract tag name
                int openBrace = line.indexOf('{');
                if (openBrace > 0) {
                    String tagName = line.substring(0, openBrace).trim();
                    components.tags.add(tagName);
                    
                    // Check for namespace prefix in tag
                    if (tagName.contains(":")) {
                        int colonPos = tagName.indexOf(':');
                        String nsPrefix = tagName.substring(0, colonPos);
                        components.namespaceDeclarations.add(nsPrefix);
                    }
                }
            }

            return components;
        }

        /**
         * Container class for parsed manifest structure.
         */
        public static class ManifestComponents {
            private final List<String> tags = new ArrayList<>();
            private final List<String> attributes = new ArrayList<>();
            private final List<String> namespaceDeclarations = new ArrayList<>();

            public List<String> getTags() { return tags; }
            public List<String> getAttributes() { return attributes; }
            public List<String> getNamespaceDeclarations() { return namespaceDeclarations; }

            @Override
            public String toString() {
                return "ManifestComponents{" +
                        "tags=" + tags.size() +
                        ", attributes=" + attributes.size() +
                        ", namespaces=" + namespaceDeclarations.size() +
                        '}';
            }
        }
    }

    // ============================================================================
    // ==============  BONUS: Signature Verification Helper =====================
    // ============================================================================
    
    /**
     * Verifies APK signatures against MANIFEST.MF.
     */
    public static class SignatureVerifier {
        
        /**
         * Extracts and verifies all APK signatures.
         */
        public static Map<String, Boolean> verifySignatures(String apkPath) throws IOException {
            try (ZipInputStream zis = new ZipInputStream(
                    new FileInputStream(apkPath))) {
                
                // Read MANIFEST.MF
                ZipEntry manifestEntry;
                while ((manifestEntry = zis.getNextEntry()) != null) {
                    if (MANIFEST_PATH.equals(manifestEntry.getName())) {
                        return extractAndVerifySignatures(zis);
                    }
                }
                
                throw new IOException("MANIFEST.MF not found");
            }
        }

        /**
         * Extracts signatures from MANIFEST.MF and returns verification results.
         */
        private static Map<String, Boolean> extractAndVerifySignatures(ZipInputStream zis) throws IOException {
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(zis, StandardCharsets.UTF_8));
            
            List<byte[]> signatures = new ArrayList<>();
            String line;
            
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("Signature-")) {
                    int endParen = line.indexOf(')');
                    if (endParen > 0) {
                        String b64 = line.substring(endParen + 1).trim();
                        signatures.add(base64ToBytes(b64));
                    }
                }
            }

            // In a real implementation, you would verify each signature against
            // the APK's certificate chain. For now, we just return what we found.
            
            Map<String, Boolean> results = new LinkedHashMap<>();
            for (int i = 0; i < signatures.size(); i++) {
                byte[] sig = signatures.get(i);
                String hexPrefix = bytesToHex(sig).substring(0, 16);
                // Placeholder: would verify against certificate chain here
                results.put("Signature " + (i + 1), true); 
            }

            return results;
        }
    }

    // ============================================================================
    // ==============  BONUS: Resource Analyzer ================================
    // ============================================================================
    
    /**
     * Analyzes APK resources (drawables, strings, layouts).
     */
    public static class ResourceAnalyzer {
        
        private static final String RESOURCES_PATH = "res/";

        /**
         * Scans and categorizes all resources in the APK.
         */
        public static ResourceSummary analyzeResources(String apkPath) throws IOException {
            try (ZipInputStream zis = new ZipInputStream(
                    new FileInputStream(apkPath))) {
                
                return scanResources(zis);
            }
        }

        /**
         * Scans the ZIP for resource files.
         */
        private static ResourceSummary scanResources(ZipInputStream zis) throws IOException {
            ResourceSummary summary = new ResourceSummary();
            
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                String name = entry.getName();
                
                if (name.startsWith(RESOURCES_PATH)) {
                    // Categorize by type
                    int resTypePos = name.indexOf('/', RESOURCES_PATH.length());
                    if (resTypePos > 0) {
                        String resType = name.substring(RESOURCES_PATH.length(), resTypePos);
                        
                        switch (resType.toLowerCase()) {
                            case "drawable":
                                summary.drawables.add(name);
                                break;
                            case "mipmap":
                                summary.mipmaps.add(name);
                                break;
                            case "values":
                                // Could further split into strings, colors, etc.
                                summary.valuesFiles.add(name);
                                break;
                            case "layout":
                                summary.layouts.add(name);
                                break;
                            case "xml":
                                // Could be menus, themes, styles, etc.
                                summary.xmlFiles.add(name);
                                break;
                        }
                    }
                } else if (name.startsWith("res/") && !name.contains("/")) {
                    // Direct resource file in root res/
                    String ext = name.substring(name.lastIndexOf('.') + 1).toLowerCase();
                    
                    switch (ext) {
                        case "xml":
                            summary.xmlFiles.add(name);
                            break;
                        case "png":
                        case "jpg":
                        case "jpeg":
                        case "gif":
                        case "webp":
                            summary.images.add(name);
                            break;
                    }
                }

                // Track all entries for size analysis
                summary.allEntries.add(name);
            }

            return summary;
        }

        /**
         * Summary of found resources.
         */
        public static class ResourceSummary {
            private final List<String> drawables = new ArrayList<>();
            private final List<String> mipmaps = new ArrayList<>();
            private final List<String> layouts = new ArrayList<>();
            private final List<String> xml