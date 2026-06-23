/*
 * apkprobe-kt — Kotlin port of apkprobe's core MASVS/MASTG manifest rule engine
 * (see apkprobe/rules.py and the Go/Rust/TS ports). Consumes a normalized
 * manifest JSON and emits the same findings as the Python reference.
 * Kotlin is the native Android language, so this port is the natural home for
 * apkprobe's manifest checks. Defensive, offline — no network or device access.
 *
 * Stdlib only (no Gradle / no third-party deps): includes a tiny JSON reader so
 * it compiles with a bare `kotlinc`.
 */

data class Component(
    val kind: String = "",
    val name: String = "",
    val exported: Boolean = false,
    val hasPermission: Boolean = false,
    val intentFilters: Int = 0,
)

data class Manifest(
    val pkg: String = "",
    val minSdk: Int = 0,
    val targetSdk: Int = 0,
    val debuggable: Boolean = false,
    val allowBackup: Boolean = false,
    val usesCleartextTraffic: Boolean? = null, // null = unset
    val networkSecurityConfig: String = "",
    val permissions: List<String> = emptyList(),
    val components: List<Component> = emptyList(),
)

data class Finding(
    val title: String,
    val severity: String,
    val masvs: String,
    val mastgTest: String,
    val evidence: String,
)

val SENSITIVE_PERMISSIONS = setOf(
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
)

/** Runs the MASVS/MASTG checks over [m], in the same order as the reference. */
fun analyzeManifest(m: Manifest): List<Finding> {
    val out = ArrayList<Finding>()
    fun add(title: String, sev: String, masvs: String, mastg: String, ev: String) =
        out.add(Finding(title, sev, masvs, mastg, ev))

    if (m.debuggable)
        add("Application is debuggable", "HIGH", "MASVS-RESILIENCE-2",
            "MASTG-TEST-0026", "android:debuggable=\"true\"")
    if (m.allowBackup)
        add("ADB backup allowed", "MEDIUM", "MASVS-STORAGE-2",
            "MASTG-TEST-0009", "android:allowBackup=\"true\"")
    if (m.usesCleartextTraffic == true)
        add("Cleartext (HTTP) traffic permitted", "HIGH", "MASVS-NETWORK-1",
            "MASTG-TEST-0019", "android:usesCleartextTraffic=\"true\"")
    if (m.targetSdk >= 24 && m.networkSecurityConfig.isEmpty() &&
        m.usesCleartextTraffic != false)
        add("No Network Security Config", "LOW", "MASVS-NETWORK-2",
            "MASTG-TEST-0020",
            "targetSdk=${m.targetSdk}, no android:networkSecurityConfig")

    for (c in m.components) {
        if (c.exported && !c.hasPermission) {
            val sev = if (c.intentFilters > 0) "MEDIUM" else "LOW"
            add("Exported ${c.kind} without permission: ${c.name}", sev,
                "MASVS-PLATFORM-1", "MASTG-TEST-0024",
                "${c.kind} ${c.name} exported=true, permission=none, " +
                    "intent-filters=${c.intentFilters}")
        }
    }

    for (p in m.permissions.filter { it in SENSITIVE_PERMISSIONS }.distinct().sorted())
        add("Sensitive permission requested: $p", "INFO",
            "MASVS-PLATFORM-1", "MASTG-TEST-0024", p)

    if (m.minSdk in 1 until 24)
        add("Low minSdkVersion (${m.minSdk})", "LOW", "MASVS-RESILIENCE-1", "",
            "minSdkVersion=${m.minSdk}")

    return out
}

// ---- JSON (minimal, stdlib-only) ------------------------------------------

private fun jesc(s: String) = s.replace("\\", "\\\\").replace("\"", "\\\"")

fun findingsToJson(fs: List<Finding>): String =
    "[" + fs.joinToString(",") { f ->
        """{"title":"${jesc(f.title)}","severity":"${f.severity}",""" +
        """"masvs":"${f.masvs}","mastg_test":"${f.mastgTest}",""" +
        """"evidence":"${jesc(f.evidence)}"}"""
    } + "]"

/** Tiny recursive-descent JSON reader → Map/List/String/Double/Boolean/null. */
class JsonReader(private val s: String) {
    private var i = 0
    fun parse(): Any? { val v = value(); ws(); return v }
    private fun ws() { while (i < s.length && s[i].isWhitespace()) i++ }
    private fun value(): Any? {
        ws()
        return when (s[i]) {
            '{' -> obj(); '[' -> arr(); '"' -> str()
            't' -> { i += 4; true }
            'f' -> { i += 5; false }
            'n' -> { i += 4; null }
            else -> num()
        }
    }
    private fun obj(): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>(); i++; ws()
        if (s[i] == '}') { i++; return m }
        while (true) {
            ws(); val k = str(); ws(); i++ /* : */; m[k] = value(); ws()
            if (s[i] == ',') i++ else { i++; break }
        }
        return m
    }
    private fun arr(): List<Any?> {
        val l = ArrayList<Any?>(); i++; ws()
        if (s[i] == ']') { i++; return l }
        while (true) {
            l.add(value()); ws()
            if (s[i] == ',') i++ else { i++; break }
        }
        return l
    }
    private fun str(): String {
        val sb = StringBuilder(); i++ /* opening quote */
        while (s[i] != '"') {
            if (s[i] == '\\') {
                i++
                sb.append(when (s[i]) {
                    'n' -> '\n'; 't' -> '\t'; 'r' -> '\r'
                    '"' -> '"'; '\\' -> '\\'; '/' -> '/'; else -> s[i]
                })
            } else sb.append(s[i])
            i++
        }
        i++; return sb.toString()
    }
    private fun num(): Double {
        val start = i
        while (i < s.length && (s[i].isDigit() || s[i] in "-+.eE")) i++
        return s.substring(start, i).toDouble()
    }
}

@Suppress("UNCHECKED_CAST")
fun manifestFromJson(json: String): Manifest {
    val m = (JsonReader(json).parse() as? Map<String, Any?>) ?: emptyMap()
    fun str(k: String) = m[k] as? String ?: ""
    fun bool(k: String) = m[k] as? Boolean ?: false
    fun int(k: String) = (m[k] as? Double)?.toInt() ?: 0
    val perms = (m["permissions"] as? List<*>)?.mapNotNull { it as? String } ?: emptyList()
    val comps = (m["components"] as? List<*>)?.mapNotNull { c ->
        val cm = c as? Map<*, *> ?: return@mapNotNull null
        Component(
            kind = cm["kind"] as? String ?: "",
            name = cm["name"] as? String ?: "",
            exported = cm["exported"] as? Boolean ?: false,
            hasPermission = cm["has_permission"] as? Boolean ?: false,
            intentFilters = (cm["intent_filters"] as? Double)?.toInt() ?: 0,
        )
    } ?: emptyList()
    return Manifest(
        pkg = str("package"),
        minSdk = int("min_sdk"),
        targetSdk = int("target_sdk"),
        debuggable = bool("debuggable"),
        allowBackup = bool("allow_backup"),
        usesCleartextTraffic = m["uses_cleartext_traffic"] as? Boolean,
        networkSecurityConfig = str("network_security_config"),
        permissions = perms,
        components = comps,
    )
}
