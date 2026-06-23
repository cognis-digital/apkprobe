/*
 * Self-contained test runner (no JUnit/Gradle) — mirrors the Go/Rust/TS port
 * tests so all ports prove identical behaviour. Exits non-zero on first failure.
 *   java -cp apkprobe-kt.jar TestKt
 */
private var failures = 0

private fun check(cond: Boolean, msg: String) {
    if (cond) {
        println("  ok: $msg")
    } else {
        println("  FAIL: $msg"); failures++
    }
}

private fun titles(fs: List<Finding>) = fs.associateBy { it.title }

fun main() {
    // debuggable -> HIGH
    titles(analyzeManifest(Manifest(debuggable = true)))["Application is debuggable"].let {
        check(it != null && it.severity == "HIGH", "debuggable is HIGH")
    }
    // allowBackup -> finding
    check("ADB backup allowed" in titles(analyzeManifest(Manifest(allowBackup = true))),
        "allowBackup flagged")
    // cleartext true -> finding
    check("Cleartext (HTTP) traffic permitted" in
        titles(analyzeManifest(Manifest(usesCleartextTraffic = true))), "cleartext=true flagged")
    // cleartext false suppresses NSC
    check("No Network Security Config" !in
        titles(analyzeManifest(Manifest(targetSdk = 33, usesCleartextTraffic = false))),
        "cleartext=false suppresses NSC")
    // NSC when target high and unset
    check("No Network Security Config" in
        titles(analyzeManifest(Manifest(targetSdk = 30))), "NSC flagged when unset")
    // NSC not flagged when configured
    check("No Network Security Config" !in
        titles(analyzeManifest(Manifest(targetSdk = 30, networkSecurityConfig = "@xml/nsc"))),
        "NSC present suppresses finding")
    // exported with intent filter -> MEDIUM
    titles(analyzeManifest(Manifest(components = listOf(
        Component("activity", ".Main", exported = true, intentFilters = 1)
    ))))["Exported activity without permission: .Main"].let {
        check(it != null && it.severity == "MEDIUM", "exported+filter is MEDIUM")
    }
    // exported no filter -> LOW
    titles(analyzeManifest(Manifest(components = listOf(
        Component("service", ".Sync", exported = true, intentFilters = 0)
    ))))["Exported service without permission: .Sync"].let {
        check(it != null && it.severity == "LOW", "exported no-filter is LOW")
    }
    // guarded component not flagged
    check(analyzeManifest(Manifest(components = listOf(
        Component("activity", ".G", exported = true, hasPermission = true, intentFilters = 1)
    ))).isEmpty(), "guarded exported component not flagged")
    // sensitive perms sorted + unique
    val sens = analyzeManifest(Manifest(permissions = listOf(
        "android.permission.READ_SMS", "android.permission.CAMERA",
        "android.permission.READ_SMS", "android.permission.INTERNET"
    ))).filter { it.title.startsWith("Sensitive permission") }.map { it.evidence }
    check(sens == listOf("android.permission.CAMERA", "android.permission.READ_SMS"),
        "sensitive perms sorted+unique")
    // low minSdk
    check("Low minSdkVersion (19)" in titles(analyzeManifest(Manifest(minSdk = 19))),
        "low minSdk flagged")
    // high minSdk not flagged
    check("Low minSdkVersion (28)" !in titles(analyzeManifest(Manifest(minSdk = 28))),
        "minSdk 28 not flagged")
    // hardened manifest clean
    check(analyzeManifest(Manifest(
        pkg = "com.acme.app", minSdk = 28, targetSdk = 33, allowBackup = false,
        networkSecurityConfig = "@xml/nsc", usesCleartextTraffic = false
    )).isEmpty(), "hardened manifest clean")
    // JSON round-trip: debuggable -> one HIGH
    analyzeManifest(manifestFromJson(
        """{"package":"com.x","debuggable":true,"allow_backup":false}""")).let {
        check(it.size == 1 && it[0].severity == "HIGH", "JSON debuggable -> one HIGH")
    }
    // JSON empty -> []
    check(findingsToJson(analyzeManifest(manifestFromJson(
        """{"package":"com.x","allow_backup":false}"""))) == "[]", "empty -> [] (not null)")
    // JSON with components array parses
    analyzeManifest(manifestFromJson(
        """{"components":[{"kind":"activity","name":".M","exported":true,"intent_filters":2}]}""")).let {
        check(it.any { f -> f.severity == "MEDIUM" }, "JSON component array parsed")
    }

    if (failures > 0) {
        println("\n$failures test(s) failed"); kotlin.system.exitProcess(1)
    }
    println("\nall tests passed")
}
