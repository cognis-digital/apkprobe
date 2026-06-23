/*
 * apkprobe-kt CLI — read a normalized manifest JSON from a file arg or stdin,
 * run the MASVS/MASTG rule engine, and print findings as a JSON array.
 *
 *   echo '{"package":"com.x","debuggable":true}' | java -cp apkprobe-kt.jar MainKt
 *   java -cp apkprobe-kt.jar MainKt manifest.json
 *
 * Exit 2 if any HIGH finding, else 0.
 */
import java.io.File

fun main(args: Array<String>) {
    val json = if (args.isNotEmpty() && args[0] != "-")
        File(args[0]).readText()
    else
        generateSequence(::readLine).joinToString("\n")

    val findings = analyzeManifest(manifestFromJson(json))
    println(findingsToJson(findings))
    if (findings.any { it.severity == "HIGH" }) kotlin.system.exitProcess(2)
}
