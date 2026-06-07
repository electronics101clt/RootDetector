package com.rootdetector

import java.text.SimpleDateFormat
import java.util.*

/**
 * Generates formatted text reports from root detection results
 */
class ReportGenerator {

    private val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)

    /**
     * Generate complete report as formatted text
     */
    fun generateReport(report: RootDetectionReport): String {
        val sb = StringBuilder()

        // Header
        sb.appendLine("═══════════════════════════════════════")
        sb.appendLine("    ROOT DETECTION REPORT")
        sb.appendLine("═══════════════════════════════════════")
        sb.appendLine("Generated: ${dateFormat.format(Date(report.timestamp))}")
        sb.appendLine()

        // Device Information
        sb.appendLine("═══════════════════════════════════════")
        sb.appendLine("DEVICE INFORMATION")
        sb.appendLine("═══════════════════════════════════════")
        sb.appendLine("Manufacturer: ${report.deviceInfo.manufacturer}")
        sb.appendLine("Model: ${report.deviceInfo.model}")
        sb.appendLine("Android Version: ${report.deviceInfo.androidVersion}")
        sb.appendLine("API Level: ${report.deviceInfo.apiLevel}")
        sb.appendLine("Build Fingerprint: ${report.deviceInfo.buildFingerprint}")
        sb.appendLine("Kernel Version: ${report.deviceInfo.kernelVersion}")
        sb.appendLine()

        // Detection Results
        sb.appendLine("═══════════════════════════════════════")
        sb.appendLine("DETECTION RESULTS")
        sb.appendLine("═══════════════════════════════════════")
        sb.appendLine()

        // SU Binary Detection
        sb.appendLine(formatCheck(
            "[✓]",
            "SU Binary Detection",
            report.suBinaryFound,
            if (report.suBinaryFound) {
                "Found: YES\n    Paths: ${report.suBinaryPaths.joinToString(", ")}"
            } else {
                "Found: NO"
            }
        ))

        // SU Execution Test
        sb.appendLine(formatCheck(
            "[✓]",
            "SU Execution Test",
            report.suExecutable,
            "Executable: ${if (report.suExecutable) "YES" else "NO"}\n    Exit Code: ${report.suExitCode}"
        ))

        // Root Access Verification
        sb.appendLine(formatCheck(
            "[✓]",
            "Root Access Verification",
            report.rootAccessGranted,
            if (report.rootAccessGranted) {
                "Access Granted: YES\n    UID: ${report.rootUid}"
            } else {
                "Access Granted: NO"
            }
        ))

        // SELinux Status
        sb.appendLine(formatCheck(
            "[!]",
            "SELinux Status",
            !report.seLinuxEnforcing,
            "Enforcing: ${if (report.seLinuxEnforcing) "YES (Secure)" else "NO (Permissive - Vulnerable)"}"
        ))

        // Build Properties
        val buildIssues = mutableListOf<String>()
        if (report.buildTags.contains("test-keys")) buildIssues.add("test-keys")
        if (report.isDebugBuild) buildIssues.add("debuggable=1")
        if (report.roSecure == "0") buildIssues.add("ro.secure=0")
        if (report.verityMode.contains("disabled")) buildIssues.add("verity disabled")

        sb.appendLine(formatCheck(
            "[!]",
            "Build Properties",
            buildIssues.isNotEmpty(),
            if (buildIssues.isNotEmpty()) {
                "Issues Found:\n    - ${buildIssues.joinToString("\n    - ")}"
            } else {
                "No Issues Found"
            }
        ))

        // Root Management Packages
        sb.appendLine(formatCheck(
            "[✗]",
            "Root Management Packages",
            report.rootPackagesFound.isNotEmpty(),
            if (report.rootPackagesFound.isNotEmpty()) {
                "Found: ${report.rootPackagesFound.size} package(s)\n    - ${report.rootPackagesFound.joinToString("\n    - ")}"
            } else {
                "Found: None"
            }
        ))

        sb.appendLine()

        // Overall Status
        sb.appendLine("═══════════════════════════════════════")
        sb.appendLine("OVERALL STATUS: ${formatRootStatus(report.overallRootStatus)}")
        sb.appendLine("═══════════════════════════════════════")

        when (report.overallRootStatus) {
            RootStatus.ROOTED_CONFIRMED -> {
                sb.appendLine("Risk Level: HIGH")
                sb.appendLine("Root Access: Fully Functional")
                val entryPoints = mutableListOf<String>()
                if (report.suBinaryFound) entryPoints.add("su binary")
                if (report.rootAccessGranted) entryPoints.add("ADB root shell")
                if (entryPoints.isNotEmpty()) {
                    sb.appendLine("Entry Points: ${entryPoints.joinToString(", ")}")
                }
            }
            RootStatus.ROOTED_INDICATORS -> {
                sb.appendLine("Risk Level: MEDIUM")
                sb.appendLine("Root Indicators: Present")
                sb.appendLine("Root Access: Not Fully Functional")
            }
            RootStatus.NOT_ROOTED -> {
                sb.appendLine("Risk Level: LOW")
                sb.appendLine("Root Access: None Detected")
            }
        }

        sb.appendLine()
        sb.appendLine("═══════════════════════════════════════")
        sb.appendLine("Report generated by RootDetector v1.0")
        sb.appendLine("Detection Method: Aptoide Methodology")
        sb.appendLine("═══════════════════════════════════════")

        return sb.toString()
    }

    /**
     * Format a single check result
     */
    private fun formatCheck(symbol: String, name: String, detected: Boolean, details: String): String {
        val sb = StringBuilder()
        sb.appendLine("$symbol $name")
        details.lines().forEach { line ->
            sb.appendLine("    $line")
        }
        sb.appendLine()
        return sb.toString()
    }

    /**
     * Format overall root status
     */
    private fun formatRootStatus(status: RootStatus): String {
        return when (status) {
            RootStatus.ROOTED_CONFIRMED -> "ROOTED (CONFIRMED)"
            RootStatus.ROOTED_INDICATORS -> "ROOTED (INDICATORS ONLY)"
            RootStatus.NOT_ROOTED -> "NOT ROOTED"
        }
    }

    /**
     * Generate short summary for display
     */
    fun generateSummary(report: RootDetectionReport): String {
        return when (report.overallRootStatus) {
            RootStatus.ROOTED_CONFIRMED -> "Device is ROOTED with functional root access"
            RootStatus.ROOTED_INDICATORS -> "Device shows root indicators but no functional root"
            RootStatus.NOT_ROOTED -> "No root detected on this device"
        }
    }
}
