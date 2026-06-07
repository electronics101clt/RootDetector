package com.rootdetector

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
import java.io.FileInputStream

/**
 * Root detection engine implementing Aptoide's methodology
 * Based on: RootShell.java, Root.java, Shell.java, CheckRootOnBoot.java
 */
class RootDetector(private val context: Context) {

    private val shellExecutor = ShellExecutor()

    /**
     * Run complete root detection suite
     * Returns comprehensive report with all findings
     */
    fun detectRoot(): RootDetectionReport {
        val deviceInfo = getDeviceInfo()

        // Method 1: Check for su binary (RootShell.isRootAvailable)
        val suPaths = shellExecutor.findSuBinary()
        val suBinaryFound = suPaths.isNotEmpty()

        // Method 2: Test su execution (Root.requestRoot)
        val suExecResult = shellExecutor.testSuExecution()
        val suExecutable = suExecResult.success

        // Method 3: Verify root access via uid (RootShell.isAccessGiven)
        val rootUidResult = shellExecutor.getRootUid()
        val rootAccessGranted = rootUidResult.stdout.contains("uid=0")

        // Method 4: Check SELinux status (Shell.isSELinuxEnforcing)
        val seLinuxEnforcing = checkSELinuxEnforcing()

        // Method 5: Build property checks
        val buildTags = Build.TAGS ?: ""
        val isDebugBuild = shellExecutor.getProp("ro.debuggable") == "1"
        val roSecure = shellExecutor.getProp("ro.secure")
        val verityMode = shellExecutor.getProp("ro.boot.veritymode")

        // Method 6: Root package detection
        val rootPackages = detectRootPackages()

        // Determine overall root status
        val overallStatus = when {
            rootAccessGranted && suExecutable -> RootStatus.ROOTED_CONFIRMED
            suBinaryFound || buildTags.contains("test-keys") || isDebugBuild -> RootStatus.ROOTED_INDICATORS
            else -> RootStatus.NOT_ROOTED
        }

        return RootDetectionReport(
            timestamp = System.currentTimeMillis(),
            deviceInfo = deviceInfo,
            suBinaryFound = suBinaryFound,
            suBinaryPaths = suPaths,
            suExecutable = suExecutable,
            suExitCode = suExecResult.exitCode,
            rootAccessGranted = rootAccessGranted,
            rootUid = if (rootAccessGranted) rootUidResult.stdout else null,
            seLinuxEnforcing = seLinuxEnforcing,
            buildTags = buildTags,
            isDebugBuild = isDebugBuild,
            roSecure = roSecure,
            verityMode = verityMode,
            rootPackagesFound = rootPackages,
            overallRootStatus = overallStatus
        )
    }

    /**
     * Check SELinux enforcement status
     * Aptoide's Shell.isSELinuxEnforcing() implementation
     * Reads /sys/fs/selinux/enforce directly (world-readable)
     */
    private fun checkSELinuxEnforcing(): Boolean {
        return try {
            val enforceFile = File("/sys/fs/selinux/enforce")
            if (enforceFile.exists() && enforceFile.canRead()) {
                val value = FileInputStream(enforceFile).use { it.read() }
                value == '1'.code  // '1' = enforcing, '0' = permissive
            } else {
                // Fallback to getenforce command
                val result = shellExecutor.execCommand("getenforce")
                result.stdout.equals("Enforcing", ignoreCase = true)
            }
        } catch (e: Exception) {
            false  // Default to not enforcing if can't determine
        }
    }

    /**
     * Detect known root management packages
     * Checks for SuperSU, Magisk, and other root managers
     */
    private fun detectRootPackages(): List<String> {
        val knownRootPackages = listOf(
            "eu.chainfire.supersu",           // SuperSU
            "com.topjohnwu.magisk",           // Magisk
            "com.noshufou.android.su",        // Superuser
            "com.koushikdutta.superuser",     // Koush Superuser
            "com.thirdparty.superuser",       // Third-party SU
            "com.yellowes.su",                // Yellow's SU
            "com.kingroot.kinguser",          // KingRoot
            "com.kingo.root",                 // Kingo Root
            "com.smedialink.oneclickroot",    // OneClick Root
            "com.zhiqupk.root.global",        // Root Master
            "com.alephzain.framaroot"         // Framaroot
        )

        val foundPackages = mutableListOf<String>()
        val pm = context.packageManager

        for (packageName in knownRootPackages) {
            try {
                pm.getPackageInfo(packageName, 0)
                foundPackages.add(packageName)
            } catch (e: PackageManager.NameNotFoundException) {
                // Package not found - expected for most
            }
        }

        return foundPackages
    }

    /**
     * Gather device information
     */
    private fun getDeviceInfo(): DeviceInfo {
        val kernelVersion = try {
            val versionFile = File("/proc/version")
            if (versionFile.exists()) {
                versionFile.readText().split(" ").getOrNull(2) ?: "Unknown"
            } else {
                "Unknown"
            }
        } catch (e: Exception) {
            "Unknown"
        }

        return DeviceInfo(
            manufacturer = Build.MANUFACTURER,
            model = Build.MODEL,
            androidVersion = Build.VERSION.RELEASE,
            apiLevel = Build.VERSION.SDK_INT,
            buildFingerprint = Build.FINGERPRINT,
            kernelVersion = kernelVersion
        )
    }

    /**
     * Generate list of detection results for UI display
     */
    fun getDetectionResults(report: RootDetectionReport): List<DetectionResult> {
        val results = mutableListOf<DetectionResult>()

        // SU Binary Check
        results.add(DetectionResult(
            checkName = "SU Binary Detection",
            passed = report.suBinaryFound,
            details = if (report.suBinaryFound) {
                "Found at: ${report.suBinaryPaths.joinToString(", ")}"
            } else {
                "No su binary found in common paths"
            },
            severity = if (report.suBinaryFound) Severity.CRITICAL else Severity.SUCCESS
        ))

        // SU Execution Test
        results.add(DetectionResult(
            checkName = "SU Execution Test",
            passed = report.suExecutable,
            details = "Exit code: ${report.suExitCode}${if (report.suExecutable) " (su is functional)" else " (su failed)"}",
            severity = if (report.suExecutable) Severity.CRITICAL else Severity.SUCCESS
        ))

        // Root Access Verification
        results.add(DetectionResult(
            checkName = "Root Access Verification",
            passed = report.rootAccessGranted,
            details = report.rootUid ?: "No root access",
            severity = if (report.rootAccessGranted) Severity.CRITICAL else Severity.SUCCESS
        ))

        // SELinux Status
        results.add(DetectionResult(
            checkName = "SELinux Status",
            passed = !report.seLinuxEnforcing,
            details = if (report.seLinuxEnforcing) "Enforcing (secure)" else "Permissive (vulnerable)",
            severity = if (!report.seLinuxEnforcing) Severity.WARNING else Severity.SUCCESS
        ))

        // Build Properties
        val buildIssues = mutableListOf<String>()
        if (report.buildTags.contains("test-keys")) buildIssues.add("test-keys")
        if (report.isDebugBuild) buildIssues.add("debuggable")
        if (report.roSecure == "0") buildIssues.add("ro.secure=0")
        if (report.verityMode.contains("disabled")) buildIssues.add("dm-verity disabled")

        results.add(DetectionResult(
            checkName = "Build Properties",
            passed = buildIssues.isNotEmpty(),
            details = if (buildIssues.isEmpty()) {
                "No suspicious build flags"
            } else {
                "Issues: ${buildIssues.joinToString(", ")}"
            },
            severity = if (buildIssues.isNotEmpty()) Severity.WARNING else Severity.SUCCESS
        ))

        // Root Management Packages
        results.add(DetectionResult(
            checkName = "Root Management Apps",
            passed = report.rootPackagesFound.isNotEmpty(),
            details = if (report.rootPackagesFound.isEmpty()) {
                "No root manager apps found"
            } else {
                "Found: ${report.rootPackagesFound.joinToString(", ")}"
            },
            severity = if (report.rootPackagesFound.isNotEmpty()) Severity.CRITICAL else Severity.SUCCESS
        ))

        return results
    }
}
