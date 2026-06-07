package com.rootdetector

/**
 * Data models for root detection
 */

data class RootDetectionReport(
    val timestamp: Long,
    val deviceInfo: DeviceInfo,
    val suBinaryFound: Boolean,
    val suBinaryPaths: List<String>,
    val suExecutable: Boolean,
    val suExitCode: Int,
    val rootAccessGranted: Boolean,
    val rootUid: String?,
    val seLinuxEnforcing: Boolean,
    val buildTags: String,
    val isDebugBuild: Boolean,
    val roSecure: String,
    val verityMode: String,
    val rootPackagesFound: List<String>,
    val overallRootStatus: RootStatus
)

data class DeviceInfo(
    val manufacturer: String,
    val model: String,
    val androidVersion: String,
    val apiLevel: Int,
    val buildFingerprint: String,
    val kernelVersion: String
)

enum class RootStatus {
    ROOTED_CONFIRMED,      // su functional
    ROOTED_INDICATORS,     // signals present but su not working
    NOT_ROOTED
}

data class ShellResult(
    val stdout: String,
    val stderr: String,
    val exitCode: Int,
    val success: Boolean = exitCode == 0
)

data class DetectionResult(
    val checkName: String,
    val passed: Boolean,
    val details: String,
    val severity: Severity = Severity.SUCCESS
)

enum class Severity {
    SUCCESS,  // Green - no root
    WARNING,  // Yellow - root indicators
    CRITICAL  // Red - root confirmed
}
