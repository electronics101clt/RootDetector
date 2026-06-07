package com.rootdetector

import java.io.BufferedReader
import java.io.InputStreamReader
import java.util.concurrent.TimeUnit

/**
 * Shell command executor - Aptoide methodology
 * Based on Aptoide's Shell.java and Command.java implementation
 */
class ShellExecutor {

    companion object {
        private const val DEFAULT_TIMEOUT_MS = 3000L
    }

    /**
     * Execute a shell command and return result
     * Replicates Aptoide's Runtime.getRuntime().exec() approach
     */
    fun execCommand(
        command: String,
        timeoutMs: Long = DEFAULT_TIMEOUT_MS,
        asRoot: Boolean = false
    ): ShellResult {
        return try {
            val cmd = if (asRoot) arrayOf("su", "-c", command) else arrayOf("sh", "-c", command)
            val process = Runtime.getRuntime().exec(cmd)

            val stdout = StringBuilder()
            val stderr = StringBuilder()

            // Read stdout
            val stdoutThread = Thread {
                BufferedReader(InputStreamReader(process.inputStream)).use { reader ->
                    reader.forEachLine { stdout.append(it).append("\n") }
                }
            }

            // Read stderr
            val stderrThread = Thread {
                BufferedReader(InputStreamReader(process.errorStream)).use { reader ->
                    reader.forEachLine { stderr.append(it).append("\n") }
                }
            }

            stdoutThread.start()
            stderrThread.start()

            // Wait for process with timeout
            val completed = process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)

            if (!completed) {
                process.destroyForcibly()
                return ShellResult(
                    stdout = stdout.toString(),
                    stderr = "Command timed out after ${timeoutMs}ms",
                    exitCode = -1
                )
            }

            stdoutThread.join(500)
            stderrThread.join(500)

            ShellResult(
                stdout = stdout.toString().trim(),
                stderr = stderr.toString().trim(),
                exitCode = process.exitValue()
            )
        } catch (e: Exception) {
            ShellResult(
                stdout = "",
                stderr = e.message ?: "Unknown error",
                exitCode = -1
            )
        }
    }

    /**
     * Check if a binary exists at given path
     * Aptoide's findBinary() method - tries stat first, then ls
     */
    fun checkBinaryExists(path: String): Boolean {
        // Method 1: stat (Aptoide's primary method)
        val statResult = execCommand("stat $path 2>/dev/null")
        if (statResult.success && statResult.stdout.isNotEmpty()) {
            return true
        }

        // Method 2: ls (Aptoide's fallback)
        val lsResult = execCommand("ls $path 2>/dev/null")
        return lsResult.success && lsResult.stdout.isNotEmpty()
    }

    /**
     * Get property value using getprop
     */
    fun getProp(property: String): String {
        val result = execCommand("getprop $property")
        return if (result.success) result.stdout else ""
    }

    /**
     * Search for su binary in common paths
     * Replicates Aptoide's RootShell.isRootAvailable() path search
     */
    fun findSuBinary(): List<String> {
        val commonPaths = listOf(
            "/system/xbin/su",
            "/system/bin/su",
            "/sbin/su",
            "/su/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/data/local/su"
        )

        return commonPaths.filter { checkBinaryExists(it) }
    }

    /**
     * Execute su and check exit code
     * Aptoide's Root.requestRoot() method
     */
    fun testSuExecution(): ShellResult {
        return execCommand("exit", asRoot = true)
    }

    /**
     * Get UID from root shell
     * Aptoide's RootShell.isAccessGiven() method
     */
    fun getRootUid(): ShellResult {
        return execCommand("id", asRoot = true)
    }
}
