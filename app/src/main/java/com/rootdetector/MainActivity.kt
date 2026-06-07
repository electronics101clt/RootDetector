package com.rootdetector

import android.Manifest
import android.content.ContentValues
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.MediaStore
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.google.android.material.button.MaterialButton
import com.google.android.material.progressindicator.LinearProgressIndicator
import com.google.android.material.textview.MaterialTextView
import androidx.recyclerview.widget.RecyclerView
import com.rootdetector.adapter.DetectionResultAdapter
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.*

class MainActivity : AppCompatActivity() {

    private lateinit var rootDetector: RootDetector
    private lateinit var reportGenerator: ReportGenerator
    private var currentReport: RootDetectionReport? = null

    private lateinit var progressIndicator: LinearProgressIndicator
    private lateinit var statusText: MaterialTextView
    private lateinit var summaryText: MaterialTextView
    private lateinit var recyclerView: RecyclerView
    private lateinit var runButton: MaterialButton
    private lateinit var saveButton: MaterialButton

    private val adapter = DetectionResultAdapter()

    companion object {
        private const val STORAGE_PERMISSION_CODE = 100
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        rootDetector = RootDetector(this)
        reportGenerator = ReportGenerator()

        initViews()
        setupRecyclerView()
        setupButtons()

        // Auto-run detection on first launch
        runDetection()
    }

    private fun initViews() {
        progressIndicator = findViewById(R.id.progressIndicator)
        statusText = findViewById(R.id.statusText)
        summaryText = findViewById(R.id.summaryText)
        recyclerView = findViewById(R.id.recyclerView)
        runButton = findViewById(R.id.runButton)
        saveButton = findViewById(R.id.saveButton)
    }

    private fun setupRecyclerView() {
        recyclerView.layoutManager = LinearLayoutManager(this)
        recyclerView.adapter = adapter
    }

    private fun setupButtons() {
        runButton.setOnClickListener {
            runDetection()
        }

        saveButton.setOnClickListener {
            saveReport()
        }
    }

    private fun runDetection() {
        lifecycleScope.launch {
            try {
                // Show progress
                progressIndicator.show()
                statusText.text = "Running detection..."
                runButton.isEnabled = false
                saveButton.isEnabled = false

                // Run detection in background
                val report = withContext(Dispatchers.IO) {
                    rootDetector.detectRoot()
                }

                currentReport = report

                // Update UI
                val results = rootDetector.getDetectionResults(report)
                adapter.submitList(results)

                summaryText.text = reportGenerator.generateSummary(report)

                // Set status color based on result
                val statusColor = when (report.overallRootStatus) {
                    RootStatus.ROOTED_CONFIRMED -> getColor(R.color.critical_red)
                    RootStatus.ROOTED_INDICATORS -> getColor(R.color.warning_yellow)
                    RootStatus.NOT_ROOTED -> getColor(R.color.success_green)
                }
                statusText.text = when (report.overallRootStatus) {
                    RootStatus.ROOTED_CONFIRMED -> "ROOTED (CONFIRMED)"
                    RootStatus.ROOTED_INDICATORS -> "ROOTED (INDICATORS)"
                    RootStatus.NOT_ROOTED -> "NOT ROOTED"
                }
                statusText.setTextColor(statusColor)

                Toast.makeText(this@MainActivity, "Detection complete", Toast.LENGTH_SHORT).show()

            } catch (e: Exception) {
                statusText.text = "Detection failed: ${e.message}"
                Toast.makeText(this@MainActivity, "Error: ${e.message}", Toast.LENGTH_LONG).show()
            } finally {
                progressIndicator.hide()
                runButton.isEnabled = true
                saveButton.isEnabled = currentReport != null
            }
        }
    }

    private fun saveReport() {
        val report = currentReport ?: run {
            Toast.makeText(this, "No report to save", Toast.LENGTH_SHORT).show()
            return
        }

        // Check permission for Android 8/9
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE)
                != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(
                    this,
                    arrayOf(Manifest.permission.WRITE_EXTERNAL_STORAGE),
                    STORAGE_PERMISSION_CODE
                )
                return
            }
        }

        lifecycleScope.launch {
            try {
                val reportText = reportGenerator.generateReport(report)
                val timestamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
                val fileName = "root_report_$timestamp.txt"

                val filePath = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    // Android 10+ - Use MediaStore
                    saveReportMediaStore(fileName, reportText)
                } else {
                    // Android 8/9 - Use legacy storage
                    saveReportLegacy(fileName, reportText)
                }

                Toast.makeText(
                    this@MainActivity,
                    "Report saved to:\n$filePath",
                    Toast.LENGTH_LONG
                ).show()

            } catch (e: Exception) {
                Toast.makeText(
                    this@MainActivity,
                    "Failed to save report: ${e.message}",
                    Toast.LENGTH_LONG
                ).show()
            }
        }
    }

    private fun saveReportMediaStore(fileName: String, content: String): String {
        val contentValues = ContentValues().apply {
            put(MediaStore.Downloads.DISPLAY_NAME, fileName)
            put(MediaStore.Downloads.MIME_TYPE, "text/plain")
            put(MediaStore.Downloads.IS_PENDING, 1)
        }

        val uri = contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, contentValues)
            ?: throw Exception("Failed to create file")

        contentResolver.openOutputStream(uri)?.use { outputStream ->
            outputStream.write(content.toByteArray())
        }

        contentValues.clear()
        contentValues.put(MediaStore.Downloads.IS_PENDING, 0)
        contentResolver.update(uri, contentValues, null, null)

        return "Downloads/$fileName"
    }

    private fun saveReportLegacy(fileName: String, content: String): String {
        val downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        val file = File(downloadsDir, fileName)
        file.writeText(content)
        return file.absolutePath
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == STORAGE_PERMISSION_CODE) {
            if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                saveReport()
            } else {
                Toast.makeText(this, "Storage permission required to save report", Toast.LENGTH_SHORT).show()
            }
        }
    }
}
