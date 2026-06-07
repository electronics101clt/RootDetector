# Root Detector

A professional Android root detection application implementing Aptoide's methodology for comprehensive root status analysis.

## Overview

Root Detector is a Kotlin-based Android application that performs thorough root detection using the same techniques employed by Aptoide's app store. It provides a detailed on-screen report and allows exporting results to the device's Downloads folder.

## Features

- **Comprehensive Detection**: Implements 6 different root detection methods
- **Real-time Results**: Displays detection results in an organized, easy-to-read format
- **Export Functionality**: Save detailed reports to Downloads folder
- **Material Design**: Clean, modern UI following Material Design guidelines
- **Android Version Support**: Compatible with Android 8.0 (API 26) through Android 10 (API 29)

## Detection Methods

Based on Aptoide's open-source implementation:

1. **SU Binary Detection** - Searches system paths for `su` binary using `stat` and `ls` commands
2. **SU Execution Test** - Attempts to execute `su -c exit` and checks exit code
3. **Root Access Verification** - Opens root shell, runs `id`, verifies uid=0
4. **SELinux Status Check** - Reads `/sys/fs/selinux/enforce` to determine security state
5. **Build Property Analysis** - Checks for test-keys, ro.debuggable, ro.secure, verity mode
6. **Root Package Detection** - Scans for known root management packages (SuperSU, Magisk, etc.)

## Technical Details

- **Language**: Kotlin
- **Min SDK**: API 26 (Android 8.0)
- **Target SDK**: API 29 (Android 10)
- **Architecture**: Single Activity with RecyclerView
- **Coroutines**: Background detection using Kotlin Coroutines
- **Storage**: MediaStore API for Android 10, legacy storage for Android 8/9

## Building

```bash
./gradlew assembleDebug
```

APK output: `app/build/outputs/apk/debug/app-debug.apk`

## Installation

```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

## Permissions

- `READ_EXTERNAL_STORAGE` - Read device info
- `WRITE_EXTERNAL_STORAGE` (API ≤28) - Save reports (legacy storage)
- `READ_PHONE_STATE` - Access device serial if needed

## Usage

1. Launch the app
2. Detection runs automatically on startup
3. View results in the scrollable list
4. Tap "Save Report" to export detailed report to Downloads folder
5. Tap "Run Detection" to re-scan

## Report Format

Generated reports include:

- Device information (manufacturer, model, Android version, kernel)
- Detection results for all 6 methods
- Overall root status (ROOTED CONFIRMED / ROOTED INDICATORS / NOT ROOTED)
- Risk level assessment
- Entry points identified

## License

This project is released under the MIT License.

## Credits

Detection methodology based on Aptoide's open-source implementation:
- [aptoide-client-v8](https://github.com/Aptoide/aptoide-client-v8)
- RootShell.java, Root.java, Shell.java, CheckRootOnBoot.java

## Development

Created as a forensic analysis tool for identifying root access on Android devices, particularly useful for security auditing and device verification.
