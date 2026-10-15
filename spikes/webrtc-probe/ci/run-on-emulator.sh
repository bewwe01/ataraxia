#!/usr/bin/env bash
# Runs inside the booted emulator job. Installs the probe APK, launches it, waits for its
# report in logcat; then runs the libsignal spike binary natively on the emulator.
set -euo pipefail
OUT="${OUT_DIR:?}"
APK="${APK_PATH:?}"
adb wait-for-device
adb shell getprop ro.build.version.release | sed 's/^/android_version=/' | tee "$OUT/device.txt"
adb shell getprop ro.product.cpu.abi | sed 's/^/abi=/' | tee -a "$OUT/device.txt"
adb shell dumpsys package com.google.android.webview 2>/dev/null | grep -m1 versionName | sed 's/^ */webview_/' | tee -a "$OUT/device.txt" || true

adb install -r "$APK"
adb logcat -c
adb shell am start -W -n org.veil.spike.webrtcprobe/.MainActivity
result=""
for _ in $(seq 1 90); do
  result=$(adb logcat -d -s VeilProbe:I '*:S' | grep VEIL_PROBE_RESULT || true)
  [ -n "$result" ] && break
  sleep 2
done
adb logcat -d > "$OUT/logcat-full.txt" || true
echo "$result" | tee "$OUT/probe-result.txt"
adb shell screencap -p /sdcard/probe.png && adb pull /sdcard/probe.png "$OUT/probe-screen.png" || true

echo "=== libsignal spike on device"
adb push "${LIBSIGNAL_BIN:?}" /data/local/tmp/veil-spike-libsignal
adb shell chmod 755 /data/local/tmp/veil-spike-libsignal
adb shell /data/local/tmp/veil-spike-libsignal | tee "$OUT/libsignal-on-android.txt"
grep -q "ALL CHECKS PASSED" "$OUT/libsignal-on-android.txt"
[ -n "$result" ] || { echo "probe produced no result"; exit 1; }
