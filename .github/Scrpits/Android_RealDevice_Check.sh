#!/usr/bin/env bash
set -euo pipefail

APK_PATH="${1:-Android/build/outputs/apk/debug/Android-debug.apk}"
PKG="com.freedom.network"

if ! command -v adb >/dev/null 2>&1; then
  echo "adb not found in PATH" >&2
  exit 1
fi

echo "[1/5] Waiting for Android device..."
adb wait-for-device
SDK=$(adb shell getprop ro.build.version.sdk | tr -d '\r')
ABI=$(adb shell getprop ro.product.cpu.abi | tr -d '\r')
echo "Connected device: SDK=$SDK ABI=$ABI"

if [ -f "$APK_PATH" ]; then
  echo "[2/5] Installing $APK_PATH..."
  adb install -r -d "$APK_PATH"
else
  echo "[2/5] APK not found at $APK_PATH, skipping install."
fi

if [ "${SDK:-0}" -ge 36 ]; then
  echo "[3/5] Applying Android 16/17 close_quic_connection=-1..."
  adb shell settings put global close_quic_connection -1 || true
else
  echo "[3/5] SDK < 36, skipping close_quic_connection."
fi

echo "[4/5] Clearing logcat and launching $PKG/.MainActivity..."
adb logcat -c
adb shell am start -n "$PKG/.MainActivity"
sleep 4

echo "[5/5] Checking for crashes and process liveness..."
CRASHES=$(adb logcat -d -s AndroidRuntime:E | grep -E "FATAL EXCEPTION|$PKG" || true)
if [ -n "$CRASHES" ]; then
  echo "CRASH DETECTED:"
  echo "$CRASHES"
  exit 1
fi

PID=$(adb shell pidof "$PKG" 2>/dev/null | tr -d '\r' || true)
if [ -z "$PID" ]; then
  echo "ERROR: $PKG process did not remain running!"
  adb logcat -d | tail -n 60
  exit 1
fi

echo "PASS: $PKG launched cleanly (PID=$PID) with zero crashes on SDK=$SDK ($ABI)."
