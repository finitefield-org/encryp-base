#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
project_dir="${PROJECT_DIR:-${repo_root}/wrappers/android}"
android_sdk_root="${ANDROID_SDK_ROOT:-${HOME}/Library/Android/sdk}"
adb_bin="${ADB_BIN:-${android_sdk_root}/platform-tools/adb}"
gradle_bin="${GRADLE_BIN:-}"
wait_for_boot_timeout_sec="${WAIT_FOR_BOOT_TIMEOUT_SEC:-300}"
wait_for_unlock_timeout_sec="${WAIT_FOR_UNLOCK_TIMEOUT_SEC:-300}"
build_native_bridge="${BUILD_NATIVE_BRIDGE:-false}"
android_serial="${ANDROID_SERIAL:-}"

usage() {
  cat <<'EOF'
Usage: scripts/verify_android_device.sh

Environment variables:
  ANDROID_SDK_ROOT             Android SDK root (default: ~/Library/Android/sdk)
  ANDROID_SERIAL               Target device serial when multiple devices are attached
  ADB_BIN                      adb executable path override
  GRADLE_BIN                   gradle executable path override
  PROJECT_DIR                  Android module directory override
  WAIT_FOR_BOOT_TIMEOUT_SEC    Boot wait timeout in seconds (default: 300)
  WAIT_FOR_UNLOCK_TIMEOUT_SEC  Unlock wait timeout in seconds (default: 300)
  BUILD_NATIVE_BRIDGE          Set to true to pass -Pencsqlite.buildNativeBridge=true
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ -z "${gradle_bin}" ]]; then
  if command -v gradle >/dev/null 2>&1; then
    gradle_bin="$(command -v gradle)"
  elif [[ -x /tmp/gradle-9.3.1/bin/gradle ]]; then
    gradle_bin="/tmp/gradle-9.3.1/bin/gradle"
  fi
fi

if [[ ! -x "${adb_bin}" ]]; then
  echo "adb not found: ${adb_bin}" >&2
  exit 1
fi

if [[ -z "${gradle_bin}" || ! -x "${gradle_bin}" ]]; then
  echo "gradle not found. Set GRADLE_BIN or add gradle to PATH." >&2
  exit 1
fi

if [[ ! -d "${project_dir}" ]]; then
  echo "Android project directory not found: ${project_dir}" >&2
  exit 1
fi

device_serial="${android_serial}"
if [[ -z "${device_serial}" ]]; then
  attached_devices=()
  while IFS= read -r line; do
    attached_devices+=("${line}")
  done < <("${adb_bin}" devices | awk 'NR > 1 && $2 == "device" { print $1 }')
  if [[ "${#attached_devices[@]}" -eq 0 ]]; then
    echo "No online Android device or emulator is attached." >&2
    exit 1
  fi
  if [[ "${#attached_devices[@]}" -gt 1 ]]; then
    printf 'Multiple devices are attached:\n' >&2
    printf '  %s\n' "${attached_devices[@]}" >&2
    echo "Set ANDROID_SERIAL to choose one." >&2
    exit 1
  fi
  device_serial="${attached_devices[0]}"
fi

adb_device=("${adb_bin}" -s "${device_serial}")

current_boot_state() {
  "${adb_device[@]}" shell getprop sys.boot_completed | tr -d '\r'
}

current_unlock_state() {
  "${adb_device[@]}" shell cmd user is-user-unlocked 0 2>/dev/null | tr -d '\r' | tr '[:upper:]' '[:lower:]'
}

is_unlocked() {
  case "$(current_unlock_state)" in
    *true*|*1*|*unlocked*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

echo "Using device: ${device_serial}"
echo "Waiting for device boot completion..."
deadline=$((SECONDS + wait_for_boot_timeout_sec))
until [[ "$(current_boot_state)" == "1" ]]; do
  if (( SECONDS >= deadline )); then
    echo "Timed out waiting for boot completion." >&2
    exit 1
  fi
  sleep 2
done

echo "Boot completed."
echo "Current unlock state: $(current_unlock_state)"
echo "Waiting for user unlock..."
deadline=$((SECONDS + wait_for_unlock_timeout_sec))
until is_unlocked; do
  if (( SECONDS >= deadline )); then
    echo "Timed out waiting for user unlock." >&2
    exit 1
  fi
  sleep 2
done

echo "User is unlocked."

gradle_args=(connectedDebugAndroidTest --no-daemon)
if [[ "${build_native_bridge}" == "true" ]]; then
  gradle_args=("-Pencsqlite.buildNativeBridge=true" "${gradle_args[@]}")
fi

(
  cd "${project_dir}"
  "${gradle_bin}" "${gradle_args[@]}"
)

echo "Android device verification completed."
