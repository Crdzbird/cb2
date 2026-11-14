# The NDK the Android tools of cb2_flutter use, sourced by them:
# ANDROID_NDK_HOME when set, else the newest NDK under $ANDROID_HOME/ndk
# (or $ANDROID_SDK_ROOT/ndk).
find_ndk() {
    if [[ -n "${ANDROID_NDK_HOME:-}" ]]; then
        echo "$ANDROID_NDK_HOME"
        return
    fi
    local sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
    if [[ -z "$sdk" || ! -d "$sdk/ndk" ]]; then
        echo "set ANDROID_NDK_HOME, or ANDROID_HOME to an SDK with an NDK" >&2
        exit 1
    fi
    echo "$sdk/ndk/$(ls "$sdk/ndk" | sort -V | tail -1)"
}
