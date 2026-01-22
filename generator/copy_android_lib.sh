set -e

if [ -f "$(dirname "$0")/.env" ]; then
    set -a
    source "$(dirname "$0")/.env"
    set +a
fi

if [ -z "$ANDROID_JNILIBS_DEST" ]; then
    echo "Error: ANDROID_JNILIBS_DEST environment variable is not set"
    echo "Please set it in .env or export it before running this script"
    echo "Example: ANDROID_JNILIBS_DEST=/path/to/passport-reader/app/src/main/jniLibs/arm64-v8a"
    exit 1
fi

export ANDROID_TARGET_ARCH=${ANDROID_TARGET_ARCH:-aarch64-linux-android}

set -x
cp target/$ANDROID_TARGET_ARCH/release/libcircuits.so "$ANDROID_JNILIBS_DEST"
