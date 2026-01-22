set -e

# Load environment variables from .env if it exists
if [ -f "$(dirname "$0")/.env" ]; then
    set -a
    source "$(dirname "$0")/.env"
    set +a
fi

# Check required environment variables
if [ -z "$NDK_HOME" ]; then
    echo "Error: NDK_HOME environment variable is not set"
    echo "Please set it in .env or export it before running this script"
    exit 1
fi

# Set defaults for optional variables
export NDK_HOST_TAG=${NDK_HOST_TAG:-linux-x86_64}
export ANDROID_TARGET_ARCH=${ANDROID_TARGET_ARCH:-aarch64-linux-android}
export ANDROID_API_LEVEL=${ANDROID_API_LEVEL:-35}

# Configure build environment
export TARGET=$ANDROID_TARGET_ARCH
export API=$ANDROID_API_LEVEL
export TOOLCHAIN=$NDK_HOME/toolchains/llvm/prebuilt/$NDK_HOST_TAG

export AR=$TOOLCHAIN/bin/llvm-ar
export CC_aarch64_linux_android=$TOOLCHAIN/bin/$TARGET$API-clang
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$CC_aarch64_linux_android

set -x
cargo build -p generator --lib --target $ANDROID_TARGET_ARCH --release
