#!/bin/bash -eu

# Update package list and install basic dependencies
apt-get update
apt-get install -y build-essential cmake pkg-config git libjson-c-dev patchelf

# Set up dependencies directory
DEPS_DIR="$PWD/deps"
mkdir -p "$DEPS_DIR"
cd "$DEPS_DIR"

# Download and build libubox (required dependency)
if [ ! -d "libubox" ]; then
    echo "Downloading libubox..."
    git clone https://github.com/openwrt/libubox.git
    cd libubox
    # Remove unnecessary components to avoid CMake errors
    rm -rf tests examples lua
    # Also patch CMakeLists.txt to remove references to examples and lua
    sed -i '/ADD_SUBDIRECTORY(examples)/d' CMakeLists.txt
    sed -i '/ADD_SUBDIRECTORY(lua)/d' CMakeLists.txt
    cd ..
fi

cd libubox
mkdir -p build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX="$DEPS_DIR/install" \
         -DCMAKE_C_FLAGS="$CFLAGS" \
         -DBUILD_LUA=OFF \
         -DBUILD_EXAMPLES=OFF \
         -DBUILD_TESTS=OFF \
         -DBUILD_STATIC=OFF \
         -DBUILD_SHARED_LIBS=ON
make -j$(nproc)
make install
cd "$DEPS_DIR"

# Go back to source directory and find the correct source structure
cd ..

echo "Checking directory structure..."
ls -la "$SRC/oss-fuzz-auto"

# Check for git repository structure with commit hash directory
REPO_DIR=$(find "$SRC/oss-fuzz-auto" -maxdepth 1 -name "relayd-oss-fuzz-*" -type d | head -n1)
if [ -n "$REPO_DIR" ] && [ -d "$REPO_DIR" ]; then
  echo "Found git repository structure with commit hash, using $REPO_DIR"
  cd "$REPO_DIR"
  SOURCE_DIR="$REPO_DIR"
elif [ -f "$SRC/oss-fuzz-auto/relayd-fuzz.c" ]; then
  echo "Found source files in mounted structure"
  cd "$SRC/oss-fuzz-auto"
  SOURCE_DIR="$SRC/oss-fuzz-auto"
else
  echo "Using default structure"
  cd "$SRC/oss-fuzz-auto"
  SOURCE_DIR="$SRC/oss-fuzz-auto"
fi

echo "Using source directory: $SOURCE_DIR"
echo "Current working directory: $(pwd)"
echo "Available files:"
ls -la

# Set up compiler flags and paths
: "${CFLAGS:=-O2 -fPIC}"
: "${LDFLAGS:=}"
: "${PKG_CONFIG_PATH:=}"
: "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"  # Default to libFuzzer if not provided

# Add required flags for the build
export CFLAGS="$CFLAGS -D_GNU_SOURCE -std=gnu99"
export CFLAGS="$CFLAGS -I$DEPS_DIR/install/include"
export LDFLAGS="$LDFLAGS -L$DEPS_DIR/install/lib"
export PKG_CONFIG_PATH="$DEPS_DIR/install/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"

echo "Compiling relayd source files..."

# Compile the individual source files
$CC $CFLAGS -c dhcp.c -o dhcp.o
$CC $CFLAGS -c route.c -o route.o

# For main.c, we need to exclude the main() function and global variable definitions when building for fuzzing
# Create a temporary file without the main function and conflicting globals, but add extern declarations
echo "Creating main source without main() function and global definitions..."
cat > main_for_fuzz.c << 'EOF'
// Include everything from main.c except the main() function and global variables
// Global variables will be defined in the fuzzer instead
#define MAIN_C_NO_MAIN

// Include necessary headers for type definitions
#include <stdint.h>
#include <stdbool.h>
#include <libubox/list.h>

// External declarations for variables defined in fuzzer
extern struct list_head interfaces;
extern int debug;
extern uint8_t local_addr[4];
extern int local_route_table;

// External declarations for static variables from original main.c
static int host_timeout = 30;
static int host_ping_tries = 5;
static int inet_sock = -1;
static int forward_bcast = 1;
static int forward_dhcp = 1;
static int parse_dhcp = 1;
static LIST_HEAD(pending_routes);

EOF

# Extract everything from main.c except the main function and global variable definitions
sed -e '/^int main(/,/^}[[:space:]]*$/d' \
    -e '/^static LIST_HEAD(pending_routes);/d' \
    -e '/^LIST_HEAD(interfaces);/d' \
    -e '/^int debug;/d' \
    -e '/^static int host_timeout;/d' \
    -e '/^static int host_ping_tries;/d' \
    -e '/^static int inet_sock;/d' \
    -e '/^static int forward_bcast;/d' \
    -e '/^static int forward_dhcp;/d' \
    -e '/^static int parse_dhcp;/d' \
    -e '/^uint8_t local_addr\[4\];/d' \
    -e '/^int local_route_table;/d' \
    main.c >> main_for_fuzz.c

$CC $CFLAGS -c main_for_fuzz.c -o main_for_fuzz.o

echo "Compiling fuzzer..."
$CC $CFLAGS -c relayd-fuzz.c -o relayd-fuzz.o

echo "Linking fuzzer with dynamic libraries..."
# Link with dynamic linking and specify library paths
$CC $CFLAGS $LIB_FUZZING_ENGINE relayd-fuzz.o \
    main_for_fuzz.o dhcp.o route.o \
    $LDFLAGS -lubox \
    -o $OUT/relayd_fuzzer

# Set correct rpath for OSS-Fuzz
echo "Setting rpath with patchelf..."
patchelf --set-rpath '$ORIGIN/lib' $OUT/relayd_fuzzer

# Copy all required shared library dependencies
echo "Finding and copying all shared library dependencies..."

# Create lib directory
mkdir -p "$OUT/lib"

# First, copy libubox from our custom installation
echo "Copying libubox from custom installation..."
if [ -f "$DEPS_DIR/install/lib/libubox.so" ]; then
    cp "$DEPS_DIR/install/lib/libubox.so" "$OUT/lib/"
    echo "Copied libubox.so from $DEPS_DIR/install/lib/libubox.so"
fi

# Create a temporary script to copy other dependencies
cat > copy_deps.sh << 'EOFSCRIPT'
#!/bin/bash
BINARY="$1"
OUT_LIB="$2"

# Get all dependencies using ldd
ldd "$BINARY" 2>/dev/null | while read line; do
    # Extract library path from ldd output
    if [[ $line =~ '=>' ]]; then
        lib_path=$(echo "$line" | awk '{print $3}')
        if [[ -f "$lib_path" ]]; then
            lib_name=$(basename "$lib_path")
            # Skip system libraries that are always available
            if [[ ! "$lib_name" =~ ^(ld-linux|libc\.so|libm\.so|libpthread\.so|libdl\.so|librt\.so|libresolv\.so) ]]; then
                echo "Copying $lib_name from $lib_path"
                cp "$lib_path" "$OUT_LIB/" 2>/dev/null || true
            fi
        fi
    fi
done
EOFSCRIPT

chmod +x copy_deps.sh
./copy_deps.sh "$OUT/relayd_fuzzer" "$OUT/lib"

# Verify the binary dependencies and rpath
echo "Checking binary dependencies..."
ldd $OUT/relayd_fuzzer || echo "ldd may show missing libs due to \$ORIGIN rpath, but they should be in lib/"

echo "Checking rpath..."
readelf -d $OUT/relayd_fuzzer | grep -E "(RPATH|RUNPATH)" || echo "No rpath found"

# Verify that all required shared libraries are in $OUT/lib
echo "Shared libraries in $OUT/lib:"
ls -la $OUT/lib/ || echo "No shared libraries copied"

# Copy source files to expected location for coverage analysis
echo "Copying source files for coverage analysis..."
mkdir -p "$OUT/src/oss-fuzz-auto"
cp main_for_fuzz.c "$OUT/src/oss-fuzz-auto/"

# Clean up temporary files (but preserve main_for_fuzz.c for coverage)
rm -f *.o copy_deps.sh

echo "Build completed successfully!"
echo "Fuzzer binary: $OUT/relayd_fuzzer"
echo "Shared libraries: $OUT/lib/"

# Final verification
if [ -f "$OUT/relayd_fuzzer" ]; then
    echo "Fuzzer binary size: $(stat -c%s "$OUT/relayd_fuzzer") bytes"
    echo "Fuzzer binary permissions: $(stat -c%A "$OUT/relayd_fuzzer")"
else
    echo "ERROR: Failed to create fuzzer binary!"
    exit 1
fi
