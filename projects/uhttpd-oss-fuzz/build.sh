#!/bin/bash -eu

# Install dependencies
apt-get update
apt-get install -y build-essential cmake pkg-config git libjson-c-dev libssl-dev patchelf

# Set up dependencies directory
DEPS_DIR="$PWD/deps"
mkdir -p "$DEPS_DIR"
cd "$DEPS_DIR"

# Clean up any existing builds to avoid conflicts
rm -rf libubox/build

# Download and build libubox (required for uhttpd)
if [ ! -d "libubox" ]; then
    echo "Downloading libubox..."
    git clone https://github.com/openwrt/libubox.git
    cd libubox
    rm -rf tests examples
    cd ..
fi

cd libubox

# Patch CMakeLists.txt to conditionally add examples directory
if [ -f CMakeLists.txt ]; then
    # Replace unconditional ADD_SUBDIRECTORY with conditional one
    sed -i 's/ADD_SUBDIRECTORY(examples)/IF(BUILD_EXAMPLES)\n  ADD_SUBDIRECTORY(examples)\nENDIF()/g' CMakeLists.txt
fi

mkdir -p build
cd build

# Build libubox as SHARED libraries (for OSS-Fuzz $ORIGIN approach)
cmake .. -DCMAKE_INSTALL_PREFIX="$DEPS_DIR/install" \
         -DCMAKE_C_FLAGS="$CFLAGS" \
         -DBUILD_LUA=OFF \
         -DBUILD_EXAMPLES=OFF \
         -DBUILD_TESTS=OFF \
         -DBUILD_SHARED_LIBS=ON \
         -DCMAKE_POSITION_INDEPENDENT_CODE=ON
make -j$(nproc)
make install
cd "$DEPS_DIR"

# Create lib directory in $OUT for shared libraries
mkdir -p "$OUT/lib"

# Copy shared libraries to $OUT/lib
echo "Copying shared libraries to $OUT/lib..."
cp "$DEPS_DIR/install/lib"/*.so* "$OUT/lib/" 2>/dev/null || true

# Also copy system libraries that the fuzzer depends on
echo "Copying required system libraries..."
# Find and copy libjson-c
find /usr/lib* /lib* -name "libjson-c.so*" -exec cp {} "$OUT/lib/" \; 2>/dev/null || true
# Find and copy libcrypt
find /usr/lib* /lib* -name "libcrypt.so*" -exec cp {} "$OUT/lib/" \; 2>/dev/null || true

# Return to source directory
cd ..

# Remove static declarations from functions we want to fuzz
echo "Making fuzzing target functions non-static..."
sed -i 's/static void client_parse_header/void client_parse_header/g' client.c
sed -i 's/static bool __handle_file_request/bool __handle_file_request/g' file.c

# Remove _GNU_SOURCE redefinitions to avoid warnings (it's already in CFLAGS)
echo "Removing _GNU_SOURCE redefinitions to avoid warnings..."
find . -name "*.c" -exec sed -i 's/#define _GNU_SOURCE//g' {} \;

# Add function declarations to header if not already present
if ! grep -q "void client_parse_header" uhttpd.h; then
    echo "Adding client_parse_header declaration to uhttpd.h..."
    sed -i '/void uh_client_notify_state/a void client_parse_header(struct client *cl, char *data);' uhttpd.h
fi

if ! grep -q "bool __handle_file_request" uhttpd.h; then
    echo "Adding __handle_file_request declaration to uhttpd.h..."
    sed -i '/void client_parse_header/a bool __handle_file_request(struct client *cl, char *url, bool is_error_handler);' uhttpd.h
fi

# Set up build environment  
: "${CFLAGS:=-O1 -fno-omit-frame-pointer}"
: "${LDFLAGS:=}"
: "${PKG_CONFIG_PATH:=}"
: "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"

# Add fuzzing flags
export CFLAGS="$CFLAGS -fsanitize=fuzzer-no-link,address"  
export LDFLAGS="$LDFLAGS -fsanitize=fuzzer-no-link,address"

# Add dependencies to build environment
export PKG_CONFIG_PATH="$DEPS_DIR/install/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"  
export CFLAGS="$CFLAGS -I$DEPS_DIR/install/include"
export LDFLAGS="$LDFLAGS -L$DEPS_DIR/install/lib"

# Add $ORIGIN rpath for shared libraries
export LDFLAGS="$LDFLAGS -Wl,-rpath,'\$ORIGIN/lib'"

# Add uhttpd-specific flags
export CFLAGS="$CFLAGS -D_GNU_SOURCE -DHAVE_SHADOW"  
export CFLAGS="$CFLAGS -Wno-c23-extensions -std=gnu99"

echo "Compiling uhttpd source files..."

# Compile uhttpd source files (excluding main.c to avoid conflicts)
$CC $CFLAGS -c utils.c -o utils.o
$CC $CFLAGS -c client.c -o client.o
$CC $CFLAGS -c file.c -o file.o  
$CC $CFLAGS -c auth.c -o auth.o
$CC $CFLAGS -c proc.c -o proc.o
$CC $CFLAGS -c handler.c -o handler.o
$CC $CFLAGS -c listen.c -o listen.o  
$CC $CFLAGS -c plugin.c -o plugin.o
$CC $CFLAGS -c relay.c -o relay.o
# Skip tls.c since TLS is disabled  
$CC $CFLAGS -c cgi.c -o cgi.o

echo "Creating minimal stub functions for missing symbols..."  
cat > missing_symbols.c << 'EOF'
// Minimal stub functions for missing symbols that aren't in libubox
#include <stdint.h>
#include <stdio.h>

// Global buffer used by uhttpd
char uh_buf[4096];

// TLS functions (stubbed since TLS is disabled)
int uh_tls_init(const char *key, const char *crt, const char *ciphers) { return 0; }
void uh_tls_client_attach(void *cl) { }  
void uh_tls_client_detach(void *cl) { }

// Connection close function
void uh_connection_close(void *cl) { }

// JSON script functions (stubbed since we don't need handler functionality for fuzzing)
void json_script_init(void *ctx, void *ops, void *priv) { }
void *json_script_file_from_blobmsg(const char *name, void *blob, int len) { return NULL; }
void json_script_run_file(void *ctx, void *file, void *vars) { }
void json_script_abort(void *ctx) { }  
EOF

$CC $CFLAGS -c missing_symbols.c -o missing_symbols.o

echo "Compiling fuzzer..."
$CC $CFLAGS -c uhttpd-fuzz.c -o uhttpd-fuzz.o

echo "Linking fuzzer with shared libraries..."  

# Link with shared libraries using $ORIGIN rpath
$CC $CFLAGS $LIB_FUZZING_ENGINE uhttpd-fuzz.o \
    utils.o client.o file.o auth.o proc.o handler.o listen.o plugin.o \
    relay.o cgi.o missing_symbols.o \
    $LDFLAGS \
    -lubox -lblobmsg_json -ljson-c -lcrypt -ldl \
    -o $OUT/uhttpd_fuzzer

# Alternative: Use patchelf to set rpath after linking (if needed)
# This is useful if the linker flags don't work properly
echo "Ensuring correct rpath with patchelf..."
patchelf --set-rpath '$ORIGIN/lib' $OUT/uhttpd_fuzzer

# Copy all required shared library dependencies
echo "Finding and copying all shared library dependencies..."

# Create a temporary script to copy dependencies
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
./copy_deps.sh "$OUT/uhttpd_fuzzer" "$OUT/lib"

# Verify the binary dependencies and rpath
echo "Checking binary dependencies..."
ldd $OUT/uhttpd_fuzzer || echo "ldd may show missing libs due to \$ORIGIN rpath, but they should be in lib/"

echo "Checking rpath..."
readelf -d $OUT/uhttpd_fuzzer | grep -E "(RPATH|RUNPATH)" || echo "No rpath found"

# Verify that all required shared libraries are in $OUT/lib
echo "Shared libraries in $OUT/lib:"
ls -la $OUT/lib/

# Clean up object files and temporary scripts
rm -f *.o copy_deps.sh

echo "Build completed successfully!"
echo "Fuzzer binary: $OUT/uhttpd_fuzzer"
echo "Shared libraries: $OUT/lib/"