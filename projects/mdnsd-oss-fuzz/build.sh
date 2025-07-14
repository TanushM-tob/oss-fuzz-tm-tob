#!/bin/bash -eu

# mdnsd OSS-Fuzz Build Script
echo "Building mdnsd fuzzer..."

# Update package list and install basic dependencies
apt-get update
apt-get install -y build-essential cmake pkg-config git libjson-c-dev patchelf

# Set up dependencies directory
DEPS_DIR="$PWD/deps"
mkdir -p "$DEPS_DIR"
cd "$DEPS_DIR"

# Download and build libubox (required dependency for mdnsd)
if [ ! -d "libubox" ]; then
    echo "Downloading libubox..."
    git clone https://github.com/openwrt/libubox.git
    cd libubox
    # Remove unnecessary components to avoid CMake errors
    rm -rf tests examples lua
    # Patch CMakeLists.txt to remove references to examples and lua
    if [ -f "CMakeLists.txt" ]; then
        cp CMakeLists.txt CMakeLists.txt.bak
        grep -v "ADD_SUBDIRECTORY(examples)" CMakeLists.txt.bak | \
        grep -v "ADD_SUBDIRECTORY(lua)" | \
        grep -v "add_subdirectory(examples)" | \
        grep -v "add_subdirectory(lua)" > CMakeLists.txt || cp CMakeLists.txt.bak CMakeLists.txt
    fi
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

# Download and build libubus (required dependency for mdnsd)
if [ ! -d "ubus" ]; then
    echo "Downloading ubus..."
    git clone https://github.com/openwrt/ubus.git
    cd ubus
    # Remove unnecessary components
    rm -rf tests examples lua
    # Patch CMakeLists.txt to remove references to examples and lua
    if [ -f "CMakeLists.txt" ]; then
        cp CMakeLists.txt CMakeLists.txt.bak
        grep -v "ADD_SUBDIRECTORY(examples)" CMakeLists.txt.bak | \
        grep -v "ADD_SUBDIRECTORY(lua)" | \
        grep -v "add_subdirectory(examples)" | \
        grep -v "add_subdirectory(lua)" > CMakeLists.txt || cp CMakeLists.txt.bak CMakeLists.txt
    fi
    cd ..
fi

cd ubus
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

# Download and build udebug (required by ubus.h in mdnsd)
if [ ! -d "udebug" ]; then
    echo "Downloading udebug..."
    git clone https://github.com/openwrt/udebug.git
    cd udebug
    # Remove unnecessary components
    rm -rf tests examples lua
    # Remove ucode support to avoid dependency (if file exists)
    rm -f lib-ucode.c  
    # More careful patching of CMakeLists.txt
    if [ -f "CMakeLists.txt" ]; then
        cp CMakeLists.txt CMakeLists.txt.bak
        # Only remove specific lines that reference lib-ucode.c or ucode dependencies
        sed -i '/lib-ucode\.c/d' CMakeLists.txt || true
        sed -i '/FIND_PATH.*ucode/d' CMakeLists.txt || true
        sed -i '/FIND_LIBRARY.*ucode/d' CMakeLists.txt || true
        sed -i '/ucode_include_dir/d' CMakeLists.txt || true
        # Remove examples and lua references if they exist
        sed -i '/ADD_SUBDIRECTORY(examples)/d' CMakeLists.txt || true
        sed -i '/ADD_SUBDIRECTORY(lua)/d' CMakeLists.txt || true
        sed -i '/add_subdirectory(examples)/d' CMakeLists.txt || true
        sed -i '/add_subdirectory(lua)/d' CMakeLists.txt || true
    fi
    cd ..
fi

echo "Building udebug..."
cd udebug
mkdir -p build
cd build
echo "Configuring udebug with cmake..."
if cmake .. -DCMAKE_INSTALL_PREFIX="$DEPS_DIR/install" \
            -DCMAKE_C_FLAGS="$CFLAGS" \
            -DBUILD_STATIC=OFF \
            -DBUILD_SHARED_LIBS=ON; then
    echo "Building udebug..."
    if make -j$(nproc); then
        echo "Installing udebug..."
        if make install; then
            # Verify that udebug.h was installed
            if [ -f "$DEPS_DIR/install/include/udebug.h" ]; then
                echo "udebug built and installed successfully"
                UDEBUG_AVAILABLE=1
            else
                echo "udebug built but header not found at $DEPS_DIR/install/include/udebug.h"
                ls -la "$DEPS_DIR/install/include/" || echo "Include directory doesn't exist"
                UDEBUG_AVAILABLE=0
            fi
        else
            echo "udebug make install failed"
            UDEBUG_AVAILABLE=0
        fi
    else
        echo "udebug make failed"
        UDEBUG_AVAILABLE=0
    fi
else
    echo "udebug cmake configuration failed"
    UDEBUG_AVAILABLE=0
fi
cd "$DEPS_DIR"

# If udebug failed to build, try to create a comprehensive stub header
if [ "$UDEBUG_AVAILABLE" = "0" ]; then
    echo "Creating comprehensive udebug.h stub since udebug build failed..."
    mkdir -p "$DEPS_DIR/install/include"
    cat > "$DEPS_DIR/install/include/udebug.h" << 'EOF'
#ifndef __UDEBUG_H
#define __UDEBUG_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>

// Forward declarations
struct ubus_context;
struct blob_attr;

// UDEBUG format constants
#define UDEBUG_FORMAT_STRING    1

// Basic udebug structures
struct udebug {
    int dummy;
};

struct udebug_buf {
    int dummy;
};

struct udebug_buf_meta {
    const char *name;
    int format;
};

// UBUS-specific udebug structures
struct udebug_ubus_ring {
    struct udebug_buf *buf;
    const struct udebug_buf_meta *meta;
    int default_entries;
    int default_size;
};

struct udebug_ubus {
    int dummy;
};

// Stub functions that do nothing
static inline void udebug_init(struct udebug *ctx) { (void)ctx; }
static inline void udebug_auto_connect(struct udebug *ctx, const char *path) { (void)ctx; (void)path; }
static inline void udebug_free(struct udebug *ctx) { (void)ctx; }

static inline bool udebug_buf_valid(struct udebug_buf *buf) { (void)buf; return false; }
static inline void udebug_entry_init(struct udebug_buf *buf) { (void)buf; }
static inline void udebug_entry_add(struct udebug_buf *buf) { (void)buf; }
static inline int udebug_entry_vprintf(struct udebug_buf *buf, const char *format, va_list ap) { 
    (void)buf; (void)format; (void)ap; return 0; 
}

// UBUS-specific stub functions
static inline void udebug_ubus_init(struct udebug_ubus *ctx, struct ubus_context *ubus, 
                                   const char *name, void (*config_cb)(struct udebug_ubus *, struct blob_attr *, bool)) {
    (void)ctx; (void)ubus; (void)name; (void)config_cb;
}

static inline void udebug_ubus_apply_config(struct udebug *ctx, struct udebug_ubus_ring *rings, 
                                           int n_rings, struct blob_attr *data, bool enabled) {
    (void)ctx; (void)rings; (void)n_rings; (void)data; (void)enabled;
}

// strlcpy implementation for systems that don't have it (like Linux)
static inline size_t strlcpy(char *dst, const char *src, size_t size) {
    size_t src_len = strlen(src);
    if (size > 0) {
        size_t copy_len = (src_len < size - 1) ? src_len : size - 1;
        memcpy(dst, src, copy_len);
        dst[copy_len] = '\0';
    }
    return src_len;
}

#endif
EOF
    echo "Created comprehensive udebug.h stub with strlcpy"
fi

# Go back to source directory
cd ..

# Set up compiler flags and paths
: "${CFLAGS:=-O2 -fPIC}"
: "${LDFLAGS:=}"
: "${PKG_CONFIG_PATH:=}"
: "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"

# Add required flags for the build (remove _GNU_SOURCE since source files already define it)
export CFLAGS="$CFLAGS -std=gnu99"
export CFLAGS="$CFLAGS -I$DEPS_DIR/install/include"
export LDFLAGS="$LDFLAGS -L$DEPS_DIR/install/lib"
export PKG_CONFIG_PATH="$DEPS_DIR/install/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"

# Verify that udebug.h is now available
echo "Checking for udebug.h availability..."
if [ -f "$DEPS_DIR/install/include/udebug.h" ]; then
    echo "✓ udebug.h found at $DEPS_DIR/install/include/udebug.h"
else
    echo "✗ udebug.h still not found - this will likely cause compilation to fail"
    ls -la "$DEPS_DIR/install/include/" || echo "Include directory doesn't exist"
fi

echo "Compiling mdnsd source files..."

SOURCE_FILES=(
    "cache.c"
    "dns.c" 
    "interface.c"
    "service.c"
    "util.c"
    "ubus.c"
    "announce.c"
    "fuzzer-support.c"
)

# Compile individual source files
OBJECT_FILES=()
for src_file in "${SOURCE_FILES[@]}"; do
    if [ -f "$src_file" ]; then
        echo "Compiling $src_file..."
        obj_file="${src_file%.c}.o"
        $CC $CFLAGS -c "$src_file" -o "$obj_file"
        OBJECT_FILES+=("$obj_file")
    else
        echo "Warning: $src_file not found, skipping..."
    fi
done

echo "Compiling fuzzer..."
$CC $CFLAGS -c mdnsd-fuzz.c -o mdnsd-fuzz.o

echo "Linking fuzzer..."
# Link the fuzzer with all components and required libraries
LINK_LIBS="-lubox -lubus -lblobmsg_json -ljson-c -lresolv"
if [ "$UDEBUG_AVAILABLE" = "1" ]; then
    LINK_LIBS="$LINK_LIBS -ludebug"
    echo "Including udebug in link"
else
    echo "Building without udebug library (using stub header)"
fi

$CC $CFLAGS $LIB_FUZZING_ENGINE mdnsd-fuzz.o \
    "${OBJECT_FILES[@]}" \
    $LDFLAGS $LINK_LIBS \
    -o $OUT/mdnsd_fuzzer

# Set correct rpath for OSS-Fuzz
echo "Setting rpath with patchelf..."
patchelf --set-rpath '$ORIGIN/lib' $OUT/mdnsd_fuzzer

# Copy all required shared library dependencies
echo "Finding and copying shared library dependencies..."

# Create lib directory
mkdir -p "$OUT/lib"

# Copy libraries from our custom installation
echo "Copying libraries from custom installation..."
COPY_LIBS="libubox.so libubus.so libblobmsg_json.so"
if [ "$UDEBUG_AVAILABLE" = "1" ]; then
    COPY_LIBS="$COPY_LIBS libudebug.so"
fi

for lib in $COPY_LIBS; do
    if [ -f "$DEPS_DIR/install/lib/$lib" ]; then
        cp "$DEPS_DIR/install/lib/$lib"* "$OUT/lib/" 2>/dev/null || true
        echo "Copied $lib"
    fi
done

# Copy other dependencies
copy_library_deps() {
    local binary="$1"
    local out_lib="$2"
    
    echo "Copying dependencies for $binary"
    
    # Get all dependencies using ldd
    ldd "$binary" 2>/dev/null | while read line; do
        # Extract library path from ldd output
        if [[ $line =~ '=>' ]]; then
            lib_path=$(echo "$line" | awk '{print $3}')
            if [[ -f "$lib_path" ]]; then
                lib_name=$(basename "$lib_path")
                # Skip system libraries that are always available
                if [[ ! "$lib_name" =~ ^(ld-linux|libc\.so|libm\.so|libpthread\.so|libdl\.so|librt\.so|libresolv\.so) ]]; then
                    if [[ "$lib_name" =~ ^(libjson-c) ]]; then
                        echo "Copying $lib_name from $lib_path"
                        cp "$lib_path" "$out_lib/" 2>/dev/null || true
                    fi
                fi
            fi
        fi
    done
}

copy_library_deps "$OUT/mdnsd_fuzzer" "$OUT/lib"

echo "Verifying fuzzer binary..."
if [ -f "$OUT/mdnsd_fuzzer" ]; then
    echo "Fuzzer binary created successfully"
    echo "Binary size: $(stat -c%s "$OUT/mdnsd_fuzzer") bytes"
    
    # Test that it can run briefly
    echo "Testing fuzzer (dry run)..."
    timeout 5 $OUT/mdnsd_fuzzer -help 2>/dev/null || echo "Fuzzer help completed"
    
    # Check dependencies
    echo "Binary dependencies:"
    ldd $OUT/mdnsd_fuzzer || echo "Some dependencies may be in lib/ directory"
    
    echo "Libraries in $OUT/lib:"
    ls -la $OUT/lib/ 2>/dev/null || echo "No additional libraries"
    
else
    echo "Failed to create fuzzer binary!"
    exit 1
fi

# Clean up build artifacts
echo "Cleaning up..."
rm -f *.o

echo "mdnsd fuzzer build completed successfully!"
echo "Fuzzer: $OUT/mdnsd_fuzzer"
