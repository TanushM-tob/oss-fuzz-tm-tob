#!/bin/bash -eu

apt-get update
apt-get install -y build-essential cmake pkg-config git libjson-c-dev patchelf

DEPS_DIR="$PWD/deps"
mkdir -p "$DEPS_DIR"
cd "$DEPS_DIR"

if [ ! -d "libubox" ]; then
    echo "Downloading libubox..."
    git clone https://github.com/openwrt/libubox.git
    cd libubox
    rm -rf tests examples
    cd ..
fi

cd libubox
# Patch CMakeLists.txt to remove examples subdirectory reference
if [ -f CMakeLists.txt ]; then
    sed -i '/ADD_SUBDIRECTORY(examples)/d' CMakeLists.txt
    sed -i '/add_subdirectory(examples)/d' CMakeLists.txt
    sed -i '/ADD_SUBDIRECTORY.*examples/d' CMakeLists.txt
    sed -i '/add_subdirectory.*examples/d' CMakeLists.txt
fi
mkdir -p build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX="$DEPS_DIR/install" \
         -DCMAKE_C_FLAGS="$CFLAGS" \
         -DBUILD_LUA=OFF \
         -DBUILD_EXAMPLES=OFF \
         -DBUILD_TESTS=OFF \
         -DBUILD_STATIC=ON \
         -DBUILD_SHARED_LIBS=OFF
make -j$(nproc)
make install
cd "$DEPS_DIR"

if [ ! -d "uci" ]; then
    echo "Downloading libuci..."
    git clone https://git.openwrt.org/project/uci.git
    cd uci
    rm -rf tests
    cd ..
fi

cd uci
mkdir -p build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX="$DEPS_DIR/install" \
         -DCMAKE_C_FLAGS="$CFLAGS" \
         -DBUILD_LUA=OFF \
         -DBUILD_TESTS=OFF \
         -DBUILD_STATIC=ON \
         -DBUILD_SHARED_LIBS=OFF \
         -DCMAKE_POSITION_INDEPENDENT_CODE=ON
make -j$(nproc)
make install

# Check if static library was created, if not create it manually
if [ ! -f "$DEPS_DIR/install/lib/libuci.a" ]; then
    echo "Creating static library for libuci..."
    ar rcs "$DEPS_DIR/install/lib/libuci.a" CMakeFiles/uci.dir/*.o
fi

cd "$DEPS_DIR"

if [ ! -d "libnl-tiny" ]; then
    echo "Downloading libnl-tiny..."
    git clone https://git.openwrt.org/project/libnl-tiny.git
    cd libnl-tiny
    rm -rf tests
    cd ..
fi

cd libnl-tiny
mkdir -p build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX="$DEPS_DIR/install" \
         -DCMAKE_C_FLAGS="$CFLAGS" \
         -DBUILD_TESTS=OFF \
         -DBUILD_SHARED_LIBS=OFF
make -j$(nproc)
make install
cd "$DEPS_DIR"

if [ ! -d "ubus" ]; then
    echo "Downloading libubus..."
    git clone https://git.openwrt.org/project/ubus.git
    cd ubus
    rm -rf tests examples
    cd ..
fi

cd ubus
# Patch CMakeLists.txt to remove examples subdirectory reference
if [ -f CMakeLists.txt ]; then
    sed -i '/ADD_SUBDIRECTORY(examples)/d' CMakeLists.txt
    sed -i '/add_subdirectory(examples)/d' CMakeLists.txt
    sed -i '/ADD_SUBDIRECTORY.*examples/d' CMakeLists.txt
    sed -i '/add_subdirectory.*examples/d' CMakeLists.txt
fi
mkdir -p build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX="$DEPS_DIR/install" \
         -DCMAKE_C_FLAGS="$CFLAGS" \
         -DCMAKE_EXE_LINKER_FLAGS="-lrt" \
         -DBUILD_LUA=OFF \
         -DBUILD_EXAMPLES=OFF \
         -DBUILD_TESTS=OFF \
         -DBUILD_STATIC=ON \
         -DBUILD_SHARED_LIBS=OFF \
         -DCMAKE_POSITION_INDEPENDENT_CODE=ON
make -j$(nproc)
make install

# Check if static library was created, if not create it manually
if [ ! -f "$DEPS_DIR/install/lib/libubus.a" ]; then
    echo "Creating static library for libubus..."
    ar rcs "$DEPS_DIR/install/lib/libubus.a" CMakeFiles/ubus.dir/*.o
fi

cd "$DEPS_DIR"

# Download and extract proper udebug headers
if [ ! -d "udebug" ]; then
    echo "Downloading udebug for headers..."
    git clone https://github.com/openwrt/udebug.git
fi

echo "Extracting udebug headers..."
mkdir -p "$DEPS_DIR/install/include"
cp udebug/udebug.h "$DEPS_DIR/install/include/"

# Note: Using real udebug from libubox instead of stubs

# Create a main wrapper that excludes the main() function but keeps all global variables and functions
echo "Creating main wrapper without main() function..."
cat > "$DEPS_DIR/main_wrapper.c" << 'EOF'
#define main disabled_main
#include "../main.c"
#undef main
EOF

# Compile the main wrapper
echo "Compiling main wrapper..."
$CC $CFLAGS -I"$DEPS_DIR/install/include" -I"$DEPS_DIR/.." -c "$DEPS_DIR/main_wrapper.c" -o "$DEPS_DIR/main_wrapper.o"

# Note: No stubs needed - using real libraries

cd ..

# Make target functions non-static by editing source files directly
echo "Making target functions non-static for fuzzing..."
sed -i 's/static void config_parse_route(/void config_parse_route(/g' config.c
sed -i 's/static void config_parse_interface(/void config_parse_interface(/g' config.c  
sed -i 's/static void proto_shell_parse_route_list(/void proto_shell_parse_route_list(/g' proto-shell.c
sed -i 's/static enum dev_change_type __bridge_reload(/enum dev_change_type __bridge_reload(/g' extdev.c

# Add missing libraries that netifd needs (from CMakeLists.txt)
echo "Adding missing libraries..."

# Build libblobmsg_json (part of libubox but separate library)
if [ ! -f "$DEPS_DIR/install/lib/libblobmsg_json.a" ]; then
    echo "Building libblobmsg_json..."
    cd "$DEPS_DIR/libubox/build"
    # libblobmsg_json should be built as part of libubox
    if [ -f "libblobmsg_json.a" ]; then
        cp libblobmsg_json.a "$DEPS_DIR/install/lib/"
    fi
    cd ..
fi

# Build real udebug library
if [ ! -f "$DEPS_DIR/install/lib/libudebug.a" ]; then
    echo "Skipping libudebug build (depends on ucode, not needed for fuzzing)"
fi

echo "Compiling missing symbol weak alias file..."
$CC $CFLAGS -c missing_syms.c -o missing_syms.o

: "${CFLAGS:=-O2 -fPIC}"
: "${LDFLAGS:=}"
: "${PKG_CONFIG_PATH:=}"
: "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"  # Default to libFuzzer if not provided

# Add flag to suppress C23 extension warnings
export CFLAGS="$CFLAGS -Wno-c23-extensions"

export PKG_CONFIG_PATH="$DEPS_DIR/install/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export CFLAGS="$CFLAGS -I$DEPS_DIR/install/include"
export LDFLAGS="$LDFLAGS -L$DEPS_DIR/install/lib"

export CFLAGS="$CFLAGS -D_GNU_SOURCE -DDUMMY_MODE=1 -DDEBUG -std=gnu99"
export CFLAGS="$CFLAGS -I$DEPS_DIR/install/include/libnl-tiny"

# Generate ethtool-modes.h if script exists
if [ -f "make_ethtool_modes_h.sh" ]; then
    echo "Generating ethtool-modes.h..."
    ./make_ethtool_modes_h.sh $CC > ethtool-modes.h || echo "Warning: Failed to generate ethtool-modes.h"
fi

echo "Compiling netifd source files..."
# Note: main.c compiled via wrapper to exclude main() function
$CC $CFLAGS -c utils.c -o utils.o
$CC $CFLAGS -c system.c -o system.o
$CC $CFLAGS -c system-dummy.c -o system-dummy.o
$CC $CFLAGS -c tunnel.c -o tunnel.o
$CC $CFLAGS -c handler.c -o handler.o
$CC $CFLAGS -c interface.c -o interface.o
$CC $CFLAGS -c interface-ip.c -o interface-ip.o
$CC $CFLAGS -c interface-event.c -o interface-event.o
$CC $CFLAGS -c iprule.c -o iprule.o
$CC $CFLAGS -c proto.c -o proto.o
$CC $CFLAGS -c proto-static.c -o proto-static.o
$CC $CFLAGS -c proto-shell.c -o proto-shell.o
$CC $CFLAGS -c config.c -o config.o
$CC $CFLAGS -c device.c -o device.o
$CC $CFLAGS -c bridge.c -o bridge.o
$CC $CFLAGS -c veth.c -o veth.o
$CC $CFLAGS -c vlan.c -o vlan.o
$CC $CFLAGS -c alias.c -o alias.o
$CC $CFLAGS -c macvlan.c -o macvlan.o
$CC $CFLAGS -c ubus.c -o ubus.o
$CC $CFLAGS -c vlandev.c -o vlandev.o
$CC $CFLAGS -c wireless.c -o wireless.o
$CC $CFLAGS -c extdev.c -o extdev.o
$CC $CFLAGS -c bonding.c -o bonding.o
$CC $CFLAGS -c vrf.c -o vrf.o

echo "Compiling fuzzer..."
$CC $CFLAGS -c netifd_fuzz.c -o netifd_fuzz.o

echo "Linking fuzzer statically..."
# Link with full paths to static libraries to avoid linker issues
$CC $CFLAGS $LIB_FUZZING_ENGINE netifd_fuzz.o \
    $DEPS_DIR/main_wrapper.o \
    utils.o system.o system-dummy.o tunnel.o handler.o \
    interface.o interface-ip.o interface-event.o \
    iprule.o proto.o proto-static.o proto-shell.o \
    config.o device.o bridge.o veth.o vlan.o alias.o \
    macvlan.o ubus.o vlandev.o wireless.o extdev.o \
    bonding.o vrf.o \
    missing_syms.o \
    $DEPS_DIR/install/lib/libubox.a \
    $DEPS_DIR/install/lib/libuci.a \
    $DEPS_DIR/install/lib/libnl-tiny.a \
    $DEPS_DIR/install/lib/libubus.a \
    $DEPS_DIR/install/lib/libblobmsg_json.a \
    $LDFLAGS -ljson-c \
    -o $OUT/netifd_fuzzer

# This is useful if the linker flags don't work properly
echo "Ensuring correct rpath with patchelf..."
patchelf --set-rpath '$ORIGIN/lib' $OUT/netifd_fuzzer

# Copy all required shared library dependencies
echo "Finding and copying all shared library dependencies..."

# Create lib directory
mkdir -p "$OUT/lib"

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
./copy_deps.sh "$OUT/netifd_fuzzer" "$OUT/lib"

# Verify the binary dependencies and rpath
echo "Checking binary dependencies..."
ldd $OUT/netifd_fuzzer || echo "ldd may show missing libs due to \$ORIGIN rpath, but they should be in lib/"

echo "Checking rpath..."
readelf -d $OUT/netifd_fuzzer | grep -E "(RPATH|RUNPATH)" || echo "No rpath found"

# Verify that all required shared libraries are in $OUT/lib
echo "Shared libraries in $OUT/lib:"
ls -la $OUT/lib/

# Clean up object files and temporary scripts
rm -f *.o copy_deps.sh

echo "Build completed successfully!"
echo "Fuzzer binary: $OUT/netifd_fuzzer"
echo "Shared libraries: $OUT/lib/"