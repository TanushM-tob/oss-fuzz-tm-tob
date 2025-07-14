#!/bin/bash -eu
# Copyright 2024 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

# Install required base packages
apt-get update
apt-get install -y build-essential cmake pkg-config git libjson-c-dev

# === Build third-party dependencies statically (libubox + libubus) ===
DEPS_DIR="$PWD/deps"
INSTALL_DIR="$DEPS_DIR/install"
mkdir -p "$DEPS_DIR"
cd "$DEPS_DIR"

# ---------- libubox ----------
if [ ! -d "libubox" ]; then
  git clone --depth 1 https://github.com/openwrt/libubox.git
fi
cd libubox
rm -rf tests || true
mkdir -p build && cd build
cmake .. \
  -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
  -DCMAKE_C_FLAGS="$CFLAGS" \
  -DBUILD_LUA=OFF \
  -DBUILD_EXAMPLES=OFF \
  -DBUILD_TESTS=OFF \
  -DBUILD_STATIC=ON \
  -DBUILD_SHARED_LIBS=OFF
make -j$(nproc)
make install
cd "$DEPS_DIR"

# ---------- libubus ----------
if [ ! -d "ubus" ]; then
  git clone --depth 1 https://git.openwrt.org/project/ubus.git
fi
cd ubus
rm -rf tests || true
mkdir -p build && cd build
cmake .. \
  -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
  -DCMAKE_C_FLAGS="$CFLAGS" \
  -DCMAKE_EXE_LINKER_FLAGS="-lrt" \
  -DBUILD_LUA=OFF \
  -DBUILD_EXAMPLES=OFF \
  -DBUILD_TESTS=OFF \
  -DBUILD_STATIC=ON \
  -DBUILD_SHARED_LIBS=OFF
make -j$(nproc)
make install
cd "$DEPS_DIR"

cd "$SRC/oss-fuzz-auto"

# Export paths for pkg-config & compiler
export PKG_CONFIG_PATH="$INSTALL_DIR/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
: "${LDFLAGS:=}"
export CFLAGS="$CFLAGS -I$INSTALL_DIR/include -D_GNU_SOURCE -std=gnu99 -DSECCOMP_SUPPORT"
# Add fallback for newer audit architecture constants that might not be in older headers
export CFLAGS="$CFLAGS -DAUDIT_ARCH_LOONGARCH64=0xc00000e2"
export LDFLAGS="$LDFLAGS -L$INSTALL_DIR/lib"

# Generate capabilities-names.h (required by jail/capabilities.c)
# Ensure script has Unix line endings
sed -i 's/\r$//' make_capabilities_h.sh
bash ./make_capabilities_h.sh "$CC" > capabilities-names.h

# Generate syscall-names.h (required by jail/seccomp-oci.c)
sed -i 's/\r$//' make_syscall_h.sh
bash ./make_syscall_h.sh "$CC" > syscall-names.h

# === Compile procd sources required for parseOCI ===
# Build all jail/* and utils/utils.c as position-independent objects
OBJ_DIR="$PWD/obj"
mkdir -p "$OBJ_DIR"

# Compile only the jail sources needed for parseOCI (exclude netifd.c and preload.c)
jail_sources="jail.c capabilities.c cgroups.c cgroups-bpf.c fs.c seccomp.c seccomp-oci.c elf.c"
for src in $jail_sources; do
  if [[ "$src" == "jail.c" ]]; then
    $CC $CFLAGS -Dmain=procd_jail_main -c "jail/$src" -o "$OBJ_DIR/$(basename $src .c).o"
  else
    $CC $CFLAGS -c "jail/$src" -o "$OBJ_DIR/$(basename $src .c).o"
  fi
done

# Compile additional helpers from utils (exclude askfirst.c)
$CC $CFLAGS -c utils/utils.c -o "$OBJ_DIR/utils.o"

# === Compile the fuzzer ===
$CC $CFLAGS -c procd-fuzz.c -o "$OBJ_DIR/fuzzer.o"

# Link statically
$CC $CFLAGS $LIB_FUZZING_ENGINE \
  "$OBJ_DIR"/*.o \
  "$INSTALL_DIR/lib/libubus.a" \
  "$INSTALL_DIR/lib/libubox.a" \
  "$INSTALL_DIR/lib/libblobmsg_json.a" \
  $LDFLAGS -ljson-c -pthread -lrt -o $OUT/procd-fuzzer

# Seed corpus directory (empty – OSS-Fuzz will populate) 
mkdir -p $OUT/procd-fuzzer_seed_corpus

# Create lib directory for shared libraries
mkdir -p $OUT/lib

# This is useful if the linker flags don't work properly
echo "Ensuring correct rpath with patchelf..."
patchelf --set-rpath '$ORIGIN/lib' $OUT/procd-fuzzer

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

# Debug: Show what ldd finds for our binary
echo "Direct ldd output for procd-fuzzer:"
ldd "$OUT/procd-fuzzer" || echo "ldd failed"

# Run the dependency copy script
./copy_deps.sh "$OUT/procd-fuzzer" "$OUT/lib"

# Verify the binary dependencies and rpath
echo "Checking binary dependencies..."
ldd $OUT/procd-fuzzer || echo "ldd may show missing libs due to \$ORIGIN rpath, but they should be in lib/"

echo "Checking rpath..."
readelf -d $OUT/procd-fuzzer | grep -E "(RPATH|RUNPATH)" || echo "No rpath found"

# Verify that all required shared libraries are in $OUT/lib
echo "Shared libraries in $OUT/lib:"
ls -la $OUT/lib/

# Clean up object files and temporary scripts
rm -f *.o copy_deps.sh

echo "Build completed successfully!"
echo "Fuzzer binary: $OUT/procd-fuzzer"
echo "Shared libraries: $OUT/lib/"
