#!/bin/bash -eu

apt-get update
apt-get install -y build-essential cmake pkg-config git libjson-c-dev

DEPS_DIR="$PWD/deps"
mkdir -p "$DEPS_DIR"
cd "$DEPS_DIR"

if [ ! -d libubox ]; then
  git clone https://github.com/openwrt/libubox.git
fi
cmake -S libubox -B libubox/build \
  -DCMAKE_INSTALL_PREFIX="$DEPS_DIR/install" \
  -DCMAKE_C_FLAGS="$CFLAGS" \
  -DBUILD_STATIC=ON \
  -DBUILD_SHARED_LIBS=OFF \
  -DBUILD_LUA=OFF \
  -DBUILD_EXAMPLES=OFF
cmake --build libubox/build --target install -j"$(nproc)"

if [ ! -d uci ]; then
  git clone https://git.openwrt.org/project/uci.git
fi
cmake -S uci -B uci/build \
  -DCMAKE_INSTALL_PREFIX="$DEPS_DIR/install" \
  -DCMAKE_C_FLAGS="$CFLAGS" \
  -DBUILD_STATIC=ON \
  -DBUILD_SHARED_LIBS=OFF \
  -DBUILD_LUA=OFF
cmake --build uci/build --target install -j"$(nproc)"
cp uci/build/libuci.a "$DEPS_DIR/install/lib/"

if [ ! -d libnl-tiny ]; then
  git clone https://git.openwrt.org/project/libnl-tiny.git
fi
cmake -S libnl-tiny -B libnl-tiny/build \
  -DCMAKE_INSTALL_PREFIX="$DEPS_DIR/install" \
  -DCMAKE_C_FLAGS="$CFLAGS" \
  -DBUILD_SHARED_LIBS=OFF
cmake --build libnl-tiny/build --target install -j"$(nproc)"

if [ ! -d ubus ]; then
  git clone https://git.openwrt.org/project/ubus.git
fi
cmake -S ubus -B ubus/build \
  -DCMAKE_INSTALL_PREFIX="$DEPS_DIR/install" \
  -DCMAKE_C_FLAGS="$CFLAGS" \
  -DBUILD_STATIC=ON \
  -DCMAKE_EXE_LINKER_FLAGS="-lrt" \
  -DBUILD_SHARED_LIBS=OFF \
  -DBUILD_LUA=OFF \
  -DBUILD_EXAMPLES=OFF
cmake --build ubus/build --target install -j"$(nproc)"

: "${CFLAGS:=-O2 -fPIC}"
: "${LDFLAGS:=}"
# Honour the sanitizer/engine flags supplied by the oss-fuzz build helper.
# If the variable is unset (e.g. manual run) fall back to empty.
: "${LIB_FUZZING_ENGINE:=}"
export CFLAGS="$CFLAGS -Wno-c23-extensions"
export PKG_CONFIG_PATH="$DEPS_DIR/install/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export CFLAGS="$CFLAGS -I$DEPS_DIR/install/include"
export CFLAGS="$CFLAGS -I$DEPS_DIR/install/include/libnl-tiny"
export LDFLAGS="$LDFLAGS -L$DEPS_DIR/install/lib"
export CFLAGS="$CFLAGS -D_GNU_SOURCE -DDHCPV4_SUPPORT -DWITH_UBUS -std=gnu99"

# The project’s source was copied to $SRC/oss-fuzz-auto during the Docker
# build (see Dockerfile).  Build the object files there.
cd "$SRC/oss-fuzz-auto"
ls -la
for f in odhcpd.c config.c router.c dhcpv6.c ndp.c dhcpv6-ia.c dhcpv6-pxe.c netlink.c dhcpv4.c ubus.c; do
  $CC $CFLAGS -c "$f" -o "${f%.c}.o"
done
$CC $CFLAGS -c "fuzz_odhcpd.c" -o fuzz_odhcpd.o

$LINK_FLAGS=""
if [ -n "${LIB_FUZZING_ENGINE}" ]; then
  LINK_FLAGS="${LIB_FUZZING_ENGINE}"
fi

$CC $CFLAGS ${LINK_FLAGS} fuzz_odhcpd.o \
  odhcpd.o config.o router.o dhcpv6.o ndp.o dhcpv6-ia.o dhcpv6-pxe.o netlink.o dhcpv4.o ubus.o \
  $LDFLAGS \
  "$DEPS_DIR/install/lib/libubox.a" \
  "$DEPS_DIR/install/lib/libuci.a" \
  "$DEPS_DIR/install/lib/libubus.a" \
  "$DEPS_DIR/install/lib/libnl-tiny.a" \
  -Wl,-Bstatic -ljson-c -Wl,-Bdynamic \
  -lresolv -lrt \
  -o "$OUT/odhcpd_fuzzer"

rm -f *.o
echo "Build completed successfully!"
echo "Fuzzer binary (combined DHCPv4/DHCPv6): $OUT/odhcpd_fuzzer"
