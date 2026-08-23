# Image for `cross` to build and test the riscv64gc-unknown-linux-gnu
# target. The stock cross image carries qemu 8.2, whose hwprobe
# emulation does not report the RISC-V cryptography extensions, so
# the run-time probe never sees them; this image uses Debian 13 qemu
# qemu (10.x), which does.
FROM debian:trixie

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        gcc \
        gcc-riscv64-linux-gnu \
        libc6-dev \
        libc6-dev-riscv64-cross \
        qemu-user-static \
    && rm -rf /var/lib/apt/lists/*

# What cross expects of a target image: how to link, how to run.
# QEMU_CPU (passed through from the host) selects the emulated CPU.
ENV CROSS_TOOLCHAIN_PREFIX=riscv64-linux-gnu- \
    CROSS_SYSROOT=/usr/riscv64-linux-gnu \
    CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER=riscv64-linux-gnu-gcc \
    CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_RUNNER="qemu-riscv64-static \
-L /usr/riscv64-linux-gnu" \
    QEMU_LD_PREFIX=/usr/riscv64-linux-gnu
