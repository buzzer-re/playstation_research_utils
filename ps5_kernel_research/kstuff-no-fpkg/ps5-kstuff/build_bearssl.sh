SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ "$(uname -s)" = "Darwin" ]; then
    CROSS_CC="${CROSS_CC:-x86_64-elf-gcc}"
    NPROC="$(sysctl -n hw.ncpu)"
    NOSTDINC=""
else
    CROSS_CC="${CROSS_CC:-gcc}"
    NPROC="$(nproc)"
    NOSTDINC="-nostdinc"
fi

cd BearSSL
for i in clean "lib -j${NPROC}"; do make CC="${CROSS_CC} -std=gnu11 -nostdlib ${NOSTDINC} -isystem ${SCRIPT_DIR}/../freebsd-headers -O3 -march=x86-64-v3 -g -ffreestanding -mgeneral-regs-only -ffunction-sections -fdata-sections -fvisibility=hidden -include ${SCRIPT_DIR}/overrides.h" $i; done
