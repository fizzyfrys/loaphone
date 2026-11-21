#!/bin/sh
# Rebuilds the synthetic HAL fixtures with Ubuntu cross compilers.
set -e
cd "$(dirname "$0")"
aarch64-linux-gnu-gcc -O2 -shared -fPIC -o libhalprobe.arm64.so hal_probe.c
arm-linux-gnueabihf-gcc -O2 -shared -fPIC -o libhalprobe.arm.so hal_probe.c
