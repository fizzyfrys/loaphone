# Android rc fixtures

Unmodified files from LineageOS/android_device_oneplus_msm8998-common,
commit `213a9c24ebcc555c67fde3af8c7c7951502b20cd` (lineage-22.2).
Copyright and redistribution notices are retained in each file.

- https://raw.githubusercontent.com/LineageOS/android_device_oneplus_msm8998-common/213a9c24ebcc555c67fde3af8c7c7951502b20cd/rootdir/etc/ueventd.qcom.rc
- https://raw.githubusercontent.com/LineageOS/android_device_oneplus_msm8998-common/213a9c24ebcc555c67fde3af8c7c7951502b20cd/rootdir/etc/init.qcom.rc

# Rootfs source fixtures

`rootfs-pmos.json` and `rootfs-droidian.json` retain selected fields/entries
from https://images.nura.eco/bpo/index.json and
https://api.github.com/repos/droidian-images/droidian/releases/latest,
retrieved 2026-11-21. They exercise the public index schemas without network
access; boot and device-specific assets are deliberately included as decoys.
