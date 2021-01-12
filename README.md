# (modified) linkit-smart-uboot
This is forked from MediaTek-Labs/linkit-smart-7688-uboot (https://github.com/MediaTek-Labs/linkit-smart-7688-uboot).

The initial README file is referred to https://github.com/MediaTek-Labs/linkit-smart-7688-uboot/blob/master/README.md 

The codes are modified for firmware signature verify with ECDSA, and secure firmware update. Additional changes on the firmware/device partitions are needed for storing new firmware and update information. 

The ECDSA library from https://github.com/jestan/easy-ecc is used. 

There are also some head files and source codes from u-boot-2021.01-rc4 (https://github.com/u-boot/u-boot/releases/tag/v2021.01-rc4) and from buildroot-gcc342 (https://github.com/MediaTek-Labs/linkit-smart-7688-uboot/blob/master/buildroot-gcc342.tar.bz2) are used.

The file changelog is [changes_summary/changes.txt](changes_summary/changes.txt)

