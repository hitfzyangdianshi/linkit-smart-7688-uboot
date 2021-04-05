# (modified) linkit-smart-uboot
This is forked from MediaTek-Labs/linkit-smart-7688-uboot (https://github.com/MediaTek-Labs/linkit-smart-7688-uboot).

The initial README file refers to https://github.com/MediaTek-Labs/linkit-smart-7688-uboot/blob/master/README.md 

The codes are modified for firmware signature verify with ECDSA, and secure firmware update. Additional changes on the firmware/device partitions are needed for storing new firmware and update information. 

The ECDSA library from https://github.com/jestan/easy-ecc is used. 

There are also some head files and source codes from u-boot-2021.01-rc4 (https://github.com/u-boot/u-boot/releases/tag/v2021.01-rc4) and from buildroot-gcc342 (https://github.com/MediaTek-Labs/linkit-smart-7688-uboot/blob/master/buildroot-gcc342.tar.bz2) are used.

The file changelog is [changes_summary/changes.txt](changes_summary/changes.txt)

Openwrt19 (https://github.com/openwrt/openwrt/tree/v19.07.7 ) is used as the firmware of the device. The partition is modified in the file ([openwrt19/openwrt/target/linux/ramips/dts/LINKIT7688.dts](openwrt19/openwrt/target/linux/ramips/dts/LINKIT7688.dts))



# NOTICE
The head file "stdio.h" is not used and cannot be used here, because functions about printing are defined in other files, so I make it as an empty file. 

# Visual Studio
**_CRT_SECURE_NO_WARNINGS**

https://docs.microsoft.com/zh-cn/cpp/error-messages/compiler-warnings/compiler-warning-level-3-c4996?f1url=%3FappId%3DDev16IDEF1%26l%3DZH-CN%26k%3Dk(C4996)%26rd%3Dtrue&view=msvc-160 

https://docs.microsoft.com/en-us/cpp/error-messages/compiler-warnings/compiler-warning-level-3-c4996?f1url=%3FappId%3DDev16IDEF1&l=ZH-CN&k=k(C4996)&rd=true&view=msvc-160

