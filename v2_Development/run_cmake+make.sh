#!/bin/sh
rm uninstall.sh
echo ====== x86_64 =====
rm -R build
cmake -Bbuild
cd build
make
cd ..
echo ======  armhf =====
rm -R build-armhf
cmake -DCMAKE_TARGET=armhf -Bbuild-armhf
cd build-armhf
make
cd ..
echo ===== aarch64 =====
rm -R build-aarch64
cmake -DCMAKE_TARGET=aarch64 -Bbuild-aarch64
cd build-aarch64
make
cd ..

