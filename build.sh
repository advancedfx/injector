#!/bin/bash

echo 'Installing base-devel if required ...'
pacman -S --needed base-devel

echo 'Preparing source ...'
tar -czf "mingw-w64-advancedfx-injector/advancedfx-injector-2.0.tar.gz" --transform 's,^,/advancedfx-injector-2.0/,' --exclude "mingw-w64-advancedfx-injector" --exclude "./.*" ./
cd ./mingw-w64-advancedfx-injector

echo 'Building ...'
MINGW_ARCH=mingw32\ mingw64 makepkg-mingw --cleanbuild --syncdeps --force --noconfirm
