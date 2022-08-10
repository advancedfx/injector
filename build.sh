#!/bin/bash

echo 'Installing base-devel if required ...'
pacman -S --needed base-devel

echo 'Preparing source ...'
tar -czf ./mingw-w64-advancedfx-injector/advancedfx-injector.tar.gz ./advancedfx-injector
cp ./LICENSE ./mingw-w64-advancedfx-injector
cd ./mingw-w64-advancedfx-injector

echo 'Building ...'
MINGW_ARCH=mingw32\ mingw64 makepkg-mingw --cleanbuild --syncdeps --force --noconfirm
