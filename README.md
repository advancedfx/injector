# injector

This injector is used by https://github.com/advancedfx/advancedfx / HLAE.

The reason for it being an own package / installer is to avoid frequent AV false-positives due to rebuilds.

# How to build

```
mkdir build
cd build
mkdir Release
cd Release
cmake -DCMAKE_BUILD_TYPE=Release -G "Visual Studio 16 2019" -T "v142" -A "Win32" ../..
cmake --build . -v -- -r
cmake --install . -v
cpack -C Release
```