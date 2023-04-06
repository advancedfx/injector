# injector

This injector is used by https://github.com/advancedfx/advancedfx / HLAE.

The reason for it being an own package / installer is to avoid frequent AV false-positives due to rebuilds.

# How to build

```
rustup target add i686-pc-windows-msvc
rustup target add x86_64-pc-windows-msvc
```

```
cargo build --target i686-pc-windows-msvc --release
cargo build --target x86_64-pc-windows-msvc --release
```
