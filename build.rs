use std::process::Command;

#[cfg(target_arch = "x86")]
#[cfg(windows)]
fn build_afxhook_dat() {
    println!("cargo:rerun-if-changed=AfxHook/AfxHook_586.asm");
    Command::new("nasm").args(&["-f","bin","-o","src/AfxHook.dat","AfxHook/AfxHook_586.asm"]).status().unwrap();
}

#[cfg(target_arch = "x86_64")]
#[cfg(windows)]
fn build_afxhook_dat() {
    println!("cargo:rerun-if-changed=AfxHook/AfxHook_x64.asm");
    Command::new("nasm").args(&["-f","bin","-o","src/AfxHook.dat","AfxHook/AfxHook_x64.asm"]).status().unwrap();
}

fn main() {
    build_afxhook_dat();
}