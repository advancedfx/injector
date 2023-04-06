extern crate http_req;
extern crate sha2;
extern crate zip;
#[macro_use]
extern crate unwrap;

use http_req::request;
use sha2::{Digest, Sha512};

use std::process::Command;
use std::env;
use std::fs;
use std::io::Cursor;
use std::path::Path;


#[cfg(windows)]
#[cfg(target_arch = "x86_64")]
const NASM_DOWNLOAD_URL: &'static str = "https://www.nasm.us/pub/nasm/releasebuilds/2.15.05/win64/nasm-2.15.05-win64.zip";

#[cfg(windows)]
#[cfg(target_arch = "x86_64")]
const NASM_DOWNLOAD_SHA512: &'static str = "0d0469f3d475f3d192b9b5b7ee74662cbcb9e02efa0d51839c12cbf6f5de5cd58b32e1d12c9ee4381a63e99a4956e03df7decaf1369e598e0edff19a12629073";

fn build_afxhook_dat_x86(nasm_exe: &str) {
    println!("cargo:rerun-if-changed=AfxHook/AfxHook_586.asm");
    Command::new(nasm_exe).args(&["-f","bin","-o","src/AfxHook_x86.dat","AfxHook/AfxHook_586.asm"]).status().unwrap();
}

fn build_afxhook_dat_x86_64(nasm_exe: &str) {
    println!("cargo:rerun-if-changed=AfxHook/AfxHook_x64.asm");
    Command::new(nasm_exe).args(&["-f","bin","-o","src/AfxHook_x86_64.dat","AfxHook/AfxHook_x64.asm"]).status().unwrap();
}

fn main() {
    let nasm_exe = get_nasm();

    let target: &str = &std::env::var("TARGET").unwrap();
    match target {
        "x86_64-pc-windows-msvc" => build_afxhook_dat_x86_64(&nasm_exe),
        "i686-pc-windows-msvc" => build_afxhook_dat_x86(&nasm_exe),
        "x86_64-pc-windows-gnu" => build_afxhook_dat_x86_64(&nasm_exe),
        "i686-pc-windows-gnu" => build_afxhook_dat_x86(&nasm_exe),
        _ => panic!("Unsupported target {}", target),
    };
}

fn try_download(url: &str, sha512: &str) -> Result<Cursor<Vec<u8>>, String> {
    // Send GET request
    let mut writer = Vec::new();
    let response = request::get(url, &mut writer).map_err(|error| error.to_string())?;

    // Only accept 2xx status codes
    if !response.status_code().is_success() {
        return Err(format!("Download error: HTTP {}", response.status_code()));
    }

    // Check the SHA-256 hash of the downloaded file is as expected
    let hash = Sha512::digest(&writer);
    if &format!("{:x}", hash) != sha512 {
        return Err("Downloaded file failed hash check.".to_string());
    }
    Ok(Cursor::new(writer))
}

fn get_install_dir() -> String {
    unwrap!(env::var("OUT_DIR"))
}

fn get_nasm() -> String {
    use std::fs::File;
    use std::io::{Read, Write};
    use zip::ZipArchive;

    // Download zip file
    let install_dir = get_install_dir();
    let lib_install_dir = Path::new(&install_dir).join("nasm");
    unwrap!(fs::create_dir_all(&lib_install_dir));

    let nasm_exe_path = lib_install_dir.join("nasm.exe");

    if !nasm_exe_path.exists() {
        let compressed_file = try_download(&NASM_DOWNLOAD_URL, &NASM_DOWNLOAD_SHA512).unwrap_or_else(|error| panic!("\n\nDownload error: {}\n\n", error));

        // Unpack the zip file
        let mut zip_archive = unwrap!(ZipArchive::new(compressed_file));

        for i in 0..zip_archive.len() {
            let mut entry = unwrap!(zip_archive.by_index(i));
            let entry_name = entry.name().to_string();
            let entry_path = Path::new(&entry_name);
            let opt_install_path = if entry_path.ends_with("nasm.exe") {
                Some(lib_install_dir.join("nasm.exe"))
            } else {
                None
            };
            if let Some(full_install_path) = opt_install_path {
                let mut buffer = Vec::with_capacity(entry.size() as usize);
                assert_eq!(entry.size(), unwrap!(entry.read_to_end(&mut buffer)) as u64);
                let mut file = unwrap!(File::create(&full_install_path));
                unwrap!(file.write_all(&buffer));
            }
        }
    }
    return nasm_exe_path.display().to_string();
}
