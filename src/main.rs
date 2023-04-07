use clap::Parser;
use std::ffi::CString;
use std::os::windows::ffi::OsStrExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use winapi::um::errhandlingapi::{GetLastError};
use winapi::um::libloaderapi::{GetModuleHandleW,GetProcAddress};
use winapi::um::handleapi::{CloseHandle};
use winapi::um::memoryapi::{VirtualAllocEx,VirtualFreeEx,WriteProcessMemory};
use winapi::um::processthreadsapi::{OpenProcess,FlushInstructionCache,CreateRemoteThread,GetExitCodeThread,TerminateThread};
use winapi::um::synchapi::{WaitForSingleObject};
use winapi::um::winbase::{WAIT_OBJECT_0};
use winapi::um::winnt::{MEM_COMMIT,MEM_RESERVE,MEM_RELEASE,PAGE_READWRITE,PAGE_EXECUTE_READWRITE,HANDLE,PROCESS_CREATE_THREAD,PROCESS_QUERY_INFORMATION,PROCESS_VM_OPERATION,PROCESS_VM_WRITE,PROCESS_VM_READ};
use winapi::shared::minwindef::{DWORD,LPVOID,FALSE};

#[derive(Serialize, Deserialize)]
pub enum InjectErrorDetail {
    LastWinApiError(u32),
    ThreadExitCode(u32)
}

#[derive(Serialize, Deserialize)]
pub enum InjectErrorGroup {
    GetModuleHandleW,
    GetProcAddress,
    OpenProcess,
    VirtualAllocEx,
    WriteProcessMemory,
    FlushInstructionCache,
    CreateRemoteThread,
    GetExitCodeThread,
    ThreadExitError,
    IdError,
}

#[derive(Serialize, Deserialize)]
pub enum InjectResult {
    Ok(),
    Timeout(),
    Error{ line: u32, group: InjectErrorGroup, message: String, detail: Option<InjectErrorDetail>}
}

struct Injector {
    h_proc: HANDLE,
    p_arg_dll_dir: LPVOID,
    p_arg_dll_file_path: LPVOID,
    p_image_afx_hook: LPVOID,
    h_thread: HANDLE,
    b_thread_terminated: bool
}

const CREATE_THREAD_ACCESS: DWORD = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;

impl Injector {
    pub fn new() -> Self {
        Self {
            h_proc: std::ptr::null_mut(),
            p_arg_dll_dir: std::ptr::null_mut(),
            p_arg_dll_file_path: std::ptr::null_mut(),
            p_image_afx_hook: std::ptr::null_mut(),
            h_thread: std::ptr::null_mut(),
            b_thread_terminated: false
        }
    }

    pub fn inject(&mut self, process_id: u32, dll_file_path: &str, base_directory: &str, wait_ms: u32) -> InjectResult {
        let result = self.inject_end(InjectResult::Ok{});
        match result {
            InjectResult::Ok() => {
            }
            _ => {
                return result;
            }
        }

        #[cfg(target_arch = "x86")] 
        const AFX_HOOK_DAT: &[u8] = include_bytes!("AfxHook_x86.dat");
        
        #[cfg(target_arch = "x86_64")]
        const AFX_HOOK_DAT: &[u8] = include_bytes!("AfxHook_x86_64.dat");
        
        const AFX_HOOK_DAT_SIZE: usize = AFX_HOOK_DAT.len();
        
        let afx_hook_head: &[u8] = &AFX_HOOK_DAT[0..32];
        let afx_hook_tail: &[u8] = &AFX_HOOK_DAT[48..AFX_HOOK_DAT_SIZE];

        let wsz_kernel32_dll: Vec<u16> = std::ffi::OsStr::new("Kernel32.dll").encode_wide().chain(Some(0)).collect();

        let os_string_dll_file_path = std::ffi::OsStr::new(dll_file_path);
        let os_string_base_directory = std::ffi::OsStr::new(base_directory);
        let wsz_dll_file_path: Vec<u16> = os_string_dll_file_path.encode_wide().chain(Some(0)).collect();
        let wsz_base_directory: Vec<u16> = os_string_base_directory.encode_wide().chain(Some(0)).collect();
        let cb_dll_file_path_size =  wsz_dll_file_path.len();
        let cb_base_directory_size = wsz_base_directory.len();

        let h_kernel32_dll = unsafe{ GetModuleHandleW(wsz_kernel32_dll.as_ptr()) };
        if std::ptr::null() == h_kernel32_dll {
            return InjectResult::Error{ line: line!(), group: InjectErrorGroup::GetModuleHandleW, message: "Could not get Kernel32.dll handle.".to_string(), detail: None };
        }

        let sz_get_module_handle_w = CString::new("GetModuleHandleW").unwrap();
        let p_get_module_handle_w = unsafe{ GetProcAddress(h_kernel32_dll, sz_get_module_handle_w.as_ptr()) };
        if std::ptr::null() == p_get_module_handle_w {
            return InjectResult::Error{ line: line!(), group: InjectErrorGroup::GetProcAddress, message: "Could not get Kernel32.dll!GetModuleHandleW address.".to_string(), detail: None };
        }

        let sz_get_proc_address = CString::new("GetProcAddress").unwrap();
        let p_get_proc_address = unsafe{ GetProcAddress(h_kernel32_dll, sz_get_proc_address.as_ptr()) };
        if std::ptr::null() == p_get_proc_address {
            return InjectResult::Error{ line: line!(), group: InjectErrorGroup::GetProcAddress, message: "Could not get Kernel32.dll!GetProcAddress address.".to_string(), detail: None};
        }

        //

        self.h_proc = unsafe{ OpenProcess(CREATE_THREAD_ACCESS, FALSE, process_id) };
        if std::ptr::null() == self.h_proc {
            let dwlast_error = unsafe{ GetLastError() };
            return InjectResult::Error{ line: line!(), group: InjectErrorGroup::OpenProcess, message: "OpenProcess failed.".to_string(), detail: Some(InjectErrorDetail::LastWinApiError(dwlast_error)) };
        }

        self.p_arg_dll_dir = unsafe{ VirtualAllocEx(self.h_proc, std::ptr::null_mut(), cb_base_directory_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
        if std::ptr::null() == self.p_arg_dll_dir {
            let dwlast_error = unsafe{ GetLastError() };
            return self.inject_end(InjectResult::Error{ line: line!(), group: InjectErrorGroup::VirtualAllocEx, message: "VirtualAllocEx (p_arg_dll_dir) failed.".to_string(), detail: Some(InjectErrorDetail::LastWinApiError(dwlast_error)) });
        }

        self.p_arg_dll_file_path = unsafe{ VirtualAllocEx(self.h_proc, std::ptr::null_mut(), cb_dll_file_path_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
        if std::ptr::null() == self.p_arg_dll_file_path {
            let dwlast_error = unsafe{ GetLastError() };
            return self.inject_end(InjectResult::Error{ line: line!(), group: InjectErrorGroup::VirtualAllocEx, message: "VirtualAllocEx (p_arg_dll_file_path) failed.".to_string(), detail: Some(InjectErrorDetail::LastWinApiError(dwlast_error)) });
        }

        self.p_image_afx_hook = unsafe{ VirtualAllocEx(self.h_proc, std::ptr::null_mut(), AFX_HOOK_DAT_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) };
        if std::ptr::null() == self.p_image_afx_hook {
            let dwlast_error = unsafe{ GetLastError() };
            return self.inject_end(InjectResult::Error{ line: line!(), group: InjectErrorGroup::VirtualAllocEx, message: "VirtualAllocEx (p_image_afx_hook) failed.".to_string(), detail: Some(InjectErrorDetail::LastWinApiError(dwlast_error)) });
        }
        
        if FALSE == unsafe{ WriteProcessMemory(self.h_proc, self.p_arg_dll_dir, wsz_base_directory.as_ptr() as HANDLE, cb_base_directory_size, std::ptr::null_mut()) }{
            let dwlast_error = unsafe{ GetLastError() };
            return self.inject_end(InjectResult::Error{ line: line!(), group: InjectErrorGroup::WriteProcessMemory, message: "WriteProcessMemory (p_arg_dll_dir) failed.".to_string(), detail: Some(InjectErrorDetail::LastWinApiError(dwlast_error)) });
        }
        
        if FALSE == unsafe{ WriteProcessMemory(self.h_proc, self.p_arg_dll_file_path, wsz_dll_file_path.as_ptr() as HANDLE, cb_dll_file_path_size, std::ptr::null_mut()) }{
            let dwlast_error = unsafe{ GetLastError() };
            return self.inject_end(InjectResult::Error{ line: line!(), group: InjectErrorGroup::WriteProcessMemory, message: "WriteProcessMemory (p_arg_dll_file_path) failed.".to_string(), detail: Some(InjectErrorDetail::LastWinApiError(dwlast_error)) });
        }

        let p_get_module_handle_w_bytes = p_get_module_handle_w as usize;
        let p_get_proc_address_bytes = p_get_proc_address as usize;
        let p_arg_dll_dir_bytes = self.p_arg_dll_dir as usize;
        let p_arg_dll_file_path_bytes = self.p_arg_dll_file_path as usize;

        let afx_hook_image: Vec<u8> = [afx_hook_head, &p_get_module_handle_w_bytes.to_le_bytes(), &p_get_proc_address_bytes.to_le_bytes(), &p_arg_dll_dir_bytes.to_le_bytes(), &p_arg_dll_file_path_bytes.to_le_bytes(), afx_hook_tail].concat();

        if FALSE == unsafe{ WriteProcessMemory(self.h_proc, self.p_image_afx_hook, afx_hook_image.as_ptr() as HANDLE, afx_hook_image.len(), std::ptr::null_mut()) }{
            let dwlast_error = unsafe{ GetLastError() };
            return self.inject_end(InjectResult::Error{ line: line!(), group: InjectErrorGroup::WriteProcessMemory, message: "WriteProcessMemory (p_image_afx_hook) failed.".to_string(), detail: Some(InjectErrorDetail::LastWinApiError(dwlast_error)) });
        }
        
        if FALSE == unsafe{ FlushInstructionCache(self.h_proc, self.p_image_afx_hook,  afx_hook_image.len()) }{
            let dwlast_error = unsafe{ GetLastError() };
            return self.inject_end(InjectResult::Error{ line: line!(), group: InjectErrorGroup::FlushInstructionCache, message: "FlushInstructionCache (p_image_afx_hook) failed.".to_string(), detail: Some(InjectErrorDetail::LastWinApiError(dwlast_error)) });
        }
        
        let thread_fn: unsafe extern "system" fn(lpThreadParameter: LPVOID) -> DWORD = unsafe { std::mem::transmute(self.p_image_afx_hook) };

        self.h_thread = unsafe{ CreateRemoteThread(self.h_proc, std::ptr::null_mut(), 0, Some(thread_fn), std::ptr::null_mut(), 0, std::ptr::null_mut()) };
        if std::ptr::null() == self.h_thread {
            let dwlast_error = unsafe{ GetLastError() };
            return self.inject_end(InjectResult::Error{ line: line!(), group: InjectErrorGroup::CreateRemoteThread, message: "CreateRemoteThread failed.".to_string(), detail: Some(InjectErrorDetail::LastWinApiError(dwlast_error)) });
        }

        self.wait(wait_ms)
    }

    pub fn wait(&mut self, wait_ms: u32) -> InjectResult {
        let mut result: InjectResult = InjectResult::Ok{};

        if std::ptr::null() != self.h_thread {
            if WAIT_OBJECT_0 != unsafe{ WaitForSingleObject(self.h_thread, wait_ms) }{
                return InjectResult::Timeout{};
            }

            let mut dwexit_code: u32 = 0;
            if FALSE == unsafe{ GetExitCodeThread(self.h_thread, &mut dwexit_code) }{
                let dwlast_error = unsafe{ GetLastError() };
                result = InjectResult::Error{ line: line!(), group: InjectErrorGroup::GetExitCodeThread, message: "GetExitCodeThread failed.".to_string(), detail: Some(InjectErrorDetail::LastWinApiError(dwlast_error)) };
            } else if 0 != dwexit_code {
                result = InjectResult::Error{ line: line!(), group: InjectErrorGroup::ThreadExitError, message: "Error on exit.".to_string(), detail: Some(InjectErrorDetail::ThreadExitCode(dwexit_code))};
            } else {
                self.b_thread_terminated = true;
            }
        }

        self.inject_end(result)
    }

    pub fn inject_end(&mut self, result: InjectResult) -> InjectResult {
        if std::ptr::null() != self.h_thread {
            if !self.b_thread_terminated {
                unsafe{ TerminateThread(self.h_thread, 0xffffffff) };
            } else {
                self.b_thread_terminated = false;
            }
            unsafe{ CloseHandle(self.h_thread) };
            self.h_thread = std::ptr::null_mut();
        }

        if std::ptr::null() != self.p_image_afx_hook {
            unsafe{ VirtualFreeEx(self.h_proc, self.p_image_afx_hook, 0, MEM_RELEASE) };
            self.p_image_afx_hook = std::ptr::null_mut();
        }
        if std::ptr::null() != self.p_arg_dll_file_path {
            unsafe{ VirtualFreeEx(self.h_proc, self.p_arg_dll_file_path, 0, MEM_RELEASE) };
            self.p_arg_dll_file_path = std::ptr::null_mut();
        }
        if std::ptr::null() != self.p_arg_dll_dir {
            unsafe{ VirtualFreeEx(self.h_proc, self.p_arg_dll_dir, 0, MEM_RELEASE) };
            self.p_arg_dll_dir = std::ptr::null_mut();
        }
        if std::ptr::null() != self.h_proc {
            unsafe{ CloseHandle(self.h_proc) };
            self.h_proc = std::ptr::null_mut();
        }

        result
    }
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Process ID to inject into
    process_id: u32,

    /// File path of DLL to inject
    dll: String,

    /// Path of directory to use while injecting the DLL.
    /// When omitted the current process' directroy is not temporarily changed.
    #[arg(short, long)]
    current_directory: Option<String>,

    /// Milliseconds to wait before checking for CTRL+C.
    #[arg(short, long, default_value_t = 500)]
    wait_interval_ms: u32,
}


fn main() {
    let cli = Cli::parse();

    let process_id = cli.process_id;
    
    let dll_file_path = cli.dll;

    let mut base_directory: &str = "";
    if let Some(current_directory) = cli.current_directory.as_deref() {
        base_directory = current_directory;
    }

    let wait_ms = cli.wait_interval_ms;
    
    let mut injector = Injector::new();

    let mut result = injector.inject(process_id, &dll_file_path, base_directory, wait_ms);

    let continue_waiting = Arc::new(AtomicBool::new(true));
    let continue_waiting_clone = continue_waiting.clone();
    
    ctrlc::set_handler(move || {
        continue_waiting_clone.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    while let InjectResult::Timeout() = result {
        if continue_waiting.load(Ordering::SeqCst) {
            result = injector.wait(wait_ms);
        } else {
            result = injector.inject_end(result);
        }
    }

    let json_result = serde_json::to_string(&result).unwrap();

    println!("{}", json_result);
}
