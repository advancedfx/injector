extern crate libc;

#[macro_use]
extern crate bitflags;

bitflags! {
    #[repr(C)]
    struct AllocationType: u32
    {
        const MEM_COMMIT = 0x1000;
        const MEM_RESERVE = 0x2000;
        const MEM_DECOMMIT = 0x4000;
        const MEM_RELEASE = 0x8000;
        const MEM_RESET = 0x80000;
        const MEM_PHYSICAL = 0x400000;
        const MEM_TOP_DOWN = 0x100000;
        const MEM_WRITE_WATCH = 0x200000;
        const MEM_RESET_UNDO = 0x1000000;
        const MEM_LARGE_PAGES = 0x20000000;
    }
}

bitflags! {
    #[repr(C)]
    struct MemoryProtection: u32
    {
        const PAGE_EXECUTE = 0x10;
        const PAGE_EXECUTE_READ = 0x20;
        const PAGE_EXECUTE_READWRITE = 0x40;
        const PAGE_EXECUTE_WRITECOPY = 0x80;
        const PAGE_NOACCESS = 0x01;
        const PAGE_READONLY = 0x02;
        const PAGE_READWRITE = 0x04;
        const PAGE_WRITECOPY = 0x08;
        const PAGE_GUARD = 0x100;
        const PAGE_NOCACHE = 0x200;
        const PAGE_WRITECOMBINE = 0x400;
    }
}

bitflags! {
    #[repr(C)]
    struct ProcessAccessFlags : u32
    {
        const PROCESS_ALL_ACCESS = 0x001F0FFF;
        const PROCESS_TERMINATE  = 0x00000001;
        const PROCESS_CREATE_THREAD = 0x00000002;
        const PROCESS_VM_OPERATION = 0x00000008;
        const PROCESS_VM_READ  = 0x00000010;
        const PROCESS_VM_WRITE  = 0x00000020;
        const PROCESS_DUP_HANDLE  = 0x00000040;
        const PROCESS_CREATE_PROCESS = 0x000000080;
        const PROCESS_SET_QUOTA = 0x00000100;
        const PROCESS_SET_INFORMATION = 0x00000200;
        const PROCESS_QUERY_INFORMATION = 0x00000400;
        const PROCESS_SUSPEND_RESUME = 0x00000800;
        const PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000;
        const SYNCHRONIZE = 0x00100000;

        const CREATE_THREAD_ACCESS = Self::PROCESS_CREATE_THREAD.bits | Self::PROCESS_QUERY_INFORMATION.bits | Self::PROCESS_VM_OPERATION.bits | Self::PROCESS_VM_WRITE.bits | Self::PROCESS_VM_READ.bits;
    }
}

const WAIT_OBJECT_0: u32 = 0;

#[link(name="Kernel32")]
extern "system" {
    fn GetLastError() -> u32;
    fn GetModuleHandleW(lpModuleName: *const libc::wchar_t) -> *const libc::c_void;
    fn GetProcAddress(hModule: *const libc::c_void, lpProcName: *const i8) -> *const libc::c_void;
    fn VirtualAllocEx(h_process: *const libc::c_void, lpAddress: *const libc::c_void, dwSize: usize, flAllocationType: AllocationType, flProtect: MemoryProtection) -> *mut libc::c_void;
    fn OpenProcess(dwDesiredAccess: ProcessAccessFlags, bInheritHandle: bool, dwProcessId: u32) -> *const libc::c_void;
    fn VirtualFreeEx(h_process: *const libc::c_void, lpAddress: *const libc::c_void, dwSize: usize, dwFreeType: AllocationType) -> bool;
    fn WriteProcessMemory(h_process: *const libc::c_void, lpBaseAddress: *const libc::c_void, lpBuffer: *const libc::c_void, nSize: usize, lpNumberOfBytesWritten: *mut usize) -> bool;
    fn FlushInstructionCache(h_process: *const libc::c_void, lpBaseAddress: *const libc::c_void, dwSize: usize) -> bool;
    fn CreateRemoteThread(h_process: *const libc::c_void, lpThreadAttributes: *const libc::c_void, dwStackSize: usize, lpStartAddress: *const libc::c_void, lpParameter: *const libc::c_void, dwCreationFlags: u32, lpThreadId: *mut libc::c_void) -> *mut libc::c_void;
    fn WaitForSingleObject(hHandle: *const libc::c_void, dwMilliseconds: u32) -> u32;
    fn GetExitCodeThread(h_thread: *const libc::c_void, lpexit_code: *mut u32) -> bool;
    fn TerminateThread(h_thread: *const libc::c_void, dwexit_code: u32) -> bool;
    fn CloseHandle(hObject: *const libc::c_void) -> bool;
}

use serde::{Deserialize, Serialize};

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
    h_proc: *const libc::c_void,
    p_arg_dll_dir: *const libc::c_void,
    p_arg_dll_file_path: *const libc::c_void,
    p_image_afx_hook: *const libc::c_void,
    h_thread: *mut libc::c_void,
    b_thread_terminated: bool
}

unsafe impl Send for Injector {}
unsafe impl Sync for Injector {}

use std::os::windows::ffi::OsStrExt;
use std::ffi::CString;

const NULL: *const libc::c_void = std::ptr::null();
const NULL_MUT: *mut libc::c_void = std::ptr::null_mut();

impl Injector {
    pub fn new() -> Self {
        Self {
            h_proc: NULL,
            p_arg_dll_dir: NULL,
            p_arg_dll_file_path: NULL,
            p_image_afx_hook: NULL,
            h_thread: NULL_MUT,
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
        if NULL == h_kernel32_dll {
            return InjectResult::Error{ line: line!(), group: InjectErrorGroup::GetModuleHandleW, message: "Could not get Kernel32.dll handle.".to_string(), detail: None };
        }

        let sz_get_module_handle_w = CString::new("GetModuleHandleW").unwrap();
        let p_get_module_handle_w = unsafe{ GetProcAddress(h_kernel32_dll, sz_get_module_handle_w.as_ptr()) };
        if NULL == p_get_module_handle_w {
            return InjectResult::Error{ line: line!(), group: InjectErrorGroup::GetProcAddress, message: "Could not get Kernel32.dll!GetModuleHandleW address.".to_string(), detail: None };
        }

        let sz_get_proc_address = CString::new("GetProcAddress").unwrap();
        let p_get_proc_address = unsafe{ GetProcAddress(h_kernel32_dll, sz_get_proc_address.as_ptr()) };
        if NULL == p_get_proc_address {
            return InjectResult::Error{ line: line!(), group: InjectErrorGroup::GetProcAddress, message: "Could not get Kernel32.dll!GetProcAddress address.".to_string(), detail: None};
        }

        //

        self.h_proc = unsafe{ OpenProcess(ProcessAccessFlags::CREATE_THREAD_ACCESS, false, process_id) };
        if NULL == self.h_proc {
            let dwlast_error = unsafe{ GetLastError() };
            return InjectResult::Error{ line: line!(), group: InjectErrorGroup::OpenProcess, message: "OpenProcess failed.".to_string(), detail: Some(InjectErrorDetail::LastWinApiError(dwlast_error)) };
        }

        self.p_arg_dll_dir = unsafe{ VirtualAllocEx(self.h_proc, NULL, cb_base_directory_size, AllocationType::MEM_COMMIT | AllocationType::MEM_RESERVE, MemoryProtection::PAGE_READWRITE) };
        if NULL == self.p_arg_dll_dir {
            let dwlast_error = unsafe{ GetLastError() };
            return self.inject_end(InjectResult::Error{ line: line!(), group: InjectErrorGroup::VirtualAllocEx, message: "VirtualAllocEx (p_arg_dll_dir) failed.".to_string(), detail: Some(InjectErrorDetail::LastWinApiError(dwlast_error)) });
        }

        self.p_arg_dll_file_path = unsafe{ VirtualAllocEx(self.h_proc, NULL, cb_dll_file_path_size, AllocationType::MEM_COMMIT | AllocationType::MEM_RESERVE, MemoryProtection::PAGE_READWRITE) };
        if NULL == self.p_arg_dll_file_path {
            let dwlast_error = unsafe{ GetLastError() };
            return self.inject_end(InjectResult::Error{ line: line!(), group: InjectErrorGroup::VirtualAllocEx, message: "VirtualAllocEx (p_arg_dll_file_path) failed.".to_string(), detail: Some(InjectErrorDetail::LastWinApiError(dwlast_error)) });
        }

        self.p_image_afx_hook = unsafe{ VirtualAllocEx(self.h_proc, NULL, AFX_HOOK_DAT_SIZE, AllocationType::MEM_COMMIT | AllocationType::MEM_RESERVE, MemoryProtection::PAGE_EXECUTE_READWRITE) };
        if NULL == self.p_image_afx_hook {
            let dwlast_error = unsafe{ GetLastError() };
            return self.inject_end(InjectResult::Error{ line: line!(), group: InjectErrorGroup::VirtualAllocEx, message: "VirtualAllocEx (p_image_afx_hook) failed.".to_string(), detail: Some(InjectErrorDetail::LastWinApiError(dwlast_error)) });
        }
        
        if !unsafe{ WriteProcessMemory(self.h_proc, self.p_arg_dll_dir, wsz_base_directory.as_ptr() as *const libc::c_void, cb_base_directory_size, NULL_MUT as *mut usize) }{
            let dwlast_error = unsafe{ GetLastError() };
            return self.inject_end(InjectResult::Error{ line: line!(), group: InjectErrorGroup::WriteProcessMemory, message: "WriteProcessMemory (p_arg_dll_dir) failed.".to_string(), detail: Some(InjectErrorDetail::LastWinApiError(dwlast_error)) });
        }
        
        if !unsafe{ WriteProcessMemory(self.h_proc, self.p_arg_dll_file_path, wsz_dll_file_path.as_ptr() as *const libc::c_void, cb_dll_file_path_size, NULL_MUT as *mut usize) }{
            let dwlast_error = unsafe{ GetLastError() };
            return self.inject_end(InjectResult::Error{ line: line!(), group: InjectErrorGroup::WriteProcessMemory, message: "WriteProcessMemory (p_arg_dll_file_path) failed.".to_string(), detail: Some(InjectErrorDetail::LastWinApiError(dwlast_error)) });
        }

        let p_get_module_handle_w_bytes = p_get_module_handle_w as usize;
        let p_get_proc_address_bytes = p_get_proc_address as usize;
        let p_arg_dll_dir_bytes = self.p_arg_dll_dir as usize;
        let p_arg_dll_file_path_bytes = self.p_arg_dll_file_path as usize;

        let afx_hook_image: Vec<u8> = [afx_hook_head, &p_get_module_handle_w_bytes.to_le_bytes(), &p_get_proc_address_bytes.to_le_bytes(), &p_arg_dll_dir_bytes.to_le_bytes(), &p_arg_dll_file_path_bytes.to_le_bytes(), afx_hook_tail].concat();

        if !unsafe{ WriteProcessMemory(self.h_proc, self.p_image_afx_hook, afx_hook_image.as_ptr() as *const libc::c_void, afx_hook_image.len(), NULL_MUT as *mut usize) }{
            let dwlast_error = unsafe{ GetLastError() };
            return self.inject_end(InjectResult::Error{ line: line!(), group: InjectErrorGroup::WriteProcessMemory, message: "WriteProcessMemory (p_image_afx_hook) failed.".to_string(), detail: Some(InjectErrorDetail::LastWinApiError(dwlast_error)) });
        }
        
        if !unsafe{ FlushInstructionCache(self.h_proc, self.p_image_afx_hook,  afx_hook_image.len()) }{
            let dwlast_error = unsafe{ GetLastError() };
            return self.inject_end(InjectResult::Error{ line: line!(), group: InjectErrorGroup::FlushInstructionCache, message: "FlushInstructionCache (p_image_afx_hook) failed.".to_string(), detail: Some(InjectErrorDetail::LastWinApiError(dwlast_error)) });
        }
        
        self.h_thread = unsafe{ CreateRemoteThread(self.h_proc, NULL, 0, self.p_image_afx_hook, NULL, 0, NULL_MUT) };
        if NULL == self.h_thread {
            let dwlast_error = unsafe{ GetLastError() };
            return self.inject_end(InjectResult::Error{ line: line!(), group: InjectErrorGroup::CreateRemoteThread, message: "CreateRemoteThread failed.".to_string(), detail: Some(InjectErrorDetail::LastWinApiError(dwlast_error)) });
        }

        self.wait(wait_ms)
    }

    pub fn wait(&mut self, wait_ms: u32) -> InjectResult {
        let mut result: InjectResult = InjectResult::Ok{};

        if NULL != self.h_thread {
            if WAIT_OBJECT_0 != unsafe{ WaitForSingleObject(self.h_thread, wait_ms) }{
                return InjectResult::Timeout{};
            }

            let mut dwexit_code: u32 = 0;
            if !unsafe{ GetExitCodeThread(self.h_thread, &mut dwexit_code) }{
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
        if NULL != self.h_thread {
            if !self.b_thread_terminated {
                unsafe{ TerminateThread(self.h_thread, 0xffffffff) };
            } else {
                self.b_thread_terminated = false;
            }
            unsafe{ CloseHandle(self.h_thread) };
            self.h_thread = NULL_MUT;
        }

        if NULL != self.p_image_afx_hook {
            unsafe{ VirtualFreeEx(self.h_proc, self.p_image_afx_hook, 0, AllocationType::MEM_RELEASE) };
            self.p_image_afx_hook = NULL;
        }
        if NULL != self.p_arg_dll_file_path {
            unsafe{ VirtualFreeEx(self.h_proc, self.p_arg_dll_file_path, 0, AllocationType::MEM_RELEASE) };
            self.p_arg_dll_file_path = NULL;
        }
        if NULL != self.p_arg_dll_dir {
            unsafe{ VirtualFreeEx(self.h_proc, self.p_arg_dll_dir, 0, AllocationType::MEM_RELEASE) };
            self.p_arg_dll_dir = NULL;
        }
        if NULL != self.h_proc {
            unsafe{ CloseHandle(self.h_proc) };
            self.h_proc = NULL;
        }

        result
    }
}

use clap::Parser;

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

    /// Number of times to greet
    #[arg(short, long, default_value_t = 500)]
    wait_interval_ms: u32,
}

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

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
