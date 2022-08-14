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
    }
}

const CREATE_THREAD_ACCESS : u32 = ProcessAccessFlags::PROCESS_CREATE_THREAD.bits | ProcessAccessFlags::PROCESS_QUERY_INFORMATION.bits | ProcessAccessFlags::PROCESS_VM_OPERATION.bits | ProcessAccessFlags::PROCESS_VM_WRITE.bits | ProcessAccessFlags::PROCESS_VM_READ.bits;

#[link(name="Kernel32")]
extern "system"{
    fn Kernel32_VirtualAllocEx(hProcess: *mut libc::c_void, lpAddress: *mut libc::c_void, dwSize: usize, flAllocationType: AllocationType, flProtect: MemoryProtection) -> *mut libc::c_void;
    fn Kernel32_OpenProcess(dwDesiredAccess: ProcessAccessFlags, bInheritHandle: bool, dwProcessId: u32) -> *mut libc::c_void;
    fn Kernel32_VirtualFreeEx(hProcess: *mut libc::c_void, lpAddress: *mut libc::c_void, dwSize: usize, dwFreeType: AllocationType) -> bool;
    fn Kernel32_WriteProcessMemory(hProcess: *mut libc::c_void, lpBaseAddress: *mut libc::c_void, lpBuffer: *const libc::c_void, nSize: usize, lpNumberOfBytesWritten: *mut usize) -> bool;
}

use jsonrpc_core::Result;
use jsonrpc_derive::rpc;

#[rpc]
pub trait Rpc {
	/// Adds two numbers and returns a result
	#[rpc(name = "add")]
	fn add(&self, a: u64, b: u64) -> Result<u64>;
}

pub struct RpcImpl;

impl Rpc for RpcImpl {

	fn add(&self, a: u64, b: u64) -> Result<u64> {
		Ok(a + b)
	}
}

#[macro_use]
extern crate tokio;

use jsonrpc_stdio_server::ServerBuilder;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut afx_hook_dat = include_bytes!("AfxHook.dat");

	let mut io = jsonrpc_core::IoHandler::new();
	io.extend_with(RpcImpl.to_delegate());

	let server = jsonrpc_stdio_server::ServerBuilder::new(io).build();
	server.await;
}
