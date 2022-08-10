#include <iostream>
#include <fstream> 
#include <string>
#include <filesystem>

#include <stdlib.h>

#include <tchar.h>
#include <Windows.h>

extern size_t _binary_AfxHook_dat_size;
extern char _binary_AfxHook_dat_start[];
extern char _binary_AfxHook_dat_end[];

class WinApiException : public std::runtime_error
{
    DWORD m_dwLastError;

public:
    WinApiException(const char * msg)
        : std::runtime_error(msg)
        , m_dwLastError(GetLastError())
    {

    }

    DWORD get_last_error() const {
        return m_dwLastError;
    }
};

class ExitErrorException : public std::runtime_error
{
    DWORD m_dwExitCode;

public:
    ExitErrorException(const char * msg, DWORD dwExitCode)
        : std::runtime_error(msg)
        , m_dwExitCode(dwExitCode)
    {

    }

    DWORD get_exit_code() const {
        return m_dwExitCode;
    }
};

int _tmain (int argc, TCHAR *argv[]) {

    try
    {
        if(argc < 3)
            throw std::runtime_error("Not enough arguments.");

        HMODULE hKernel32Dll = GetModuleHandle(_T("Kernel32.dll"));
        if(NULL == hKernel32Dll)
            throw std::runtime_error("Could not get Kernel32.dll handle.");

        FARPROC pGetModuleHandleW = GetProcAddress(hKernel32Dll, "GetModuleHandleW");
            throw std::runtime_error("Could not get Kernel32.dll!GetModuleHandleW address.");

        FARPROC pGetProcAddress = GetProcAddress(hKernel32Dll, "GetProcAddress");
            throw std::runtime_error("Could not get Kernel32.dll!GetProcAddress address.");

        DWORD dwProcessId = _tcstoul(argv[1], NULL, 0);

        std::filesystem::path dllPath(argv[2]);

        std::wstring strBaseDirectory(dllPath.parent_path());
        std::wstring strDllFilePath(argv[2]);

        size_t argBaseDirectorySize =  sizeof(wchar_t) * (strBaseDirectory.length() + 1);
        size_t argDllFilePathSize =  sizeof(wchar_t) * (strDllFilePath.length() + 1);

        HANDLE hProc = NULL;
        HANDLE hThread = NULL;
        LPTHREAD_START_ROUTINE pImageAfxHook = NULL;
        LPVOID pArgDllDir = NULL;
        LPVOID pArgDllFilePath = NULL;

        std::exception_ptr eptr;

        bool bThreadTerminated = false;

        try {
            if(NULL == (hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, dwProcessId)))
                throw WinApiException("OpenProcess failed.");

            if(NULL == (pArgDllDir = VirtualAllocEx(hProc, NULL, argBaseDirectorySize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
                throw WinApiException("VirtualAllocEx (pArgDllDir) failed.");

            if(NULL == (pArgDllFilePath = VirtualAllocEx(hProc, NULL, argDllFilePathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
                throw WinApiException("VirtualAllocEx (pArgDllFilePath) failed.");

            if(NULL == (pImageAfxHook = (LPTHREAD_START_ROUTINE)VirtualAllocEx(hProc, NULL, _binary_AfxHook_dat_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
                throw WinApiException("VirtualAllocEx (pImageAfxHook) failed.");

            if(!WriteProcessMemory(hProc, pArgDllDir, strBaseDirectory.c_str(), argBaseDirectorySize, NULL))
                throw WinApiException("WriteProcessMemory (pArgDllDir) failed.");

            if(!WriteProcessMemory(hProc, pArgDllFilePath, strDllFilePath.c_str(), argDllFilePathSize, NULL))
                throw WinApiException("WriteProcessMemory (pArgDllFilePath) failed.");

            memcpy(_binary_AfxHook_dat_start + 32 + 0 * sizeof(void *), &pGetModuleHandleW, sizeof(pGetModuleHandleW));
            memcpy(_binary_AfxHook_dat_start + 32 + 1 * sizeof(void *), &pGetProcAddress, sizeof(pGetProcAddress));
            memcpy(_binary_AfxHook_dat_start + 32 + 2 * sizeof(void *), &pArgDllDir, sizeof(pArgDllDir));
            memcpy(_binary_AfxHook_dat_start + 32 + 3 * sizeof(void *), &pArgDllFilePath, sizeof(pArgDllFilePath));

            if(!WriteProcessMemory(hProc, (LPVOID)pImageAfxHook, &_binary_AfxHook_dat_start[0], _binary_AfxHook_dat_size, NULL))
                throw WinApiException("WriteProcessMemory (pImageAfxHook) failed.");

            if(!FlushInstructionCache(hProc, (LPVOID)pImageAfxHook, _binary_AfxHook_dat_size))
                throw WinApiException("FlushInstructionCache (pImageAfxHook) failed.");

            if(NULL == (hThread = CreateRemoteThread(hProc, NULL, 0, pImageAfxHook, NULL, 0, NULL)))
                throw WinApiException("CreateRemoteThread failed.");
    
            bool bWait;

            do
            {
                bWait = false;

                for (int i = 0; i < 60; i++)
                {
                    if (WAIT_OBJECT_0 == WaitForSingleObject(hThread, 1000))
                    {
                        bThreadTerminated = true;
                        break;
                    }
                }

                if (!bThreadTerminated)
                {
                    std::cout << "Continue waiting?: ";
                    std::cin >> bWait;
                }

            } while (bWait);

            if(bThreadTerminated)
            {
                DWORD dwExitCode;
                if(!GetExitCodeThread(hThread, &dwExitCode))
                    throw WinApiException("GetExitCodeThread");

                if (0 != dwExitCode)
                    throw ExitErrorException("Error on exit", dwExitCode);
            }
        }
        catch(...) {
            eptr = std::current_exception();
        }

        if(hThread) {
            if(!bThreadTerminated) TerminateThread(hThread, -1);
            CloseHandle(hThread);
        }
        if(pImageAfxHook) VirtualFreeEx(hProc, (LPVOID)pImageAfxHook, 0, MEM_RELEASE);
        if(pArgDllFilePath) VirtualFreeEx(hProc, pArgDllFilePath, 0, MEM_RELEASE);
        if(pArgDllDir) VirtualFreeEx(hProc, pArgDllDir, 0, MEM_RELEASE);
        if(hProc) CloseHandle(hProc);

        if (eptr) {
            std::rethrow_exception(eptr);
        }        
    }
    catch(const ExitErrorException& e) {
        std::cerr << "Exit error exception: Exit code: " << e.get_exit_code() << " Exception: " << e.what() << '\n';
        return EXIT_FAILURE;
    }
    catch(const WinApiException& e) {
        std::cerr << "Windows API exception: GetLastError: " << e.get_last_error() << " Exception: " << e.what() << '\n';
        return EXIT_FAILURE;
    }
    catch(const std::exception& e) {
        std::cerr << "Exception: " << e.what() << '\n';
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}
