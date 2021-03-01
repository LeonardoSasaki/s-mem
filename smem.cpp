#include <TCHAR.h>
#include "smem.h"

process::process(LPCTSTR proc_name, DWORD access, bool inherit) {
    this->proc_info.handle = NULL;
    this->proc_info.process_found = false;
    update_process(proc_name, access, false);
}

process::process(DWORD pid, DWORD access, bool inherit) {
    this->proc_info.handle = NULL;
    this->proc_info.process_found = false;
    update_process(pid, access, inherit);
}

process::process(HWND window, DWORD access, bool inherit) {
    this->proc_info.handle = NULL;
    this->proc_info.process_found = false;
    update_process(window, access, inherit);
}

process::process(HANDLE handle, DWORD pid) {
    this->proc_info.handle = NULL;
    this->proc_info.process_found = false;
    update_process(handle, pid);
}

process::~process() {
    if (this->proc_info.handle != INVALID_HANDLE_VALUE && this->proc_info.handle != NULL)
        CloseHandle(this->proc_info.handle);
}

bool process::update_process(LPCTSTR proc_name, DWORD access, bool inherit) {
    if (this->proc_info.handle != INVALID_HANDLE_VALUE && this->proc_info.handle != NULL)
        CloseHandle(this->proc_info.handle);

    this->proc_info.pentry32.dwSize = sizeof(PROCESSENTRY32);
    HANDLE tl_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(tl_snapshot, &this->proc_info.pentry32)) {
        while(true){
            if (Process32Next(tl_snapshot, &this->proc_info.pentry32)){
                if (!_tcscmp(this->proc_info.pentry32.szExeFile, proc_name))
                    break;
            }
            else return this->proc_info.process_found = false;
        }
    }

    CloseHandle(tl_snapshot);

    this->proc_info.pid = this->proc_info.pentry32.th32ProcessID;
    this->proc_info.handle = OpenProcess(access, inherit, this->proc_info.pid);

    if (this->proc_info.handle == INVALID_HANDLE_VALUE)
        return this->proc_info.process_found = false;

    return this->proc_info.process_found = true;
}

bool process::update_process(DWORD pid, DWORD access, bool inherit) {
    if (this->proc_info.handle != INVALID_HANDLE_VALUE && this->proc_info.handle != NULL)
        CloseHandle(this->proc_info.handle);

    this->proc_info.handle = OpenProcess(access, inherit, pid);

    if (this->proc_info.handle == INVALID_HANDLE_VALUE)
        return this->proc_info.process_found = false;

    return this->proc_info.process_found = true;
}

bool process::update_process(HWND window, DWORD access, bool inherit) {
    if (window != INVALID_HANDLE_VALUE && window != NULL)
        CloseHandle(this->proc_info.handle);

    GetWindowThreadProcessId(window, &this->proc_info.pid);
    
    if(this->proc_info.pid == 0)
        return this->proc_info.process_found = false;
    
    this->proc_info.handle = OpenProcess(access, inherit, this->proc_info.pid);

    if(this->proc_info.handle == INVALID_HANDLE_VALUE  || this->proc_info.handle == NULL)
        return this->proc_info.process_found = false;
    
    return this->proc_info.process_found = true;                    
}

bool process::update_process(HANDLE handle, DWORD pid) {
    if (this->proc_info.handle != INVALID_HANDLE_VALUE && this->proc_info.handle != NULL)
        CloseHandle(this->proc_info.handle);

    this->proc_info.handle = handle;
    this->proc_info.pid = pid == 0 ? GetProcessId(handle) : pid;    // pid param defaults to 0

    return this->proc_info.process_found = true;                    // assumes the user passed a valid handle
}

_proc_info process::get_proc_info() {
    return this->proc_info;
}

_proc_info process::get_proc_info() {
    return this->proc_info;
}

bool process::success() {
    return this->proc_info.process_found;
}

MODULEENTRY32 process::get_module(LPCTSTR module_name) {
    MODULEENTRY32 mentry32;
    mentry32.dwSize = sizeof(MODULEENTRY32);
    HANDLE tl_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, proc_info.pid);

    if (Module32First(tl_snapshot, &mentry32)) {
        while(true){
            if(Module32Next(tl_snapshot, &mentry32)){
                if (!_tcscmp(mentry32.szModule, module_name))
                    break;
            }
            else{                                            // if module list ended && module wasn't found,
                memset(&mentry32, 0, sizeof(MODULEENTRY32)); // then zero all structure
                break;
            }
        }
    }

    CloseHandle(tl_snapshot); 

    return mentry32;
}

BOOL process::mem_protect(uintptr_t address, size_t size, DWORD protection, PDWORD old_prot) {
    return VirtualProtectEx(this->proc_info.handle, reinterpret_cast<LPVOID>(address), size, protection, old_prot);
}

size_t process::mem_query(uintptr_t address, PMEMORY_BASIC_INFORMATION pmbi, size_t len) {
    return VirtualQueryEx(this->proc_info.handle, reinterpret_cast<LPCVOID>(address), pmbi, len);
}

LPVOID process::mem_alloc(uintptr_t address, size_t size, DWORD protection, DWORD allocation_type) {
    return VirtualAllocEx(this->proc_info.handle, reinterpret_cast<LPVOID>(address), size, protection, allocation_type);
}

BOOL process::mem_dealloc(uintptr_t address, size_t size, DWORD free_type) {
    return VirtualFreeEx(this->proc_info.handle, reinterpret_cast<LPVOID>(address), size, free_type);
}

uintptr_t process::pattern_scan(MODULEENTRY32 module_entry, const char* sig, const char* mask)
{
    if (module_entry.modBaseAddr == 0)  // get_module returns a empty struct on failure, this check prevents a seg fault
        return 0;                       // this could happen for example when the module wasn't loaded yet

    uintptr_t return_val = 0, sig_len = strlen(sig), mask_len = strlen(mask);
    auto block = reinterpret_cast<char*>(malloc(module_entry.modBaseSize));

    if (block == NULL )                 // if malloc fails
        return 0;

    ReadProcessMemory(this->proc_info.handle, module_entry.modBaseAddr, block, module_entry.modBaseSize, nullptr);

    if (mask_len >= sig_len) {          // no point otherwise, this could cause problems
        for (DWORD i = 0; i < module_entry.modBaseSize - sig_len && return_val == 0; i++)
        {
            bool found = true;
            for (DWORD j = 0; found && mask[j]; j++)
                found = !(mask[j] != '?' && *reinterpret_cast<char*>(block + i + j) != sig[j]);

            if (found)
                return_val = reinterpret_cast<uintptr_t>(module_entry.modBaseAddr + i);
        }
    }

    free(block);
    return return_val;
}
