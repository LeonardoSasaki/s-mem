#include <Windows.h>
#include <TlHelp32.h>

typedef struct _proc_info {
	PROCESSENTRY32	pentry32;
	HANDLE		handle;
	DWORD		pid;
	bool		process_found;
};

class process {
private:
	_proc_info proc_info;
public:
	_proc_info get_proc_info();

	process(LPCTSTR proc_name, DWORD access = PROCESS_ALL_ACCESS, bool inherit = false);
	process(DWORD pid, DWORD access = PROCESS_ALL_ACCESS, bool inherit = false);
	process(HWND window, DWORD access = PROCESS_ALL_ACCESS, bool inherit = false);
	process(HANDLE handle, DWORD pid = 0);
	~process();
	
	bool update_process(LPCTSTR proc_name, DWORD access = PROCESS_ALL_ACCESS, bool inherit = false);
	bool update_process(DWORD pid, DWORD access = PROCESS_ALL_ACCESS, bool inherit = false);
	bool update_process(HWND window, DWORD access = PROCESS_ALL_ACCESS, bool inherit = false);
	bool update_process(HANDLE handle, DWORD pid = 0);
	bool success();
	
	template<typename T> bool write_mem(LPVOID address, T val, size_t size = sizeof(T)) {
		return WriteProcessMemory(proc_info.handle, address, &val, size, nullptr);
	}

	template<typename T> T read_mem(LPCVOID address, size_t size = sizeof(T)) {
		T val;
		ReadProcessMemory(proc_info.handle, address, &val, size, nullptr);
		return val;
	}

	MODULEENTRY32 get_module(LPCTSTR module_name);

	BOOL mem_protect(uintptr_t address, size_t size, DWORD protection, PDWORD old_prot);
	size_t mem_query(uintptr_t address, PMEMORY_BASIC_INFORMATION pmbi, size_t len = 0);
	LPVOID mem_alloc(uintptr_t address, size_t size = 0, DWORD allocation_type = MEM_COMMIT, DWORD protection = PAGE_EXECUTE_READWRITE);
	BOOL mem_dealloc(uintptr_t address, size_t size = 0, DWORD free_type = MEM_DECOMMIT);

	uintptr_t pattern_scan(MODULEENTRY32 module_entry, const char* sig, const char* mask);
};
