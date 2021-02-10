#include <iostream>
#include <memory.h>
#include "smem.h"

int wmain(int argc, wchar_t* argv[]) {
	auto mem = std::make_shared<process>(L"notepad.exe");

	while (!mem->success()) // checks whether the process was found or not
	{
		Sleep(1);
		mem->update_process(L"notepad.exe");
	}

	// this is just a pattern scan to a random existing sig just as a example
	std::wcout << mem->pattern_scan(mem->get_module(L"KERNEL32.DLL"), "\x85\xC0\x74\x38\x48\x8B\x4E\x38", "xxxxxxxx");

	return 0;
}