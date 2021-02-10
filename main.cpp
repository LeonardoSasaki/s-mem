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
	std::wcout << std::hex << mem->pattern_scan(mem->get_module(L"notepad.exe"), "\x76\x02\xB0\x01\x88\x43\x39\x66\x44\x39\x3F", "xxxxxxxxxxx");

	return 0;
}
