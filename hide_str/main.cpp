#include <windows.h>

#include "hide_str.hpp"

int main()
{
	using namespace hide_string;
	// Demo
	// It is simple like a magic
	MessageBoxA(nullptr, reinterpret_cast<LPCSTR>(hide_str("Привет мир")),
	            reinterpret_cast<LPCSTR>(hide_str("Hide String2")), MB_OK);
	// test for no hide strings
	MessageBoxA(nullptr, "NO Hide String1", "NO Hide String2", MB_OK);
}
