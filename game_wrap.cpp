#include <windows.h>
#include <psapi.h>

#define EXTERNC extern "C"
#define NAKED __declspec(naked)
#define EXPORT __declspec(dllexport)

static HMODULE gmDll = NULL;
static FARPROC gmExps[3] = {NULL, NULL, NULL};

static uintptr_t g_base = 0;
static size_t    g_size = 0;

bool Wrap_Initialize(HMODULE module) {
	MODULEINFO info;
	if (!GetModuleInformation(GetCurrentProcess(), module, &info, sizeof(MODULEINFO)))
		return false;
	
	g_base = (uintptr_t)info.lpBaseOfDll;
	g_size = (size_t)info.SizeOfImage;
	return true;
}

uintptr_t Wrap_Find(const char* pattern, const char* mask, int offset) {
	BYTE first = pattern[0];
	int patternLength = strlen(mask);
	bool found = false;

	//For each byte from start to end
	for (uintptr_t i = g_base; i < g_base + g_size - patternLength; i++) {
		if (*(BYTE*)i != first) {
			continue;
		}
		found = true;
		//For each byte in the pattern
		for (int idx = 0; idx < patternLength; idx++) {

			if (mask[idx] == 'x' && pattern[idx] != *(char*)(i + idx)) {
				found = false;
				break;
			}
		}
		if (found) {
			return i + offset;
		}
	}
	return NULL;
}

void Wrap_Patch(HMODULE module)
{
	if ( Wrap_Initialize(module) )
	{
		uintptr_t addr = Wrap_Find("\x69\xC9\x98\x24\x01\x00", "xxxxxx", 0x2B);
		if (addr != NULL)
		{
			BYTE *a = (BYTE *)addr;
			if (a[0] != 0x83 || a[1] != 0xFF || a[2] != 01)
				MessageBox(NULL, "Can't apply patch #1.", "Wrapper", MB_OK | MB_ICONERROR);
			else
			{
				DWORD dwProtect = PAGE_EXECUTE_READWRITE;
				VirtualProtect(a, 2, dwProtect, &dwProtect);
				a[0] = 0xEB;
				a[1] = 0xCE;
				VirtualProtect(a, 2, dwProtect, &dwProtect);
			}
		}
		else
		{
			MessageBox(NULL, "Can't find patch #1 place.", "Wrapper", MB_OK | MB_ICONERROR);
		}
		
		addr = Wrap_Find("\x8B\x01\x83\x38\x01\x75\x05", "xxxxxxx", 0x29);
		if (addr != NULL)
		{
			BYTE *a = (BYTE *)addr;
			if (a[0] != 0x50 || a[1] != 0xE8)
				MessageBox(NULL, "Can't apply patch #2.", "Wrapper", MB_OK | MB_ICONERROR);
			else
			{
				DWORD dwProtect = PAGE_EXECUTE_READWRITE;
				VirtualProtect(a, 2, dwProtect, &dwProtect);
				a[0] = 0xEB;
				a[1] = 0x12;
				VirtualProtect(a, 2, dwProtect, &dwProtect);
			}
		}
		else
		{
			MessageBox(NULL, "Can't find patch #2 place.", "Wrapper", MB_OK | MB_ICONERROR);
		}
		
		
	}
	else
	{
		MessageBox(NULL, "Can't get info about game.dll_orig", "Wrapper", MB_OK | MB_ICONERROR);
	}
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, PVOID pvReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		gmDll = LoadLibraryA("game.dll_orig");
		if (gmDll)
		{
			gmExps[0] = GetProcAddress(gmDll, "??4_Init_locks@std@@QAEAAV01@ABV01@@Z");
			gmExps[1] = GetProcAddress(gmDll, "CreateGameInstance");
			gmExps[2] = GetProcAddress(gmDll, "CryModuleGetMemoryInfo");
			
			Wrap_Patch(gmDll);
		}
		else
		{
			MessageBox(NULL, "Can't load game.dll_orig", "Wrapper", MB_OK | MB_ICONERROR);
			return false;		
		}
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{
		FreeLibrary(gmDll);
	}

	return true;
}

EXTERNC NAKED void __cdecl Wrap_Init_locks(void)
{
	__asm__(".intel_syntax noprefix \n"
		    "jmp dword ptr [%0]"
			:
			: "rm" (gmExps[0])
			);
}

EXTERNC NAKED void __cdecl Wrap_CreateGameInstance(void)
{
	__asm__(".intel_syntax noprefix \n"
		    "jmp dword ptr [%0]"
			:
			: "rm" (gmExps[1])
			);
}

EXTERNC NAKED void __cdecl Wrap_CryModuleGetMemoryInfo(void)
{
	__asm__(".intel_syntax noprefix \n"
		    "jmp dword ptr [%0]"
			:
			: "rm" (gmExps[2])
			);
}
