
#include "stdafx.h"
#include "BasicChecks.h"

struct Result_Str {
	std::wstring DLL_name;
	LPVOID Base;
	std::wstring SAFE_SEH;
	std::wstring ASLR;
	std::wstring DEP;
};
Result_Str Result2[MAX_PATH];

unsigned int max_lenght = 0;
int sz = 0;

BOOL EnableTokenPrivilege(LPCTSTR Debug_Pr, HANDLE Curr_Proc_Address) {

	HANDLE Token = 0;
	TOKEN_PRIVILEGES token_priv = { 0 };
	if (!OpenProcessToken(Curr_Proc_Address, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token))
		return FALSE;
	if (LookupPrivilegeValue(NULL, Debug_Pr, &token_priv.Privileges[0].Luid)) {
		token_priv.PrivilegeCount = 1;
		token_priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		AdjustTokenPrivileges(Token, FALSE, &token_priv, 0, PTOKEN_PRIVILEGES(NULL), (PDWORD)NULL);
		if (GetLastError() != NULL)
			return FALSE;
		return TRUE;
	}
	return FALSE;
}

wstring check_SEH(LPVOID Base,LPVOID optional_header) {
	//cout << "Came Here" << endl;
	// Change Memory pointer data type from byte to other if we want operation on WORD,DWORD etc..
	
	
		if (*(WORD*)optional_header == 0x010B) {
			LPVOID dll_characteristics = (BYTE *)optional_header + 0x46;
			if (*(WORD*)dll_characteristics & 0x0400 == 0x0400) {
				return L"NO SEH";
			}
			LPVOID Load_Configuration_Table = (BYTE *)optional_header + 0xB0;
			if (*(DWORD*)Load_Configuration_Table == 0x00) return L"NO SEH";
			else {
				LPVOID load_config_directory= (BYTE*)Base + *(DWORD*)Load_Configuration_Table;
				LPVOID SEH_Table = (BYTE*)load_config_directory + 0x40;
				if (*(DWORD*)SEH_Table == 0x00) return L"OFF";
			}
		}
	
	return L"ON";
}

wstring check_ASLR(LPVOID optional_header) {
	LPVOID dll_characteristics = (BYTE *)optional_header + 0x46;
	if ((*(WORD *)dll_characteristics & 0x0040) == 0x0040) 	return L"True";
	return L"False";
}

wstring check_DEP(LPVOID optional_header) {
	LPVOID dll_characteristics = (BYTE *)optional_header + 0x46;
	if ((*(WORD *)dll_characteristics & 0x0100) == 0x0100) 	return L"True";
	return L"False";
}

BOOL GetProcessModules(HANDLE hProc, DWORD pID) {
	HMODULE hMods[100];
	DWORD cb;
	if (EnumProcessModules(hProc, hMods, sizeof(hMods), &cb)) {
		TCHAR szName[MAX_PATH];
		DWORD size = 100;
		MODULEINFO mInfo;
		LPVOID address;
		for (int i = 0; i < (cb / sizeof(HMODULE)); i++) {
			try
			{
				if (GetModuleBaseName(hProc, hMods[i], szName, MAX_PATH) &&
					GetModuleInformation(hProc, hMods[i], &mInfo, cb)) {
					address = mInfo.lpBaseOfDll;
					if (max_lenght < wcslen(szName))
						max_lenght = wcslen(szName);
					wstring DLL_name = wstring(szName);
					try {
						LPVOID nt_header_offset = (BYTE*)mInfo.lpBaseOfDll + *((BYTE*)mInfo.lpBaseOfDll + 0x3c);
						if (!strcmp((CHAR*)nt_header_offset, "PE")) {
							LPVOID optional_header = (BYTE *)nt_header_offset + 0x18;
							Result2[sz].SAFE_SEH = check_SEH(mInfo.lpBaseOfDll,optional_header);
							Result2[sz].DLL_name = DLL_name;
							Result2[sz].ASLR = check_ASLR(optional_header);
							Result2[sz].DEP = check_DEP(optional_header);
							Result2[sz++].Base = mInfo.lpBaseOfDll;
							
						}
					}
					catch (exception e) {
						Result2[sz].DLL_name = DLL_name;
						Result2[sz].SAFE_SEH = L"-";
						Result2[sz].Base = mInfo.lpBaseOfDll;
						Result2[sz].DEP = L"-";
						Result2[sz++].ASLR = L"-";
					}
					
					//Result[std::wstring(szName)] = mInfo.lpBaseOfDll;
				}
			}
			catch (const std::exception&)
			{
				std::cout << "Exception occurred" << std::endl;
			}

		}
	}
	if (sz> 0)
		return TRUE;
	return FALSE;
}

void printModules() {
	int total_lenght = int(max_lenght) + 49;
	l(total_lenght); l(total_lenght);
	c(); std::cout << std::left << std::setw(max_lenght) << std::setfill(' ') << "DLL Name";
	c(); std::cout << std::left << std::setw(12) << std::setfill(' ') << "Base Address";
	c(); std::cout << std::right << std::setw(8) << std::setfill(' ') << "SAFE SEH";
	c(); std::cout << std::right << std::setw(8) << std::setfill(' ') << "ASLR";
	c(); std::cout << std::right << std::setw(5) << std::setfill(' ') << "DEP";
	c(); std::cout << std::endl;
	l(total_lenght); l(total_lenght);
	for (int i = 0; i < sz; i++) {
		c(); std::wcout << std::left << std::setw(max_lenght) << std::setfill(TCHAR(' ')) << (Result2[i].DLL_name).c_str(); c();
		std::cout << std::right << std::setw(12) << std::setfill(' ') << Result2[i].Base; c();
		std::wcout << std::right << std::setw(8) << std::setfill(L' ') << Result2[i].SAFE_SEH; c();
		std::wcout << std::right << std::setw(8) << std::setfill(L' ') << Result2[i].ASLR; c();
		std::wcout << std::right << std::setw(5) << std::setfill(L' ') << Result2[i].DEP;
		c(); std::cout << std::endl;
	}

	l(total_lenght); l(total_lenght);

}

extern "C" __declspec(dllexport) void check() {
	HANDLE hProc_Addr = GetCurrentProcess();
	DWORD pID = GetCurrentProcessId();
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);
	if (hProcess != NULL) {
		if (EnableTokenPrivilege(SE_DEBUG_NAME, hProc_Addr))
		{
			if (GetProcessModules(hProcess, pID)) {
				printModules();
			}
		}
	}
}

