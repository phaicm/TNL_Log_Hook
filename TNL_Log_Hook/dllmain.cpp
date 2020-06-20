#include <Windows.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <WinInet.h>
#include <Psapi.h>
#include <string>

//Third Party Libs
#include "3rdparty\INI.h"
#include "3rdparty\detours.h"
#pragma comment(lib, "3rdparty\detours.lib")

#include "virtools.h"

/*
	Globals
*/
DWORD logprintfAddress = 0;
std::ofstream ofs;


/*
	Helper Functions
*/
DWORD FindPattern(char *module, char *pattern, char *mask)
{
	MODULEINFO mInfo;
	GetModuleInformation(GetCurrentProcess(), GetModuleHandle(module), &mInfo, sizeof(MODULEINFO));
	DWORD base = (DWORD)mInfo.lpBaseOfDll;
	DWORD size = (DWORD)mInfo.SizeOfImage;
	DWORD patternLength = (DWORD)strlen(mask);

	for (DWORD i = 0; i < size - patternLength; i++)
	{
		bool found = true;
		for (DWORD j = 0; j < patternLength; j++)
		{
			found &= mask[j] == '?' || pattern[j] == *(char*)(base + i + j);
		}
		if (found)
		{
			return base + i;
		}
	}

	return NULL;
}

BOOL InstallSystemHook(LPCTSTR dllname, LPCSTR exportname, VOID *ProxyFunction, LPVOID *pOriginalFunction)
{
	BOOL result = FALSE;
	std::stringstream fullpath;

	TCHAR systemdir[MAX_PATH];
	HMODULE hDll;
	::GetSystemDirectory(systemdir, MAX_PATH);

	fullpath << systemdir << "\\" << dllname;
	hDll = ::LoadLibrary(fullpath.str().c_str());

	if (!hDll)
		return result;

	BYTE *p;
	p = (BYTE*)::GetProcAddress(hDll, exportname);
	DetourTransactionBegin();
	*pOriginalFunction = DetourFindFunction(dllname, exportname);

	if (DetourAttach(pOriginalFunction, ProxyFunction) == NO_ERROR)
	{
		DetourTransactionCommit();
		result = TRUE;
	}
	else DetourTransactionAbort();

	ofs << "Hooked: " << exportname << "@" << dllname << std::endl;

	return result;
}


/*
	Hooked Functions
*/

//OpenTNL logprintf
void Hook_logprintf(const char *format, ...)
{
	va_list argptr;
	va_start(argptr, format);
	int length = _vscprintf(format, argptr);
	char* buf = new char[length + 2];

	vsprintf_s(buf, length + 2, format, argptr);
	strcat_s(buf, length + 2, "");

	ofs << buf << std::endl;

	delete[] buf;
	va_end(argptr);
}

//wininet.dll InternetConnectA
typedef HINTERNET(WINAPI *tInternetConnectA)(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
tInternetConnectA OrigInternetConnectA = NULL;

HINTERNET WINAPI MyInternetConnectA(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext)
{
	LPCSTR newServerName = lpszServerName;
	INI ini("TNL_HOOK.ini", true);
	ini.select("HTTP_Redirect");
	LPCSTR redirectServerName = ini.getAs<LPCSTR>("HTTP_Redirect", lpszServerName, "");

	if (lstrcmp(redirectServerName, "") != 0)
	{
		newServerName = redirectServerName;
		ofs << "Redirecting " << lpszServerName << "-->" << redirectServerName << std::endl;;
	}
		
	return OrigInternetConnectA(hInternet, newServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
}


/*
	DLLMain
*/
BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		//INI Initialization
		INI::PARSE_FLAGS = INI::PARSE_COMMENTS_ALL | INI::PARSE_COMMENTS_SLASH | INI::PARSE_COMMENTS_HASH;
		INI ini("TNL_HOOK.ini", true);

		//Output File Initialization
		std::ostringstream tempfilepath;
		char* buf = nullptr;
		size_t sz = 0;
		if (_dupenv_s(&buf, &sz, "UserProfile") == 0 && buf != nullptr)
		{
			tempfilepath << buf << "\\Desktop\\TNLLogHook.txt";
			free(buf);
		}
		ofs.open(tempfilepath.str(), std::ofstream::out);
		
		ofs << "============TNL_Log_Hook START============" << std::endl;

		ofs << "Debug: " << ini["DEBUG"]["logprintf"] << std::endl;
		ofs << "Redirect: " << ini["HTTP_Redirect"]["Redirect"] << std::endl;

		ini.select("DEBUG");
		if (ini.getAs<int>("DEBUG", "logprintf", 0) == 1)
		{
			logprintfAddress = FindPattern("Avatar.dll", "\xE9\xBF\x13\x0B\x00\xE9\x6A\x24\x0C\x00", "xxxxxxxxxx");
			ofs << "logprintfAddress: 0x" << std::hex << logprintfAddress << std::endl;
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourAttach(&(LPVOID&)logprintfAddress, &Hook_logprintf);
			DetourTransactionCommit();
		}
		
		ini.select("HTTP_Redirect");
		if (ini.getAs<int>("HTTP_Redirect", "Redirect", 0) == 1)
		{
			InstallSystemHook("wininet.dll", "InternetConnectA", *MyInternetConnectA, (LPVOID*)&OrigInternetConnectA);
		}
	}

	else if (dwReason == DLL_PROCESS_DETACH)
	{
		INI ini("TNL_HOOK.ini", true);
		ofs << "DLL_PROCESS_DETACH - lpReserved: " << std::hex << lpReserved << std::endl;
		ofs << "Unhooking functions" << std::endl;
		ini.select("DEBUG");
		if (ini.getAs<int>("DEBUG", "logprintf", 0) == 1)
		{
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourDetach(&(LPVOID&)logprintfAddress, &Hook_logprintf);
			DetourTransactionCommit();
		}

		ini.select("HTTP_Redirect");
		if (ini.getAs<int>("HTTP_Redirect", "Redirect", 0) == 1)
		{
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourDetach(&(LPVOID&)OrigInternetConnectA, &MyInternetConnectA);
			DetourTransactionCommit();
		}

		ofs << "============TNL_Log_Hook END============" << std::endl;
	}
	return TRUE;
}
