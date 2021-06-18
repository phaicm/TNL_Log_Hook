#include <Windows.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <WinInet.h>
#include <Psapi.h>
#include <string>

/*
	Third Party Libraries
*/

#include "3rdparty\INI.h"
#include "3rdparty\detours.h"
#pragma comment(lib, "3rdparty\\detours.lib")

/*
	Custom Headers
*/

#include "virtools.h"

/*
	Globals
*/

DWORD logprintfAddress = 0;
std::ofstream ofs;


/*
	Helper Functions
*/

DWORD FindPattern(const char *module, char *pattern, const char *mask)
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
		ofs << "Hooked: " << exportname << "@" << dllname << std::endl;
	}
	else DetourTransactionAbort();

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
tInternetConnectA Orig_InternetConnectA = NULL;

HINTERNET WINAPI my_InternetConnectA(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext)
{
	LPCSTR newServerName = lpszServerName;
	INI ini("TNL_HOOK.ini", true);
	ini.select("HTTP_Redirect");
	LPCSTR redirectServerName = ini.getAs<LPCSTR>("HTTP_Redirect", lpszServerName, "");

	if (lstrcmp(redirectServerName, "") != 0)
	{
		newServerName = redirectServerName;
		ofs << "[HTTP_Redirect] Redirecting " << lpszServerName << "-->" << redirectServerName << std::endl;
		return Orig_InternetConnectA(hInternet, newServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
	}

	ofs << "[HTTP_Redirect] No redirect for " << lpszServerName << std::endl;
	return Orig_InternetConnectA(hInternet, newServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
}

//ws2_32.dll gethostbyname
typedef hostent* (WINAPI *tgethostbyname)(const char* name);
tgethostbyname Orig_gethostbyname = NULL;

hostent * WINAPI my_gethostbyname(const char *name)
{
	INI ini("TNL_HOOK.ini", true);
	ini.select("HostName_Redirect");

	LPCSTR redirectServerName = ini.getAs<LPCSTR>("HostName_Redirect", name, "");

	if (lstrcmp(redirectServerName, "") != 0)
	{
		ofs << "[HostName_Redirect] Redirecting " << name << "-->" << redirectServerName << std::endl;
		return Orig_gethostbyname(redirectServerName);
	}

	ofs << "[HostName_Redirect] No redirect for " << name << std::endl;
	return Orig_gethostbyname(name);
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
		ini.select("DEBUG");

		if (ini.getAs<int>("DEBUG", "outputfile", 0) == 1)
		{
			std::ostringstream tempfilepath;
			char* buf = nullptr;
			size_t sz = 0;
			if (_dupenv_s(&buf, &sz, "UserProfile") == 0 && buf != nullptr)
			{
				tempfilepath << buf << "\\TNLLogHook.txt";
				free(buf);
			}
			ofs.open(tempfilepath.str(), std::ofstream::out);
		}
		
		ofs << "============TNL_Log_Hook START============" << std::endl;

		ofs << "Debug: " << ini["DEBUG"]["logprintf"] << std::endl;
		ofs << "Redirect: " << ini["HTTP_Redirect"]["Redirect"] << std::endl;

		ini.select("DEBUG");
		if (ini.getAs<int>("DEBUG", "logprintf", 0) == 1)
		{
			//The life of String to Char *
			std::string logprintf_dll = ini.get("DEBUG", "logprintf_dll", "");
			std::string logprintf_pattern = ini.get("DEBUG", "logprintf_pattern", "");
			std::string logprintf_mask = ini.get("DEBUG", "logprintf_mask", "");

			//Convert hex string to array byte
			std::istringstream hex_chars_stream(logprintf_pattern);
			std::vector<unsigned char> bytes;
			unsigned int c;
			while (hex_chars_stream >> std::hex >> c)
			{
				bytes.push_back(c);
			}

			ofs << "logprintf_dll: " << logprintf_dll << std::endl;
			ofs << "logprintf_pattern: " << logprintf_pattern << std::endl;
			ofs << "logprintf_mask: " << logprintf_mask << std::endl;

			logprintfAddress = FindPattern(logprintf_dll.c_str(), reinterpret_cast<char*> (&bytes[0]), logprintf_mask.c_str());

			if (logprintfAddress != NULL)
			{
				ofs << "logprintfAddress: 0x" << std::hex << logprintfAddress << std::endl;
				DetourTransactionBegin();
				DetourUpdateThread(GetCurrentThread());
				if (DetourAttach(&(LPVOID&)logprintfAddress, &Hook_logprintf) == NO_ERROR)
				{
					DetourTransactionCommit();
					ofs << "Hooked: - logprintf" << std::endl;
				}
			}

		}
		
		ini.select("HTTP_Redirect");
		if (ini.getAs<int>("HTTP_Redirect", "Redirect", 0) == 1)
		{
			InstallSystemHook("wininet.dll", "InternetConnectA", *my_InternetConnectA, (LPVOID*)&Orig_InternetConnectA);
		}

		ini.select("HostName_Redirect");
		if (ini.getAs<int>("HostName_Redirect", "Redirect", 0) == 1)
		{
			InstallSystemHook("ws2_32.dll", "gethostbyname", *my_gethostbyname, (LPVOID*)&Orig_gethostbyname);
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
			if (DetourDetach(&(LPVOID&)logprintfAddress, &Hook_logprintf) == NO_ERROR) 
			{
				ofs << "Unhooked: logprintf - Sucess" << std::endl;
			}
			DetourTransactionCommit();
		}

		ini.select("HTTP_Redirect");
		if (ini.getAs<int>("HTTP_Redirect", "Redirect", 0) == 1)
		{
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			if (DetourDetach(&(LPVOID&)Orig_InternetConnectA, &my_InternetConnectA) == NO_ERROR)
			{
				ofs << "Unhooked: InternetConnectA - Sucess" << std::endl;
			}
			DetourTransactionCommit();
		}

		ini.select("HostName_Redirect");
		if (ini.getAs<int>("HostName_Redirect", "Redirect", 0) == 1)
		{
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			if (DetourDetach(&(LPVOID&)Orig_gethostbyname, &my_gethostbyname) == NO_ERROR)
			{
				ofs << "Unhooked: gethostbyname - Sucess" << std::endl;
			}
			DetourTransactionCommit();
		}

		ofs << "============TNL_Log_Hook END============" << std::endl;
		ofs.close();
	}
	return TRUE;
}
