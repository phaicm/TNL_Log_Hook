#pragma once
#include <Windows.h>

/*
	Below code is the minimum required for Virtools to not reject a DLL from ./BuildingBlocks/.
	It is essentially a bypass during the CKPluginManager::RegisterPlugin() which subsequently calls
	VxSharedLibrary::Load() in CK2.dll. There are three checks in this function.
		1) Check for dllexport of CKGetPluginInfoCount (returns an int value).
		2) Check for dllexport of CKGetPluginInfo (returns an address CKPluginInfo)
		3) Check for dllexport of RegisterBehaviorDeclarations (returns an int value).
	If either check fails, it wil subsquently release your DLL immediately, but your DLL should have
	already performed all the tasks in DLL_PROCESS_ATTACH which is an exploit of itself. However, for
	this purpose, we needed a way to keep the DLL active in memory to perform logging functions without
	compiling this against Virtools SDK. 

	This method was tested for Virtools 4.0 players / programs. But should work universally with 3.5
	and 5.0.

*/

//Creation of a fake CKPluginInfo for Virtools to validate during CKGetPluginInfo().
struct Fake_CKPluginInfo {
	unsigned int m_GUID[2];
	char m_ExtShort[4];
	char* m_Description_m_Buffer;
	unsigned short m_Description_m_Length;
	unsigned short m_Description_m_Allocated;
	char* m_Author_m_Buffer;
	unsigned short m_Author_m_Length;
	unsigned short m_Author_m_Allocated;
	char* m_Summary_m_Buffer;
	unsigned short m_Summary_m_Length;
	unsigned short m_Summary_m_Allocated;
	unsigned int m_Version;
	unsigned int m_InitInstanceFct;
	unsigned int m_Type;
	unsigned int m_ExitInstanceFct;
	char m_Extension[4];
};
Fake_CKPluginInfo myPlugin;

extern "C" __declspec(dllexport) int CKGetPluginInfoCount() { return 1; }
extern "C" __declspec(dllexport) Fake_CKPluginInfo* CKGetPluginInfo(int Index)
{
	myPlugin.m_Description_m_Buffer = "Virtools";
	myPlugin.m_Description_m_Buffer = "Building blocks AddOns 3";
	myPlugin.m_Extension[0] = 'a';
	myPlugin.m_Type = 4;
	myPlugin.m_Version = 0x000001;
	myPlugin.m_InitInstanceFct = NULL;
	myPlugin.m_ExitInstanceFct = NULL;
	myPlugin.m_GUID[0] = 0x12345678;
	myPlugin.m_GUID[1] = 0x12345679;
	myPlugin.m_Summary_m_Buffer = "FakePlugin";
	return &myPlugin;
}
extern "C" __declspec(dllexport) int RegisterBehaviorDeclarations(char *a) { return 1; }
