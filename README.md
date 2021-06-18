# TNL_Log_Hook

An OpenTNL `TNL:logprintf()` hook for games that utilizes the function but had surpressed output. It will now redirect the output to a `TNLLogHook.txt` file in `%USERS%` folder.

It can perform the following:

  * Hook `TNL::logprintf()` for debug output
  * Hook `InternetConnectA` from `wininet.dll` to redirect based on matched `lpszServerName` in TNL_HOOK.ini
  * Hook `gethostbyname` from `ws2_32.dll` to redirect based on matched `name` in TNL_HOOK.ini
  * Allows Virtools Players to load this DLL by including export checks. For more info, check `virtools.h`

The purpose of this program is for software conservation.

## Build
  * Build in Visual Studio 2015 (v140) toolset
  * May need to adjust Visual Studio Property Pages -> Target Platform Version to whatever platform version you have.

## Installation

1. Copy `TNL_Log_Hook.dll` to `[VirtoolsGame]/BuildingBlocks/` folder
2. Copy `TNL_HOOK.ini` to `[VirtoolsGame]` folder where the .exe to start the game.
3. Make sure to have vcruntime140

If you are intending to use this on a non-Virtools program, you must use your own DLL injection method.


### 3rd Party Software
  * [feather-ini-parser](https://github.com/Turbine1991/cpp-feather-ini-parser)
  * [Microsoft Detours](https://github.com/microsoft/Detours)
