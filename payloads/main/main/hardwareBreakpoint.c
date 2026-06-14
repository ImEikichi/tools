#include <windows.h>
#include <stdio.h>
#include <winternl.h>
#include "hardwareBreakpoint.h"
#include <tlhelp32.h>

// to be explained :) 
void SetDR0Breakpoint(PVOID address) {
    DWORD pid = GetCurrentProcessId();

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te = { 0 };
    te.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hSnapshot, &te)) {
        CloseHandle(hSnapshot);
        return;
    }

    do {
        // Filtre uniquement les threads du process courant
        if (te.th32OwnerProcessID != pid) continue;

        HANDLE hThread = OpenThread(
            THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
            FALSE,
            te.th32ThreadID
        );
        if (!hThread) continue;

        SuspendThread(hThread);

        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        GetThreadContext(hThread, &ctx);

        ctx.Dr0 = (DWORD64)address;
        ctx.Dr7 |= (1 << 0);

        SetThreadContext(hThread, &ctx);
        ResumeThread(hThread);
        CloseHandle(hThread);

    } while (Thread32Next(hSnapshot, &te));

    CloseHandle(hSnapshot);
}



void SetDR0BreakpointFormer(PVOID address) {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    GetThreadContext(GetCurrentThread(), &ctx);

    ctx.Dr0 = (DWORD64)address;   // adresse du breakpoint
    ctx.Dr7 |= (1 << 0);          // active DR0 (bit 0 de DR7)

    SetThreadContext(GetCurrentThread(), &ctx);
}