#pragma once
#include <windows.h>
#include <winternl.h>

extern PVOID g_AmsiScanBuffer;

// structures windows pour cast
typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE  ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG   AllocationType,
    ULONG   Protect
    );

typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
    HANDLE  ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG   NewProtect,
    PULONG  OldProtect
    );
typedef VOID(NTAPI* pRtlMoveMemory)(
    PVOID       Destination,
    const PVOID Source,
    SIZE_T      Length
    );

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE             ThreadHandle,
    ACCESS_MASK         DesiredAccess,
    PVOID               ObjectAttributes,
    HANDLE              ProcessHandle,
    PVOID               StartRoutine,
    PVOID               Argument,
    ULONG               CreateFlags,
    SIZE_T              ZeroBits,
    SIZE_T              StackSize,
    SIZE_T              MaximumStackSize,
    PVOID               AttributeList
    );

typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY;

// fonctions
PVOID pebWalking(const wchar_t* dllSearched);
PVOID peParsing(PVOID dll_addr, const char* funcName);
LONG WINAPI VEH_Handler(EXCEPTION_POINTERS* pExInfo);