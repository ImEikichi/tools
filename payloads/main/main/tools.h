#pragma once
#include <windows.h>
#include <ole2.h>

/* ── GUIDs ─────────────────────────────────────────────── */
static const GUID CLSID_CLRMetaHost = {
    0x9280188d,0xe8e, 0x4867,{0xb3,0xc,0x7f,0xa8,0x38,0x84,0xe8,0xde}
};
static const GUID IID_ICLRMetaHost = {
    0xD332DB9E,0xB9B3,0x4125,{0x82,0x07,0xA1,0x48,0x84,0xF5,0x32,0x16}
};
static const GUID CLSID_CLRRuntimeHost = {
    0x90F1A06E,0x7712,0x4762,{0x86,0xB5,0x7A,0x5E,0xBA,0x6B,0xDB,0x02}
};
static const GUID IID_ICLRRuntimeHost = {
    0x90F1A06C,0x7712,0x4762,{0x86,0xB5,0x7A,0x5E,0xBA,0x6B,0xDB,0x02}
};
static const GUID IID_ICLRRuntimeInfo = {
    0xBD39D1D2,0xBA2F,0x486a,{0x89,0xB0,0xB4,0xB0,0xCB,0x46,0x68,0x91}
};

/* ── Vtables ────────────────────────────────────────────── */
typedef struct ICLRRuntimeHostVtbl ICLRRuntimeHostVtbl;
typedef struct { ICLRRuntimeHostVtbl* lpVtbl; } ICLRRuntimeHost;
struct ICLRRuntimeHostVtbl {
    HRESULT(STDMETHODCALLTYPE* QueryInterface)      (ICLRRuntimeHost*, REFIID, void**);
    ULONG(STDMETHODCALLTYPE* AddRef)              (ICLRRuntimeHost*);
    ULONG(STDMETHODCALLTYPE* Release)             (ICLRRuntimeHost*);
    HRESULT(STDMETHODCALLTYPE* Start)               (ICLRRuntimeHost*);
    HRESULT(STDMETHODCALLTYPE* Stop)                (ICLRRuntimeHost*);
    HRESULT(STDMETHODCALLTYPE* SetHostControl)      (ICLRRuntimeHost*, void*);
    HRESULT(STDMETHODCALLTYPE* GetCLRControl)       (ICLRRuntimeHost*, void**);
    HRESULT(STDMETHODCALLTYPE* UnloadAppDomain)     (ICLRRuntimeHost*, DWORD, BOOL);
    HRESULT(STDMETHODCALLTYPE* ExecuteInAppDomain)  (ICLRRuntimeHost*, DWORD, void*, void*, DWORD*);
    HRESULT(STDMETHODCALLTYPE* GetCurrentAppDomainId)(ICLRRuntimeHost*, DWORD*);
    HRESULT(STDMETHODCALLTYPE* ExecuteApplication)  (ICLRRuntimeHost*, LPCWSTR, DWORD, LPCWSTR*, DWORD, void*, DWORD*);
    HRESULT(STDMETHODCALLTYPE* ExecuteInDefaultAppDomain)(ICLRRuntimeHost*, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, DWORD*);
};

typedef struct ICLRRuntimeInfoVtbl ICLRRuntimeInfoVtbl;
typedef struct { ICLRRuntimeInfoVtbl* lpVtbl; } ICLRRuntimeInfo;
struct ICLRRuntimeInfoVtbl {
    HRESULT(STDMETHODCALLTYPE* QueryInterface)          (ICLRRuntimeInfo*, REFIID, void**);
    ULONG(STDMETHODCALLTYPE* AddRef)                  (ICLRRuntimeInfo*);
    ULONG(STDMETHODCALLTYPE* Release)                 (ICLRRuntimeInfo*);
    HRESULT(STDMETHODCALLTYPE* GetVersionString)        (ICLRRuntimeInfo*, LPWSTR, DWORD*);
    HRESULT(STDMETHODCALLTYPE* GetRuntimeDirectory)     (ICLRRuntimeInfo*, LPWSTR, DWORD*);
    HRESULT(STDMETHODCALLTYPE* IsLoaded)                (ICLRRuntimeInfo*, HANDLE, BOOL*);
    HRESULT(STDMETHODCALLTYPE* LoadErrorString)         (ICLRRuntimeInfo*, UINT, LPWSTR, DWORD*, LCID);
    HRESULT(STDMETHODCALLTYPE* LoadLibrary)             (ICLRRuntimeInfo*, LPCWSTR, HMODULE*);
    HRESULT(STDMETHODCALLTYPE* GetProcAddress)          (ICLRRuntimeInfo*, LPCWSTR, LPVOID*);
    HRESULT(STDMETHODCALLTYPE* GetInterface)            (ICLRRuntimeInfo*, REFCLSID, REFIID, LPVOID*);
    HRESULT(STDMETHODCALLTYPE* IsLoadable)              (ICLRRuntimeInfo*, BOOL*);
    HRESULT(STDMETHODCALLTYPE* SetDefaultStartupFlags)  (ICLRRuntimeInfo*, DWORD, LPCWSTR);
    HRESULT(STDMETHODCALLTYPE* GetDefaultStartupFlags)  (ICLRRuntimeInfo*, DWORD*, LPWSTR, DWORD*);
    HRESULT(STDMETHODCALLTYPE* BindAsLegacyV2Runtime)   (ICLRRuntimeInfo*);
    HRESULT(STDMETHODCALLTYPE* IsStarted)               (ICLRRuntimeInfo*, BOOL*, DWORD*);
};

typedef struct ICLRMetaHostVtbl ICLRMetaHostVtbl;
typedef struct { ICLRMetaHostVtbl* lpVtbl; } ICLRMetaHost;
struct ICLRMetaHostVtbl {
    HRESULT(STDMETHODCALLTYPE* QueryInterface)(ICLRMetaHost*, REFIID, void**);
    ULONG(STDMETHODCALLTYPE* AddRef)        (ICLRMetaHost*);
    ULONG(STDMETHODCALLTYPE* Release)       (ICLRMetaHost*);
    HRESULT(STDMETHODCALLTYPE* GetRuntime)    (ICLRMetaHost*, LPCWSTR, REFIID, LPVOID*);
};

/* ── Export ─────────────────────────────────────────────── */
HRESULT LoadCLR(ICLRRuntimeHost** ppHost);