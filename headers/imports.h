#pragma once

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$DeleteFileW(LPCWSTR);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryExW(LPCWSTR, HANDLE, DWORD);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError();
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT HGLOBAL WINAPI KERNEL32$GlobalAlloc(UINT, SIZE_T);
DECLSPEC_IMPORT HGLOBAL WINAPI KERNEL32$GlobalFree(HGLOBAL);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$DeviceIoControl(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetCurrentProcessId();
DECLSPEC_IMPORT UINT WINAPI KERNEL32$GetWindowsDirectoryW(LPWSTR, UINT);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetModuleFileNameW(HMODULE, LPWSTR, DWORD);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$FormatMessageA(DWORD, LPCVOID, DWORD, DWORD, LPTSTR, DWORD, va_list*);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleW(LPCWSTR);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$StartServiceW(SC_HANDLE, DWORD, LPCWSTR*);
DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$CreateServiceW(SC_HANDLE, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR);
DECLSPEC_IMPORT HANDLE WINAPI ADVAPI32$OpenSCManagerW(LPCWSTR, LPCWSTR, DWORD);
DECLSPEC_IMPORT HANDLE WINAPI ADVAPI32$OpenServiceW(SC_HANDLE, LPCWSTR, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ControlService(SC_HANDLE, DWORD, LPSERVICE_STATUS);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$DeleteService(SC_HANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE);

DECLSPEC_IMPORT HRESULT WINAPI OLE32$IIDFromString(LPCOLESTR, LPIID);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitialize(LPVOID);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoGetObject(LPCWSTR, BIND_OPTS*, REFIID, void**);

DECLSPEC_IMPORT BOOL WINAPI NTDLL$NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

WINBASEAPI  int         __cdecl     MSVCRT$fclose (FILE *fStream);
WINBASEAPI  errno_t     __cdecl     MSVCRT$fopen_s (FILE **fStream, const char* _fName, const char *_Mode);
WINBASEAPI  int         __cdecl     MSVCRT$fseek (FILE *fStream, long _Offset, int _Origin);
WINBASEAPI  long        __cdecl     MSVCRT$ftell (FILE *fStream);
WINBASEAPI  int         __cdecl     MSVCRT$getc (FILE *fStream);
WINBASEAPI  long        __cdecl     MSVCRT$rewind (FILE *fStream);
WINBASEAPI  char*       __cdecl     MSVCRT$strstr (char* _String, const char* _SubString);
WINBASEAPI  void*       __cdecl     MSVCRT$memset (void* _Dst, int _Val, size_t Size);
WINBASEAPI  errno_t     __cdecl     MSVCRT$wcscat_s (wchar_t*, size_t, const wchar_t*);
WINBASEAPI  errno_t     __cdecl     MSVCRT$wcscpy_s (wchar_t*, rsize_t, const wchar_t*);
WINBASEAPI  void*       __cdecl     MSVCRT$malloc (size_t);
WINBASEAPI  void*       __cdecl     MSVCRT$calloc (size_t, size_t);
WINBASEAPI  int         __cdecl     MSVCRT$_wcsicmp (const wchar_t*, const wchar_t*);
WINBASEAPI  size_t      __cdecl     MSVCRT$wcslen (const wchar_t*);
WINBASEAPI  void*       __cdecl     MSVCRT$memcpy (void*, const void*, size_t);
WINBASEAPI  size_t      __cdecl     MSVCRT$strlen (const char*);
WINBASEAPI  size_t      __cdecl     MSVCRT$mbstowcs (wchar_t*, const char*, size_t);
