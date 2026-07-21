#define _WIN32_WINNT 0x0600

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")

typedef VOID (WINAPI *stub_entry_t)(VOID);
typedef LONG (WINAPI *reg_open_key_ex_a_t)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
typedef LONG (WINAPI *reg_set_value_ex_a_t)(HKEY, LPCSTR, DWORD, DWORD, const BYTE *, DWORD);
typedef LONG (WINAPI *reg_delete_value_a_t)(HKEY, LPCSTR);
typedef LONG (WINAPI *reg_close_key_t)(HKEY);

static const unsigned char kEncodedCommand[] = {
    0x43, 0x4f, 0x4d, 0x4d, 0x41, 0x4e, 0x44, 0x3a, 0x20,
    0x70, 0x6f, 0x77, 0x65, 0x72, 0x73, 0x68, 0x65, 0x6c,
    0x6c, 0x20, 0x2d, 0x65, 0x6e, 0x63, 0x20, 0x53, 0x47,
    0x56, 0x73, 0x62, 0x47, 0x38, 0x67, 0x56, 0x32, 0x39,
    0x79, 0x62, 0x47, 0x51, 0x3d
};

static void enumerate_processes(void) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("[proc] Could not snapshot processes.\n");
        return;
    }

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(entry);

    int count = 0;
    if (Process32FirstW(snapshot, &entry)) {
        do {
            count++;
        } while (Process32NextW(snapshot, &entry));
    }

    printf("[proc] Enumerated %d processes.\n", count);
    CloseHandle(snapshot);
}

static void create_demo_mutex(void) {
    HANDLE mutex = CreateMutexW(NULL, FALSE, L"Local\\WizhorseBenignSuspiciousMutex");
    if (mutex == NULL) {
        printf("[mutex] CreateMutexW failed.\n");
        return;
    }
    printf("[mutex] Created and released demo mutex.\n");
    CloseHandle(mutex);
}

static DWORD WINAPI harmless_thread(LPVOID parameter) {
    stub_entry_t stub = (stub_entry_t)parameter;
    stub();
    return 0;
}

static void allocate_and_execute_rwx_stub(void) {
    const unsigned char stub_bytes[] = {0xC3};
    LPVOID memory = VirtualAlloc(
        NULL,
        sizeof(stub_bytes),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (memory == NULL) {
        printf("[rwx] VirtualAlloc failed.\n");
        return;
    }

    memcpy(memory, stub_bytes, sizeof(stub_bytes));
    HANDLE thread = CreateThread(NULL, 0, harmless_thread, memory, 0, NULL);
    if (thread == NULL) {
        printf("[rwx] CreateThread failed.\n");
        VirtualFree(memory, 0, MEM_RELEASE);
        return;
    }

    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    VirtualFree(memory, 0, MEM_RELEASE);
    printf("[rwx] Executed single-instruction RWX stub safely.\n");
}

static void collect_basic_identity(void) {
    char computer_name[256];
    DWORD size = sizeof(computer_name);
    if (GetComputerNameA(computer_name, &size)) {
        printf("[recon] Computer name: %s\n", computer_name);
    }

    char user_name[256];
    size = sizeof(user_name);
    if (GetUserNameA(user_name, &size)) {
        printf("[recon] User name: %s\n", user_name);
    }
}

static void enumerate_network_adapters(void) {
    ULONG size = 0;
    ULONG status = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL, &size);
    if (status != ERROR_BUFFER_OVERFLOW) {
        printf("[net] GetAdaptersAddresses sizing failed (rc=%lu).\n", status);
        return;
    }

    IP_ADAPTER_ADDRESSES *buffer = (IP_ADAPTER_ADDRESSES *)malloc(size);
    if (buffer == NULL) {
        printf("[net] Allocation failed.\n");
        return;
    }

    status = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, buffer, &size);
    if (status != NO_ERROR) {
        printf("[net] GetAdaptersAddresses failed (rc=%lu).\n", status);
        free(buffer);
        return;
    }

    int count = 0;
    for (IP_ADAPTER_ADDRESSES *adapter = buffer; adapter != NULL; adapter = adapter->Next) {
        count++;
    }

    printf("[net] Enumerated %d network adapters without sending traffic.\n", count);
    free(buffer);
}

static void decode_demo_blob(void) {
    char decoded[sizeof(kEncodedCommand)];
    size_t index;

    for (index = 0; index < sizeof(kEncodedCommand); index++) {
        decoded[index] = (char)kEncodedCommand[index];
    }
    decoded[sizeof(decoded) - 1] = '\0';

    printf("[decode] Decoded harmless demo string: %s\n", decoded);
}

static void write_and_remove_demo_autostart(void) {
    HMODULE advapi32 = LoadLibraryW(L"advapi32.dll");
    if (advapi32 == NULL) {
        printf("[reg] Could not load advapi32.dll.\n");
        return;
    }

    reg_open_key_ex_a_t open_key =
        (reg_open_key_ex_a_t)GetProcAddress(advapi32, "RegOpenKeyExA");
    reg_set_value_ex_a_t set_value =
        (reg_set_value_ex_a_t)GetProcAddress(advapi32, "RegSetValueExA");
    reg_delete_value_a_t delete_value =
        (reg_delete_value_a_t)GetProcAddress(advapi32, "RegDeleteValueA");
    reg_close_key_t close_key =
        (reg_close_key_t)GetProcAddress(advapi32, "RegCloseKey");

    if (open_key == NULL || set_value == NULL || delete_value == NULL || close_key == NULL) {
        printf("[reg] Could not resolve registry APIs dynamically.\n");
        FreeLibrary(advapi32);
        return;
    }

    const char *key_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    const char *value_name = "WizhorseBenignTool";
    const char *value_data = "C:\\path\\to\\benign_suspicious_plus.exe";

    HKEY key_handle;
    LONG result = open_key(HKEY_CURRENT_USER, key_path, 0, KEY_SET_VALUE, &key_handle);
    if (result != ERROR_SUCCESS) {
        printf("[reg] Could not open HKCU Run key (rc=%ld).\n", result);
        FreeLibrary(advapi32);
        return;
    }

    result = set_value(
        key_handle,
        value_name,
        0,
        REG_SZ,
        (const BYTE *)value_data,
        (DWORD)(strlen(value_data) + 1)
    );
    if (result == ERROR_SUCCESS) {
        printf("[reg] Wrote demo Run value.\n");
    } else {
        printf("[reg] Failed to write Run value (rc=%ld).\n", result);
    }
    close_key(key_handle);

    result = open_key(HKEY_CURRENT_USER, key_path, 0, KEY_SET_VALUE, &key_handle);
    if (result == ERROR_SUCCESS) {
        delete_value(key_handle, value_name);
        close_key(key_handle);
        printf("[reg] Removed demo Run value.\n");
    }

    FreeLibrary(advapi32);
}

static void write_and_delete_dropper_like_file(void) {
    char temp_path[MAX_PATH];
    char temp_file[MAX_PATH];
    DWORD path_length = GetTempPathA((DWORD)sizeof(temp_path), temp_path);
    if (path_length == 0 || path_length >= sizeof(temp_path)) {
        printf("[file] Could not resolve temp path.\n");
        return;
    }

    if (GetTempFileNameA(temp_path, "wh", 0, temp_file) == 0) {
        printf("[file] Could not create temp file name.\n");
        return;
    }

    HANDLE file = CreateFileA(
        temp_file,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (file == INVALID_HANDLE_VALUE) {
        printf("[file] Could not create temp file.\n");
        DeleteFileA(temp_file);
        return;
    }

    const char payload[] =
        "@echo off\r\n"
        "echo This is a harmless static-analysis calibration artifact.\r\n";
    DWORD written = 0;
    WriteFile(file, payload, (DWORD)strlen(payload), &written, NULL);
    CloseHandle(file);

    DeleteFileA(temp_file);
    printf("[file] Wrote and deleted a short-lived script-like temp artifact.\n");
}

int wmain(void) {
    printf("=== benign_suspicious_plus.exe ===\n");
    printf("This binary is intentionally suspicious-looking but benign.\n");
    printf("It exists only to exercise static analysis heuristics.\n\n");

    enumerate_processes();
    create_demo_mutex();
    allocate_and_execute_rwx_stub();
    write_and_remove_demo_autostart();
    collect_basic_identity();
    enumerate_network_adapters();
    decode_demo_blob();
    write_and_delete_dropper_like_file();

    printf("\nDone. No network traffic, no persistence left behind, no other process modified.\n");
    return 0;
}
