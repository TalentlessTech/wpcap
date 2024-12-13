#pragma once

#include "pcap-dyn-types.h"
#include "pcap-dyn-api.h"

#define WPCAP_FLT_EMPTY          0
#define WPCAP_FLT_PRIMARY        0x00000001
#define WPCAP_FLT_BASE           0x00000002
#define WPCAP_FLT_SEND           0x00000004
#define WPCAP_FLT_REMOTE         0x00000008
#define WPCAP_FLT_EXT            0x00000010
#define WPCAP_FLT_ALL            0xFFFFFFFF

#define WPCAP_FLAG_WINPCAP_MODE  0x0001
#define WPCAP_FLAG_NPCAP_MODE    0x0002

#define WPCAP_LOAD_DLL_FROM_MEM  ((const wchar_t *)(1))


#define WPCAP_GOTO_EXIT_IF(exp, code) do { \
    if ((exp)) {                           \
        hr = code;                         \
        goto exit;                         \
    }                                      \
} while(0)

#define GET_PROC_ADDR_WPC(_funcname_) do {  \
    LPVOID * ptr = (LPVOID *)&wpc->_funcname_;  \
    LPVOID addr = (LPVOID) GetProcAddress(wpc->wpc.hModule, #_funcname_);  \
    if (!addr)          \
        return -2;      \
    *ptr = addr;        \
} while(0)

__forceinline
int wpcap_get_func(struct wpcap_dyn * wpc, DWORD filter)
{
    if (!wpc->wpc.hModule)
        return -1;
    if (filter & WPCAP_FLT_PRIMARY) {
        GET_PROC_ADDR_WPC(pcap_lib_version);
        GET_PROC_ADDR_WPC(pcap_findalldevs);
        GET_PROC_ADDR_WPC(pcap_freealldevs);
        GET_PROC_ADDR_WPC(pcap_lookupnet);
    }
    if (filter & WPCAP_FLT_BASE) {
        GET_PROC_ADDR_WPC(pcap_major_version);
        GET_PROC_ADDR_WPC(pcap_minor_version);
        GET_PROC_ADDR_WPC(pcap_open_live);
        GET_PROC_ADDR_WPC(pcap_close);
        GET_PROC_ADDR_WPC(pcap_lookupnet);
        GET_PROC_ADDR_WPC(pcap_compile);
        GET_PROC_ADDR_WPC(pcap_setfilter);
        GET_PROC_ADDR_WPC(pcap_dispatch);
        GET_PROC_ADDR_WPC(pcap_freecode);
        GET_PROC_ADDR_WPC(pcap_geterr);
        GET_PROC_ADDR_WPC(pcap_getnonblock);
        GET_PROC_ADDR_WPC(pcap_setnonblock);
    }
    if (filter & WPCAP_FLT_SEND) {
        GET_PROC_ADDR_WPC(pcap_sendpacket);
    }
    if (filter & WPCAP_FLT_EXT) {
        GET_PROC_ADDR_WPC(pcap_findalldevs_ex);
        GET_PROC_ADDR_WPC(pcap_setmintocopy);
        GET_PROC_ADDR_WPC(pcap_getevent);
        GET_PROC_ADDR_WPC(pcap_setbuff);
    }
    return 0;
}

#define GET_PROC_ADDR_PKT(_funcname_) do {  \
    LPVOID * ptr = (LPVOID *)&wpc->_funcname_;  \
    LPVOID addr = (LPVOID) GetProcAddress(wpc->pkt.hModule, #_funcname_);  \
    if (!addr)          \
        return -2;      \
    *ptr = addr;        \
} while(0)

__forceinline
int wpcap_get_pkt_func(struct wpcap_dyn * wpc)
{
    if (!wpc->pkt.hModule)
        return -1;
    GET_PROC_ADDR_PKT(PacketGetVersion);
    GET_PROC_ADDR_PKT(PacketGetDriverVersion);
    GET_PROC_ADDR_PKT(PacketGetAdapterNames);
    return 0;
}

__inline
int wpcap_get_adapters(struct wpcap_dyn * wpc)
{
    BOOL x;
    ULONG bufSize;
    char * p;

    if (wpc->pkt.adp_list)
        free(wpc->pkt.adp_list);
    wpc->pkt.adp_list = NULL;
    wpc->pkt.adp_count = 0;
    bufSize = 0;
    x = wpc->PacketGetAdapterNames(NULL, &bufSize);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        return -1;
    if (bufSize < 5)
        return 0;
    wpc->pkt.adp_list = (char *) malloc(bufSize + 16);
    if (!wpc->pkt.adp_list)
        return -2;
    memset(wpc->pkt.adp_list, 0, bufSize + 16);
    x = wpc->PacketGetAdapterNames(wpc->pkt.adp_list, &bufSize);
    if (!x) {
        free(wpc->pkt.adp_list);
        wpc->pkt.adp_list = NULL;
        return -3;
    }
    p = wpc->pkt.adp_list;
    while (1) {
        size_t len = strlen(p);
        if (len == 0)
            break;
        wpc->pkt.adp_count++;
        p += len + 1;
    }
    return wpc->pkt.adp_count;
}

__inline
int wpcap_free(struct wpcap_dyn * wpc)
{
    if (wpc) {
        if (wpc->pkt.adp_list)
            free(wpc->pkt.adp_list);
        if (wpc->wpc.devlist && wpc->pcap_freealldevs)
            wpc->pcap_freealldevs(wpc->wpc.devlist);
        if (wpc->wpc.hModule && wpc->wpc.filename[0])
            FreeLibrary(wpc->wpc.hModule);
        if (wpc->pkt.hModule && wpc->pkt.filename[0])
            FreeLibrary(wpc->pkt.hModule);
        free(wpc);
    }
    return 0;
}

__inline
int wpcap_find_module(LPCWSTR modfile, LPWSTR out, size_t outLen)
{
    int hr = -1;
    LPWSTR filename = (LPWSTR) modfile;
    WCHAR tmp[MAX_PATH];
    size_t len;
    LPWSTR p;
    HMODULE hMod = NULL;
    DWORD nSize, dw;
    BOOL x;

    WPCAP_GOTO_EXIT_IF(!out || outLen < MAX_PATH, -70);
    memset(out, 0, outLen * sizeof(out[0]));
    WPCAP_GOTO_EXIT_IF(wcslen(filename) < 3, -71);
    WPCAP_GOTO_EXIT_IF(wcslen(filename) >= MAX_PATH, -72);
    p = wcsrchr(filename, L'\\');
    if (!p) {
        WPCAP_GOTO_EXIT_IF(wcslen(filename) > 32, -73); 
        x = GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)wpcap_find_module, &hMod);
        WPCAP_GOTO_EXIT_IF(x == FALSE, -74); 
        memset(tmp, 0, sizeof(tmp));
        nSize = _countof(tmp) - 1;
        SetLastError(ERROR_SUCCESS);
        dw = GetModuleFileNameW(hMod, tmp, nSize);
        WPCAP_GOTO_EXIT_IF(dw < 3, -75);
        WPCAP_GOTO_EXIT_IF(GetLastError() == ERROR_INSUFFICIENT_BUFFER, -76);
        WPCAP_GOTO_EXIT_IF(dw == nSize, -77);
        p = (LPWSTR) wcsrchr(tmp, L'\\');
        WPCAP_GOTO_EXIT_IF(!p, -78);
        p[1] = 0;
        len = wcslen(tmp);
        WPCAP_GOTO_EXIT_IF(len < 3, -78);
        WPCAP_GOTO_EXIT_IF(len + 1 + wcslen(filename) + 1 >= _countof(tmp), -79);
        wcscat(tmp, filename);
        if (GetFileAttributesW(tmp) == INVALID_FILE_ATTRIBUTES) {   // try System directory
            memset(tmp, 0, sizeof(tmp));
#ifdef _WIN64
            len = GetSystemDirectoryW(tmp, _countof(tmp) - 1);
#else
            {
                BOOL wow64proc = FALSE;
                x = IsWow64Process(GetCurrentProcess(), &wow64proc);
                if (x && wow64proc) {
                    len = GetSystemWow64DirectoryW(tmp, _countof(tmp) - 1);
                } else {
                    len = GetSystemDirectoryW(tmp, _countof(tmp) - 1);
                }
            }
#endif
            WPCAP_GOTO_EXIT_IF(len < 3, -80);
            len = wcslen(tmp);
            WPCAP_GOTO_EXIT_IF(len < 3, -80);
            if (tmp[len] == L'\\')
                tmp[len] = 0;
            WPCAP_GOTO_EXIT_IF(len + 1 + wcslen(filename) + 1 >= _countof(tmp), -81);
            wcscat(tmp, L"\\");
            wcscat(tmp, filename);
        }
        filename = tmp;
    }
    if (wcsncmp(filename, L"\\\\?\\", 4) == 0)
        filename += 4;
    WPCAP_GOTO_EXIT_IF(wcslen(filename) < 3, -82);
    WPCAP_GOTO_EXIT_IF(filename[1] != L':' || filename[2] != L'\\', -83);
    WPCAP_GOTO_EXIT_IF(GetFileAttributesW(filename) == INVALID_FILE_ATTRIBUTES, -84);
    wcscpy(out, filename);
    hr = 0;

exit:
    return hr;
}

__inline
int wpcap_load(const wchar_t * modfile, struct wpcap_dyn ** wpc)
{
    int hr = -1;
    struct wpcap_dyn * api = NULL;
    WCHAR dlldir[MAX_PATH];
    WCHAR filename[MAX_PATH];
    size_t len;
    LPWSTR p;
    char * str;

    WPCAP_GOTO_EXIT_IF(!wpc, -1);
    *wpc = NULL;
    api = (struct wpcap_dyn *) malloc(sizeof(*api));
    WPCAP_GOTO_EXIT_IF(!api, -2);
    memset(api, 0, sizeof(*api));

    if (modfile == WPCAP_LOAD_DLL_FROM_MEM) {
        HMODULE hModWpcap = GetModuleHandleW(L"wpcap.dll");
        HMODULE hModPacket = GetModuleHandleW(L"packet.dll");
        if (hModWpcap && hModPacket) {
            api->pkt.hModule = hModPacket;
            api->wpc.hModule = hModWpcap;
        }
        modfile = NULL;
    }
    if (!api->pkt.hModule) {
        if (!modfile)
            modfile = L"wpcap.dll";
        hr = wpcap_find_module(modfile, filename, MAX_PATH);
        WPCAP_GOTO_EXIT_IF(hr, hr);

        p = wcsrchr(filename, L'\\');
        WPCAP_GOTO_EXIT_IF(!p, -14);
        len = ((size_t)p - (size_t)filename) / sizeof(WCHAR);
        WPCAP_GOTO_EXIT_IF(len > MAX_PATH - 32, -15);
        memset(dlldir, 0, sizeof(dlldir));
        wcsncpy(dlldir, filename, len);

        wcscpy(api->wpc.filename, filename);
        wcscpy(api->pkt.filename, dlldir);
        wcscat(api->pkt.filename, L"\\");
        wcscat(api->pkt.filename, L"packet.dll");
        WPCAP_GOTO_EXIT_IF(GetFileAttributesW(api->pkt.filename) == INVALID_FILE_ATTRIBUTES, -18);

        WPCAP_GOTO_EXIT_IF(SetDllDirectoryW(dlldir) == FALSE, -19);
        api->pkt.hModule = LoadLibraryExW(api->pkt.filename, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (api->pkt.hModule)
            api->wpc.hModule = LoadLibraryExW(api->wpc.filename, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
        SetDllDirectoryW(NULL);
        WPCAP_GOTO_EXIT_IF(!api->pkt.hModule, -21);
        WPCAP_GOTO_EXIT_IF(!api->wpc.hModule, -22);
    }

    hr = wpcap_get_pkt_func(api);
    WPCAP_GOTO_EXIT_IF(hr, -30);

    str = api->PacketGetVersion();
    WPCAP_GOTO_EXIT_IF(!str, -31);
    strncpy(api->pkt.version, str, sizeof(api->pkt.version) - 1);

    str = api->PacketGetDriverVersion();
    WPCAP_GOTO_EXIT_IF(!str, -32);
    strncpy(api->drv.version, str, sizeof(api->drv.version) - 1);

    strcpy(api->drv.name, "NPF");

    hr = wpcap_get_adapters(api);
    WPCAP_GOTO_EXIT_IF(hr < 0, -40);

    hr = wpcap_get_func(api, WPCAP_FLT_PRIMARY);
    WPCAP_GOTO_EXIT_IF(hr, -50);

    str = (char *) api->pcap_lib_version();
    WPCAP_GOTO_EXIT_IF(!str, -51);
    strncpy(api->wpc.version, str, sizeof(api->wpc.version) - 1);

    hr = 0;
    *wpc = api;

exit:
    if (hr && api)
        wpcap_free(api);
    return hr;
}

__inline
int wpcap_enum_iface(struct wpcap_dyn * wpc)
{
    int hr = -1;
    int dcnt = 0;
    pcap_if_t * alldevs = NULL;
    pcap_if_t * dev;

    WPCAP_GOTO_EXIT_IF(!wpc->wpc.hModule, -100);
    WPCAP_GOTO_EXIT_IF(!wpc->pcap_findalldevs, -101);
    if (wpc->wpc.devlist)
        wpc->pcap_freealldevs(alldevs);
    wpc->wpc.devlist = NULL;

    hr = wpc->pcap_findalldevs(&alldevs, wpc->wpc.errbuf);
    WPCAP_GOTO_EXIT_IF(hr < 0, -110);
    for (dev=alldevs; dev; dev = dev->next) {
        dcnt++;
    }
    wpc->wpc.devlist = alldevs;
    hr = 0;

exit:
    return hr < 0 ? hr : dcnt;
}

