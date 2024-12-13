#include <winsock2.h>
#include <windows.h>
#include <stdarg.h>
#include <stdio.h>
#include <tchar.h>
#include <shlwapi.h>

#include "pcap.h"
#include "xgetopt.h"

struct wpcap_dyn * wpc = NULL;

#define OPTLIST "m:", /* speciefied module name */  \
                "v",  /* show installed version WinPCap */  \
                "x:", /* show device name by device number */  \
                "s",  /* show all devices name and ip address */  \
                 0

typedef enum out_mode {
    omUnknown = 0,
    omEnum,
    omVersion,
    omGetId,
};

const char * get_file_name(const char * path)
{
    const char * n = strrchr(path, '\\');
    return n ? n+1 : path;
}

int wmain(int argc, wchar_t ** argv)
{
    int hr = -1;
    int ret;
    out_mode mode = omUnknown;
    int output_ver = 0;
    int iface_id = -1;
    int short_info = 0;
    LPWSTR modname = NULL;
    char ntop_buf[INET6_ADDRSTRLEN];

    while ((ret = getoptExW(argc, argv, OPTLIST)) != EOF) {
        switch (ret) {
        case 'm':
            modname = optargW;
            break;
        case 'v':
            output_ver = 1;
            break;
        case 's':
            short_info = 1;
            break;
        case 'x':
            mode = omGetId;
            iface_id = _wtoi(optargW);
            break;
        default:
            return 1;   // error
        }
    }
    if (mode == omUnknown)
        mode = omEnum;

    hr = wpcap_load(modname, &wpc);
    if (hr) {
        printf("ERROR: can't load wpcap.dll (err = %d) \n", hr);
        return hr;
    }
    if (output_ver) {
        printf("%s\n", wpc->wpc.version);
        WPCAP_GOTO_EXIT_IF(1, 0);
    }
    hr = wpcap_enum_iface(wpc);
    if (hr < 0) {
        printf("ERROR: can't init wpcap.dll (err = %d) \n", hr);
        WPCAP_GOTO_EXIT_IF(1, hr);
    }
    if (mode == omEnum) {
        printf("Devices: %d\n\n", hr);
        WPCAP_GOTO_EXIT_IF(hr == 0, 1);
    }

    int id = 0;
    pcap_if_t * alldevs = wpc->wpc.devlist;
    for (pcap_if_t * dev=alldevs; dev; dev = dev->next) {
        id++;
        if (mode == omGetId) {
            if (id != iface_id) continue;
            printf("%s\n", get_file_name(dev->name));
            WPCAP_GOTO_EXIT_IF(1, 0);
        }

        if (short_info) {
            char * ip_addr = NULL;
            for (pcap_addr_t * a=dev->addresses; a ; a = a->next) {
                if (a->addr && a->addr->sa_family == AF_INET) {
                    ip_addr = inet_ntoa(((struct sockaddr_in *)(a->addr))->sin_addr);
                    break;
                }
            }
            printf("%d: %s %s\n", id, get_file_name(dev->name), ip_addr ? ip_addr : "");
            continue;
        }

        printf("%d: %s\n", id, dev->name);
        if (dev->description)
            printf("\tDesc: %s\n",dev->description);

        for (pcap_addr_t * a=dev->addresses; a ; a = a->next) {
            if (!a->addr)
                continue;
            switch(a->addr->sa_family) {
            case AF_INET:
                printf("\t%s\t\t", inet_ntoa(((struct sockaddr_in *)(a->addr))->sin_addr));
                if (a->netmask)
                    printf(" [%s]\t", inet_ntoa(((struct sockaddr_in *)(a->netmask))->sin_addr));
                if (a->broadaddr)
                    printf(" (%s)\t", inet_ntoa(((struct sockaddr_in *)(a->broadaddr))->sin_addr));
                if (a->dstaddr)
                    printf(" {%s}\t", inet_ntoa(((struct sockaddr_in *)(a->dstaddr))->sin_addr)); 
                printf("\n");
                break;
            case AF_INET6:
                printf("\t%s\t", inet_ntop(AF_INET6, ((struct sockaddr_in6 *)(a->addr))->sin6_addr.s6_addr, ntop_buf, sizeof ntop_buf));
                if (a->netmask)
                    printf(" [%s]\t", inet_ntop(AF_INET6, ((struct sockaddr_in6 *)(a->netmask))->sin6_addr.s6_addr, ntop_buf, sizeof ntop_buf));
                if (a->broadaddr)
                    printf(" (%s)\t", inet_ntop(AF_INET6, ((struct sockaddr_in6 *)(a->broadaddr))->sin6_addr.s6_addr, ntop_buf, sizeof ntop_buf));
                if (a->dstaddr)
                    printf(" {%s}\t", inet_ntop(AF_INET6, ((struct sockaddr_in6 *)(a->dstaddr))->sin6_addr.s6_addr, ntop_buf, sizeof ntop_buf));
                printf("\n");
                break;
            default:
                printf("\tAddress Family: Unknown (%d)\n", a->addr->sa_family);
                break;
            }
        }
        printf("\n");
    }

    hr = 0;
    if (mode == omGetId) {
        hr = 1;   // error
    }

exit:
    if (wpc)
        wpcap_free(wpc);
    return (hr == 0) ? 0 : 1;
}

