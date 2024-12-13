#pragma once

#include "pcap.h"

struct wpcap_dyn_drv {
    WCHAR   filename[MAX_PATH];
    char    version[64];
    char    name[16];
};

struct wpcap_dyn_pkt {
    WCHAR   filename[MAX_PATH];
    HMODULE hModule;
    char    version[64];
    char  * adp_list;
    int     adp_count;
};

struct wpcap_dyn_wpc {
    WCHAR   filename[MAX_PATH];
    HMODULE hModule;
    char    version[64];
    pcap_if_t * devlist;
    char    errbuf[PCAP_ERRBUF_SIZE + 1];
};

struct wpcap_dyn {
  struct wpcap_dyn_drv drv;
  struct wpcap_dyn_pkt pkt;
  struct wpcap_dyn_wpc wpc;

  PacketGetVersion_t           PacketGetVersion;
  PacketGetDriverVersion_t     PacketGetDriverVersion;
  PacketGetAdapterNames_t      PacketGetAdapterNames;

  Pcap_lookupdev               pcap_lookupdev;
  Pcap_lookupnet               pcap_lookupnet;

  Pcap_create                  pcap_create;
  Pcap_set_snaplen             pcap_set_snaplen;
  Pcap_set_promisc             pcap_set_promisc;
  Pcap_can_set_rfmon           pcap_can_set_rfmon;
  Pcap_set_rfmon               pcap_set_rfmon;
  Pcap_set_timeout             pcap_set_timeout;
  Pcap_set_buffer_size         pcap_set_buffer_size;
  Pcap_activate                pcap_activate;

  Pcap_open_live                             pcap_open_live;
  Pcap_open_dead                             pcap_open_dead;
  Pcap_open_offline                          pcap_open_offline;
  Pcap_hopen_offline                         pcap_hopen_offline;

  Pcap_close                 pcap_close;
  Pcap_loop                  pcap_loop;
  Pcap_dispatch              pcap_dispatch;
  Pcap_next                  pcap_next;
  Pcap_next_ex               pcap_next_ex;
  Pcap_breakloop             pcap_breakloop;
  Pcap_stats                 pcap_stats;
  Pcap_setfilter             pcap_setfilter;
  Pcap_setdirection          pcap_setdirection;
  Pcap_getnonblock           pcap_getnonblock;
  Pcap_setnonblock           pcap_setnonblock;
  Pcap_inject                pcap_inject;
  Pcap_sendpacket            pcap_sendpacket;
  Pcap_statustostr           pcap_statustostr;
  Pcap_strerror              pcap_strerror;
  Pcap_geterr                pcap_geterr;
  Pcap_perror                pcap_perror;
  Pcap_compile               pcap_compile;
  Pcap_compile_nopcap        pcap_compile_nopcap;
  Pcap_freecode              pcap_freecode;
  Pcap_offline_filter        pcap_offline_filter;
  Pcap_datalink              pcap_datalink;
  Pcap_datalink_ext          pcap_datalink_ext;
  Pcap_list_datalinks        pcap_list_datalinks;
  Pcap_set_datalink          pcap_set_datalink;
  Pcap_free_datalinks        pcap_free_datalinks;
  Pcap_datalink_name_to_val         pcap_datalink_name_to_val;
  Pcap_datalink_val_to_name         pcap_datalink_val_to_name;
  Pcap_datalink_val_to_description  pcap_datalink_val_to_description;
  Pcap_snapshot              pcap_snapshot;
  Pcap_is_swapped            pcap_is_swapped;
  Pcap_major_version         pcap_major_version;
  Pcap_minor_version         pcap_minor_version;

  Pcap_file                  pcap_file;
  Pcap_fileno                pcap_fileno;

  Pcap_dump_open             pcap_dump_open;
  Pcap_dump_fopen            pcap_dump_fopen;
  Pcap_dump_file             pcap_dump_file;
  Pcap_dump_ftell            pcap_dump_ftell;
  Pcap_dump_flush            pcap_dump_flush;
  Pcap_dump_close            pcap_dump_close;
  Pcap_dump                  pcap_dump;

  Pcap_findalldevs           pcap_findalldevs;
  Pcap_freealldevs           pcap_freealldevs;

  Pcap_lib_version           pcap_lib_version;

  Bpf_filter                 bpf_filter;
  Bpf_validate               bpf_validate;
  Bpf_image                  bpf_image;
  Bpf_dump                   bpf_dump;

  Pcap_setbuff               pcap_setbuff;
  Pcap_setmode               pcap_setmode;
  Pcap_setmintocopy          pcap_setmintocopy;

  Pcap_sendqueue_alloc       pcap_sendqueue_alloc;
  Pcap_sendqueue_destroy     pcap_sendqueue_destroy;
  Pcap_sendqueue_queue       pcap_sendqueue_queue;
  Pcap_sendqueue_transmit    pcap_sendqueue_transmit;
  Pcap_getevent              pcap_getevent;
  Pcap_stats_ex              pcap_stats_ex;
  Pcap_setuserbuffer         pcap_setuserbuffer;
  Pcap_live_dump             pcap_live_dump;
  Pcap_live_dump_ended       pcap_live_dump_ended;
  Pcap_start_oem             pcap_start_oem;
  Pcap_get_airpcap_handle    pcap_get_airpcap_handle;

  Pcap_open                  pcap_open;
  Pcap_createsrcstr          pcap_createsrcstr;
  Pcap_parsesrcstr           pcap_parsesrcstr;
  Pcap_findalldevs_ex        pcap_findalldevs_ex;
  Pcap_setsampling           pcap_setsampling;
  Pcap_remoteact_accept      pcap_remoteact_accept;
  Pcap_remoteact_list        pcap_remoteact_list;
  Pcap_remoteact_close       pcap_remoteact_close;
  Pcap_remoteact_cleanup     pcap_remoteact_cleanup;
};

