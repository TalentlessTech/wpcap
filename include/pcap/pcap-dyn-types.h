#pragma once

#include "pcap.h"

typedef char * (* PacketGetVersion_t) (void);
typedef char * (* PacketGetDriverVersion_t) (void);
typedef BOOLEAN (* PacketGetAdapterNames_t) (PCHAR pStr, PULONG BufferSize);

typedef char * (* Pcap_lookupdev) (char *);
typedef int (* Pcap_lookupnet) (const char *, bpf_u_int32 *, bpf_u_int32 *, char *);

typedef pcap_t * (* Pcap_create) (const char *, char *);
typedef int (* Pcap_set_snaplen) (pcap_t *, int);
typedef int (* Pcap_set_promisc) (pcap_t *, int);
typedef int (* Pcap_can_set_rfmon) (pcap_t *);
typedef int (* Pcap_set_rfmon) (pcap_t *, int);
typedef int (* Pcap_set_timeout) (pcap_t *, int);
typedef int (* Pcap_set_buffer_size) (pcap_t *, int);
typedef int (* Pcap_activate) (pcap_t *);

typedef pcap_t * (* Pcap_open_live) (const char *, int, int, int, char *);
typedef pcap_t * (* Pcap_open_dead) (int, int);
typedef pcap_t * (* Pcap_open_offline) (const char *, char *);
typedef pcap_t * (* Pcap_hopen_offline) (intptr_t, char *);

typedef void (* Pcap_close) (pcap_t *);
typedef int  (* Pcap_loop) (pcap_t *, int, pcap_handler, u_char *);
typedef int  (* Pcap_dispatch) (pcap_t *, int, pcap_handler, u_char *);
typedef const u_char * (* Pcap_next) (pcap_t *, struct pcap_pkthdr *);
typedef int  (* Pcap_next_ex) (pcap_t *, struct pcap_pkthdr **, const u_char **);
typedef void (* Pcap_breakloop) (pcap_t *);
typedef int  (* Pcap_stats) (pcap_t *, struct pcap_stat *);
typedef int  (* Pcap_setfilter) (pcap_t *, struct bpf_program *);
typedef int  (* Pcap_setdirection) (pcap_t *, pcap_direction_t);
typedef int  (* Pcap_getnonblock) (pcap_t *, char *);
typedef int  (* Pcap_setnonblock) (pcap_t *, int, char *);
typedef int  (* Pcap_inject) (pcap_t *, const void *, size_t);
typedef int  (* Pcap_sendpacket) (pcap_t *, const u_char *, int);
typedef const char * (* Pcap_statustostr) (int);
typedef const char * (* Pcap_strerror) (int);
typedef char * (* Pcap_geterr) (pcap_t *);
typedef void   (* Pcap_perror) (pcap_t *, const char *);
typedef int (* Pcap_compile) (pcap_t *, struct bpf_program *, const char *, int, bpf_u_int32);
typedef int (* Pcap_compile_nopcap) (int, int, struct bpf_program *, const char *, int, bpf_u_int32);
typedef void (* Pcap_freecode) (struct bpf_program *);
typedef int (* Pcap_offline_filter) (const struct bpf_program *, const struct pcap_pkthdr *, const u_char *);
typedef int (* Pcap_datalink) (pcap_t *);
typedef int (* Pcap_datalink_ext) (pcap_t *);
typedef int (* Pcap_list_datalinks) (pcap_t *, int **);
typedef int (* Pcap_set_datalink) (pcap_t *, int);
typedef void (* Pcap_free_datalinks) (int *);
typedef int (* Pcap_datalink_name_to_val) (const char *);
typedef const char * (* Pcap_datalink_val_to_name) (int);
typedef const char * (* Pcap_datalink_val_to_description) (int);
typedef int (* Pcap_snapshot) (pcap_t *);
typedef int (* Pcap_is_swapped) (pcap_t *);
typedef int (* Pcap_major_version) (pcap_t *);
typedef int (* Pcap_minor_version) (pcap_t *);

typedef FILE * (* Pcap_file) (pcap_t *);
typedef int    (* Pcap_fileno) (pcap_t *);

typedef pcap_dumper_t * (* Pcap_dump_open) (pcap_t *, const char *);
typedef pcap_dumper_t * (* Pcap_dump_fopen) (pcap_t *, FILE *fp);
typedef FILE * (* Pcap_dump_file) (pcap_dumper_t *);
typedef long (* Pcap_dump_ftell) (pcap_dumper_t *);
typedef int (* Pcap_dump_flush) (pcap_dumper_t *);
typedef void (* Pcap_dump_close) (pcap_dumper_t *);
typedef void (* Pcap_dump) (u_char *, const struct pcap_pkthdr *, const u_char *);

typedef int (* Pcap_findalldevs) (pcap_if_t **, char *);
typedef void (* Pcap_freealldevs) (pcap_if_t *);

typedef const char * (* Pcap_lib_version) (void);

typedef u_int  (* Bpf_filter) (const struct bpf_insn *, const u_char *, u_int, u_int);
typedef int    (* Bpf_validate) (const struct bpf_insn *f, int len);
typedef char * (* Bpf_image) (const struct bpf_insn *, int);
typedef void   (* Bpf_dump) (const struct bpf_program *, int);

typedef int (* Pcap_setbuff) (pcap_t *p, int dim);
typedef int (* Pcap_setmode) (pcap_t *p, int mode);
typedef int (* Pcap_setmintocopy) (pcap_t *p, int size);

typedef pcap_send_queue * (* Pcap_sendqueue_alloc) (u_int memsize);
typedef void (* Pcap_sendqueue_destroy) (pcap_send_queue* queue);
typedef int (* Pcap_sendqueue_queue) (pcap_send_queue* queue, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data);
typedef u_int (* Pcap_sendqueue_transmit) (pcap_t *p, pcap_send_queue* queue, int sync);
typedef HANDLE (* Pcap_getevent) (pcap_t *p);
typedef struct pcap_stat * (* Pcap_stats_ex) (pcap_t *p, int *pcap_stat_size);
typedef int (* Pcap_setuserbuffer) (pcap_t *p, int size);
typedef int (* Pcap_live_dump) (pcap_t *p, char *filename, int maxsize, int maxpacks);
typedef int (* Pcap_live_dump_ended) (pcap_t *p, int sync);
typedef int (* Pcap_start_oem) (char* err_str, int flags);
typedef PAirpcapHandle (* Pcap_get_airpcap_handle) (pcap_t *p);

typedef pcap_t * (* Pcap_open) (const char *source, int snaplen, int flags, int read_timeout, struct pcap_rmtauth *auth, char *errbuf);
typedef int (* Pcap_createsrcstr) (char *source, int type, const char *host, const char *port, const char *name, char *errbuf);
typedef int (* Pcap_parsesrcstr) (const char *source, int *type, char *host, char *port, char *name, char *errbuf);
typedef int (* Pcap_findalldevs_ex) (char *source, struct pcap_rmtauth *auth, pcap_if_t **alldevs, char *errbuf);
typedef struct pcap_samp * (* Pcap_setsampling) (pcap_t *p);
typedef SOCKET (* Pcap_remoteact_accept) (const char *address, const char *port, const char *hostlist, char *connectinghost, struct pcap_rmtauth *auth, char *errbuf);
typedef int (* Pcap_remoteact_list) (char *hostlist, char sep, int size, char *errbuf);
typedef int (* Pcap_remoteact_close) (const char *host, char *errbuf);
typedef void (* Pcap_remoteact_cleanup) (void);

