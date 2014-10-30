/* -*- coding: utf-8-unix; -*- */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <stdint.h>
#include <grp.h>

#include <zmq.h>
#include <pcap.h>

#include "utils.h"

#define PROGNAME "pcap2zmq"

#define ZMQ_ADDR "ipc:///var/run/" PROGNAME "/" PROGNAME ".sock"

#define ZMQ_SOCKET_PERM 0660
#define ZMQ_SOCKET_GROUP "adm"

#define ZMQ_SEND_HWM 100000

#define PIDFILE "/var/run/" PROGNAME ".pid"

#define PCAP_STATS_INTERVAL 300

#define SNAP_LEN 1518


struct pcap_dev {
        char *device;
        pcap_t *handle;
        struct bpf_program filter_program;
        const char *filter;
        int fd;
        unsigned stat_counter;
};


struct bag {
        void *zmq_sock;
        int pcap_stats_interval;
        struct pcap_dev **pcaps;
        size_t pcaps_count;
};


// Network byte order (big-endian)
static
inline
void
copy_uint32(u_char *p, uint32_t i)
{
        p[0] = (i >> 24) & 0xff;
        p[1] = (i >> 16) & 0xff;
        p[2] = (i >> 8) & 0xff;
        p[3] = i & 0xff;
}


// Статистика pcap
static
void
pcap_accounting(const struct bag *bag, time_t time)
{
        static time_t stat_time = 0;

        if(stat_time == 0)
                stat_time = time;
        
        if(time < stat_time + bag->pcap_stats_interval)
                return;
        
        for (int i = 0; i < bag->pcaps_count; i++) {
                struct pcap_dev *pcap = bag->pcaps[i];

                struct pcap_stat ps;
                if(-1 == pcap_stats(pcap->handle, &ps))
                        errexit("Couldn't get pcap statistic: %s",
                                pcap_geterr(pcap->handle));

                int time_passed = time - stat_time;
                int pkt_received = ps.ps_recv - pcap->stat_counter;
                int speed = pcap->stat_counter > 0 && time_passed > 0 ?
                        pkt_received / time_passed : -1;
  
                logmsg(LOG_INFO, "%s recv: %d drop: %d ifdrop: %d speed: %d pkt/s",
                       pcap->device,
                       ps.ps_recv, ps.ps_drop, ps.ps_ifdrop, speed);

                pcap->stat_counter = ps.ps_recv;
        }

        stat_time = time;
}


// Обработчик пакетов для pcap
static
void
got_packet(u_char *bag_, const struct pcap_pkthdr *header, const u_char *packet)
{
        size_t size;
        zmq_msg_t msg;
        u_char *p;

        struct bag *bag = (struct bag*) bag_;
  
        size = header->caplen + 4 + 4;

        if(-1 == zmq_msg_init_size(&msg, size))
                syserr("zmq_msg_init_size()");

        p = zmq_msg_data(&msg);

        copy_uint32(p, header->ts.tv_sec); // Секунды
        copy_uint32(p + 4, header->ts.tv_usec); // Микросекунды
        memcpy(p + 8, packet, header->caplen); // Пакет

        if(size != zmq_msg_send(&msg, bag->zmq_sock, 0))
                syserr("zmq_msg_send()");

        zmq_msg_close(&msg);
        
        pcap_accounting(bag, header->ts.tv_sec);
}


// Установка прав доступа к сокету
static
void
fix_socket_perm(const char *addr, const char *group, mode_t mode)
{
        const char *path;
        static const char *ipc = "ipc://";
        struct stat st;
        struct group *gr;
  
        if(addr != strstr(addr, ipc))
                return;
  
        path = addr + strlen(ipc);

        if(-1 == stat(path, &st))
                syserr("stat()");
  
        if(!S_ISSOCK(st.st_mode))
                errexit("'%s' not a socket", path);

        if(NULL == (gr = getgrnam(group)))
                syserr("getgrnam()");
  
        if(0 != chown(path, getuid(), gr->gr_gid))
                syserr("chown()");
  
        if(0 != chmod(path, mode))
                syserr("chmod()");
        
        /* if(-1 == stat(path, &st)) */
        /*   syserr("stat()"); */
  
        /* logdbg("ipc path: %s uid: %d gid: %d mode: %o", */
        /*        path, st.st_uid, st.st_gid, st.st_mode); */
}


static
struct pcap_dev*
open_pcap_dev(const char *arg)
{
        struct pcap_dev *pcap = malloc(sizeof(struct pcap_dev));
        
        char *p = strchr(arg, ',');
        if (p == NULL)
                errexit("Invalid capture format");

        size_t device_len = p - arg;
        pcap->device = malloc(device_len + 1);
        memcpy(pcap->device, arg, device_len);
        pcap->device[device_len] = 0;
        
        // const char *filter_text = p+1;
        pcap->filter = strdup(p+1);
        
        char errbuf[PCAP_ERRBUF_SIZE];
        if(NULL == (pcap->handle = pcap_open_live(pcap->device, SNAP_LEN, 1, 1000, errbuf)))
                errexit("Couldn't open device %s: %s", pcap->device, errbuf);

        // struct bpf_program filter_program;
        
        if(-1 == pcap_compile(pcap->handle, &pcap->filter_program, pcap->filter, 0, 0))
                errexit("Couldn't parse filter %s: %s",
                        pcap->filter, pcap_geterr(pcap->handle));
  
        if(-1 == pcap_setfilter(pcap->handle, &pcap->filter_program))
                errexit("Couldn't install filter '%s': %s",
                        pcap->filter, pcap_geterr(pcap->handle));
        
        // printf("%s: %s\n", pcap->device, pcap->filter);
        
        pcap->fd = pcap_get_selectable_fd(pcap->handle);
        
        pcap->stat_counter = 0;
        
        return pcap;
}


// main program
int
main(int argc, char *argv[])
{
        size_t pcaps_size = 10;
        struct pcap_dev **pcaps = malloc(pcaps_size * sizeof(struct pcap_dev*));
        size_t pcaps_count = 0;
        int fdmax = 0;

        void *zmq_context;
        void *zmq_sock;
        char *zmq_addr = ZMQ_ADDR;

        int opt;
        int background = 0;
        const char *pidfile = NULL;

        int sndhwm = ZMQ_SEND_HWM;

        int pcap_stats_interval = PCAP_STATS_INTERVAL;

        while((opt = getopt(argc, argv, "z:s:dP:c:")) != -1) {

                switch(opt) {

                case 'c':
                        
                        if (pcaps_count == pcaps_size) {
                                pcaps_size *= 2;
                                pcaps = realloc(pcaps, pcaps_size * sizeof(struct pcap_dev*));
                        }
                        
                        struct pcap_dev *pcap = open_pcap_dev(optarg);

                        if (fdmax < pcap->fd)
                                fdmax = pcap->fd;

                        pcaps[pcaps_count++] = pcap;

                        break;

                case 'z':
                        zmq_addr = strdup(optarg);
                        break;

                case 's':
                        pcap_stats_interval = atoi(optarg);
                        if(pcap_stats_interval == 0) {
                                logmsg(LOG_ERR, "-s %s", optarg);
                                goto usage;
                        }
                        break;
                        
                case 'd':
                        background = 1;
                        break;

                case 'P':
                        pidfile = strdup(optarg);
                        break;

                default: /* '?' */
                        logmsg(LOG_ERR, "unknown key");
                        goto usage;
                }
        }
        
        if (pcaps_count == 0)
                errexit("No interfaces given");

        if(background)
                daemonize(PROGNAME);
  
        if (pidfile) {
                FILE *f = fopen(pidfile, "w");
                if (f == NULL)
                        errexit("Cannot write pidfile. Error occurred during fopen(%s): %s", pidfile, strerror(errno));
                fprintf(f, "%d\n", getpid());
                fclose(f);
        }
  
        // Инициализирование zeromq
        if(NULL == (zmq_context = zmq_ctx_new()))
                syserr("zmq_ctx_new()");
  
        if(NULL == (zmq_sock = zmq_socket(zmq_context, ZMQ_PUB)))
                syserr("zmq_socket()");

        zmq_setsockopt(zmq_sock, ZMQ_SNDHWM, &sndhwm, sizeof sndhwm);
  
        if(-1 == zmq_bind(zmq_sock, zmq_addr))
                syserr("zmq_bind()");

        fix_socket_perm(zmq_addr, ZMQ_SOCKET_GROUP, ZMQ_SOCKET_PERM);

        for (int i = 0; i < pcaps_count; i++)
                logmsg(LOG_INFO, "interface %d: %s, filter: %s", i, pcaps[i]->device, pcaps[i]->filter);
        logmsg(LOG_INFO, "zmq socket: %s", zmq_addr);
        logmsg(LOG_INFO, "pcap stats interval: %d", pcap_stats_interval);

        struct bag bag;
        bag.pcap_stats_interval = pcap_stats_interval;
        bag.zmq_sock = zmq_sock;
        bag.pcaps = pcaps;
        bag.pcaps_count = pcaps_count;
        
        // Рабочий цикл
        for (;;) {
                fd_set rfds;
                FD_ZERO(&rfds);
                for (int i = 0; i < pcaps_count; i++)
                        FD_SET(pcaps[i]->fd, &rfds);
                int rc = select(fdmax+1, &rfds, NULL, NULL, NULL);
                if (rc == -1)
                        syserr("select()");
                if (rc == 0 || rc < 0)
                        continue;
                for (int i = 0; i < pcaps_count; i++) {
                        struct pcap_dev *pcap = pcaps[i];
                        if (!FD_ISSET(pcap->fd, &rfds))
                                continue;
                        int maxcnt = -1;
                        void *user_data = &bag;
                        int prc = pcap_dispatch(pcap->handle, maxcnt, got_packet, user_data);
                        if (prc == -1)
                                errexit("pcap_dispatch(): %s", pcap_geterr(pcap->handle));
                        if (prc < 0)
                                errexit("pcap_dispatch(): unknown error");
                }
        }
  
        // Освобождение
        // pcap_freecode(&filter_program);
        // pcap_close(pcap_handle);

        /* zmq_close(zmq_sock); */
        /* zmq_ctx_destroy(zmq_context); */

        return 0;

 usage:
        fprintf(stderr, "Usage: %s -c 'interface,filter' [-c 'interface,filter' ...] [-s nsecs]\n", argv[0]);
        return -1;
}

