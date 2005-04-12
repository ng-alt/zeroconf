/*
 * Simple IPv4 Link-Local addressing (see <http://www.zeroconf.org/>)
 * @(#)llip.c, 1.5, Copyright 2003 by Arthur van Hoff (avh@strangeberry.com)
 * Copyright 2005 (c) Anand Kumria 
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * See <http://www.gnu.org/copyleft/lesser.html>
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/poll.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define LINKLOCAL_ADDR          0xa9fe0000
#define LINKLOCAL_MASK          0xFFFF0000
#define NPROBES                 3
#define PROBE_INTERVAL          200
#define NCLAIMS                 3
#define CLAIM_INTERVAL          200
#define FAILURE_INTERVAL        14000
#define DEFAULT_INTERFACE       "eth0"
#define DEFAULT_SCRIPT          "/etc/zeroconf"


static char *prog;
static int verbose = 0;

static struct in_addr null_ip = {0};
static struct ether_addr null_addr = {{0, 0, 0, 0, 0, 0}};
static struct ether_addr broadcast_addr = {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};

/**
 * ARP packet.
 */
struct arp_packet {
    struct ether_header hdr;
    struct arphdr arp;
    struct ether_addr source_addr;
    struct in_addr source_ip;
    struct ether_addr target_addr; 
    struct in_addr target_ip;
    unsigned char pad[18];
} __attribute__ ((__packed__));


/**
 * Convert an ethernet address to a printable string.
 */
static char *ether2str(const struct ether_addr *addr)
{
    static char str[32];
    snprintf(str, sizeof(str), "%02X:%02X:%02X:%02X:%02X:%02X",
             addr->ether_addr_octet[0], addr->ether_addr_octet[1],
             addr->ether_addr_octet[2], addr->ether_addr_octet[3],
             addr->ether_addr_octet[4], addr->ether_addr_octet[5]);
    return str;
}


/**
 * Pick a random link local IP address.
 */
static void pick(struct in_addr *ip)
{
    ip->s_addr = htonl(LINKLOCAL_ADDR | ((abs(random()) % 0xFD00) + 0x0100));
}

/**
 * Send out an ARP packet.
 */
static void arp(int fd, struct sockaddr *saddr, int op,
                struct ether_addr *source_addr, struct in_addr source_ip,
                struct ether_addr *target_addr, struct in_addr target_ip)
{
    struct arp_packet p;
    memset(&p, 0, sizeof(p));

    // ether header
    p.hdr.ether_type = htons(ETHERTYPE_ARP);
    memcpy(p.hdr.ether_shost, source_addr, ETH_ALEN);
    memcpy(p.hdr.ether_dhost, &broadcast_addr, ETH_ALEN);

    // arp request
    p.arp.ar_hrd = htons(ARPHRD_ETHER);
    p.arp.ar_pro = htons(ETHERTYPE_IP);
    p.arp.ar_hln = ETH_ALEN;
    p.arp.ar_pln = 4;
    p.arp.ar_op = htons(op);
    memcpy(&p.source_addr, source_addr, ETH_ALEN);
    memcpy(&p.source_ip, &source_ip, sizeof(p.source_ip));
    memcpy(&p.target_addr, target_addr, ETH_ALEN);
    memcpy(&p.target_ip, &target_ip, sizeof(p.target_ip));

    // send it
    if (sendto(fd, &p, sizeof(p), 0, saddr, sizeof(*saddr)) < 0) {
        perror("sendto failed");
        exit(1);
    }
}

/**
 * Run a script.
 */
static void run(char *script, const char *arg, char *intf, struct in_addr *ip)
{
    int pid, status;

    if (script != NULL) {
        if (verbose) {
            fprintf(stderr, "%s %s: run %s %s\n", prog, intf, script, arg);
        }
        pid = fork();
        if (pid < 0) {
            perror("fork failed");
            exit(1);
        }
        if (pid == 0) {
            // child process
            setenv("interface", intf, 1);
            if (ip != NULL) {
                setenv("ip", inet_ntoa(*ip), 1);
            }

            execl(script, script, arg, intf, NULL);
            perror("execl failed");
            exit(1);
        }
        if (waitpid(pid, &status, 0) <= 0) {
            perror("waitpid failed");
            exit(1);
        }
        if (WEXITSTATUS(status) != 0) {
            fprintf(stderr, "%s: script %s failed, exit=%d\n", prog, script, WEXITSTATUS(status));
            exit(1);
        }
    }
}

/**
 * Print usage information.
 */
static void usage(const char *msg)
{
    fprintf(stderr, "%s: %s\n\n", prog, msg);
    fprintf(stderr, "Usage: %s [OPTIONS]\n", prog);
    fprintf(stderr, " -v                verbose\n");
    fprintf(stderr, " -q                quit after obtaining address\n");
    fprintf(stderr, " -f                do not fork a daemon\n");
    fprintf(stderr, " -n                exit with failure if no address can be obtained\n");
    fprintf(stderr, " -i <interface>    network interface (default %s)\n", DEFAULT_INTERFACE);
    fprintf(stderr, " -s <script>       network script (default %s)\n", DEFAULT_SCRIPT);
    fprintf(stderr, " -ip 169.254.x.x   try this address first\n", DEFAULT_SCRIPT);
    exit(1);
}

/**
 * main program
 */
int main(int argc, char *argv[])
{
    char *intf = strdup(DEFAULT_INTERFACE);
    char *script = strdup(DEFAULT_SCRIPT);
    struct sockaddr saddr;
    struct pollfd fds[1];
    struct arp_packet p;
    struct ifreq ifr;
    struct ether_addr addr;
    struct timeval tv;
    struct in_addr ip = {0};
    int fd;
    int quit = 0;
    int ready = 0;
    int foreground = 0;
    int timeout = 0;
    int nprobes = 0;
    int nclaims = 0;
    int failby = 0;
    int i = 1;

    // init
    gettimeofday(&tv, NULL);
    prog = argv[0];

    // parse arguments
    while (i < argc) {
        char *arg = argv[i++];
        if (strcmp(arg, "-q") == 0) {
            quit = 1;
        } else if (strcmp(arg, "-f") == 0) {
            foreground = 1;
        } else if (strcmp(arg, "-v") == 0) {
            verbose = 1;
        } else if (strcmp(arg, "-n") == 0) {
            failby = time(0) + FAILURE_INTERVAL / 1000;
        } else if (strcmp(arg, "-i") == 0) {
  	    free(intf);
            if ((intf = argv[i++]) == NULL) {
                usage("interface name missing");
            }
        } else if (strcmp(arg, "-s") == 0) {
            free(script);
            if ((script = argv[i++]) == NULL) {
                usage("script missing");
            }
        } else if (strcmp(arg, "-ip") == 0) {
            char *ipstr = argv[i++];
            if (ipstr == NULL) {
                usage("ip address missing");
            }
            if (inet_aton(ipstr, &ip) == 0) {
                usage("invalid ip address");
            }
            if ((ntohl(ip.s_addr) & LINKLOCAL_MASK) != LINKLOCAL_ADDR) {
                usage("invalid linklocal address");
            }
        } else {
            usage("invald argument");
        }
    }

    // initialize saddr
    memset(&saddr, 0, sizeof(saddr));
    strncpy(saddr.sa_data, intf, sizeof(saddr.sa_data));

    // open an ARP socket
    if ((fd = socket(PF_PACKET, SOCK_PACKET, htons(ETH_P_ARP))) < 0) {
        perror("open failed");
        exit(1);
    }

    // bind to the ARP socket
    if (bind(fd, &saddr, sizeof(saddr)) < 0) {
        perror("bind failed");
        exit(1);
    }

    // get the ethernet address of the interface
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, intf, sizeof(ifr.ifr_name));
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl failed");
        exit(1);
    }
    memcpy(&addr, &ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);

    // initialize the interface
    run(script, "init", intf, NULL);

    // initialize pseudo random selection of IP addresses
    srandom((addr.ether_addr_octet[ETHER_ADDR_LEN-4] << 24) |
            (addr.ether_addr_octet[ETHER_ADDR_LEN-3] << 16) |
            (addr.ether_addr_octet[ETHER_ADDR_LEN-2] <<  8) |
            (addr.ether_addr_octet[ETHER_ADDR_LEN-1] <<  0));
    
    // pick an ip address
    if (ip.s_addr == 0) {
        pick(&ip);
    }

    // prepare for polling
    fds[0].fd = fd;
    fds[0].events = POLLIN | POLLERR;

    while (1) {
        if (verbose) {
            printf("%s %s: polling %d, nprobes=%d, nclaims=%d\n", prog, intf, timeout, nprobes, nclaims);
        }
        fds[0].revents = 0;
        switch (poll(fds, 1, timeout)) {
            case 0:
                // timeout
                if ((failby != 0) && (failby < time(0))) {
                    fprintf(stderr, "%s %s: failed to obtain address\n", prog, intf);
                    exit(1);
                }
                if (nprobes < NPROBES) {
                    // ARP probe
                    if (verbose) {
                        fprintf(stderr, "%s %s: ARP probe %s\n", prog, intf, inet_ntoa(ip));
                    }
                    arp(fd, &saddr, ARPOP_REQUEST, &addr, null_ip, &null_addr, ip);
                    nprobes++;
                    timeout = PROBE_INTERVAL;
                } else if (nclaims < NCLAIMS) {
                    // ARP claim
                    if (verbose) {
                        fprintf(stderr, "%s %s: ARP claim %s\n", prog, intf, inet_ntoa(ip));
                    }
                    arp(fd, &saddr, ARPOP_REQUEST, &addr, ip, &addr, ip);
                    nclaims++;
                    timeout = CLAIM_INTERVAL;
                } else {
                    // ARP take
                    if (verbose) {
                        fprintf(stderr, "%s %s: use %s\n", prog, intf, inet_ntoa(ip));
                    }
                    ready = 1;
                    timeout = -1;
                    failby = 0;
                    run(script, "config", intf, &ip);

                    if (quit) {
                        exit(0);
                    }
                    if (!foreground) {
                        if (daemon(0, 0) < 0) {
                            perror("daemon failed");
                            exit(1);
                        }
                    }
                }
                break;

            case 1:
                // i/o event
                if ((fds[0].revents & POLLIN) == 0) {
                    if (fds[0].revents & POLLERR) {
                        fprintf(stderr, "%s %s: I/O error\n", prog, intf);
                        exit(1);
                    }
                    continue;
                }

                // read ARP packet
                if (recv(fd, &p, sizeof(p), 0) < 0) {
                    perror("recv failed");
                    exit(1);
                }

                if (verbose) {
                    printf("%s %s: recv arp type=%d, op=%d, ", prog, intf, ntohs(p.hdr.ether_type), ntohs(p.arp.ar_op));
                    printf("source=%s %s,", ether2str(&p.source_addr), inet_ntoa(p.source_ip));
                    printf("target=%s %s\n", ether2str(&p.target_addr), inet_ntoa(p.target_ip));
                }

                if ((ntohs(p.hdr.ether_type) == ETHERTYPE_ARP) && (ntohs(p.arp.ar_op) == ARPOP_REPLY) &&
                    (p.target_ip.s_addr == ip.s_addr) && (memcmp(&addr, &p.target_addr, ETH_ALEN) != 0)) {

                    if (verbose) {
                        fprintf(stderr, "%s %s: ARP conflict %s\n", prog, intf, inet_ntoa(ip));
                    }

		    /* if we've already assigned the address, remove it 
		     * and grab another one and reset everything
		     */
                    if (ready) {
                        ready = 0;
                        run(script, "deconfig", intf, &ip);
                    }
                    pick(&ip);
                    timeout = 0;
                    nprobes = 0;
                    nclaims = 0;
                }
                break;

            default:
                perror("poll failed");
                exit(1);
        }
    }
}
