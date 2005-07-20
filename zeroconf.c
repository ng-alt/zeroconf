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
#define FAILURE_INTERVAL        14000
#define DEFAULT_INTERFACE       "eth0"
#define DEFAULT_SCRIPT          "/etc/zeroconf"

/* Constants from RFC3927 */
#define PROBE_WAIT           1 /*second   (initial random delay) */
#define PROBE_MIN            1 /*second   (minimum delay till repeated probe) */
#define PROBE_MAX            2 /*seconds  (maximum delay till repeated probe) */
#define PROBE_NUM            3 /*         (number of probe packets) */
#define ANNOUNCE_NUM         2 /*         (number of announcement packets) */
#define ANNOUNCE_INTERVAL    2 /*seconds  (time between announcement packets) */
#define ANNOUNCE_WAIT        2 /*seconds  (delay before announcing) */
#define MAX_CONFLICTS       10 /*         (max conflicts before rate limiting) */
#define RATE_LIMIT_INTERVAL 60 /*seconds  (delay between successive attempts) */
#define RATE_LIMIT_INTERVAL_APPLE 1 /*seconds  (delay between successive attempts) */
#define DEFEND_INTERVAL     10 /*seconds  (minimum interval between defensive ARPs). */

enum {
  ADDR_PROBE,
  ADDR_PROBE_WAIT,
  ADDR_PROBE_CONFLICT,
  ADDR_PROBE_RATELIMIT,
  ADDR_CLAIM,
  ADDR_TAKE,
  ADDR_DEFEND,
  ADDR_DEFEND_FINAL
};


static char *prog;
static int verbose = 0;
int conflict_count = 4; /* ak */ /* start off at 4 for APPLE */

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
  /* IPv4 LL address are in the 169.254.0.0/16 network
   * - but 169.254.0.0/24 and 169.254.255.0/24 are reserved
   * - leaving 65024 usable addresses
   */
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
  fprintf(stderr, " -ip 169.254.x.x   try this address first\n");
  exit(1);
}

static unsigned int gen_msec_timeout(unsigned int min_seconds, unsigned int max_seconds)
{
  unsigned int max_msec = max_seconds * 1000;
  unsigned int min_msec = min_seconds * 1000;

  return ((abs(random()) % (max_msec - min_msec)) + min_msec);
}

static int check_arp_conflict(int fd, 
			      const char* intf, 
			      struct in_addr ip,
			      struct ether_addr addr)
{
  struct arp_packet p;

  /* we might have a conflict */
  if (recv(fd, &p, sizeof(p), 0) < 0) {
    perror("recv failed");
    exit(1);
  }

  if (verbose) {
    printf("%s %s: recv arp type=%d, op=%d, ", prog, intf, ntohs(p.hdr.ether_type), ntohs(p.arp.ar_op));
    printf("source=%s %s,", ether2str(&p.source_addr), inet_ntoa(p.source_ip));
    printf("target=%s %s\n", ether2str(&p.target_addr), inet_ntoa(p.target_ip));
    printf("trying=%s\n",inet_ntoa(ip));
    printf("target=%s\n",ether2str(&addr));
  }

  /* two types of conflicts:
   *
   * 1. another node is also sending out a simultaneous probe for 
   * the address we are using - this is done via ARPOP_REQUEST
   * and it's source IP address will be null and the target IP address
   * will match (additionally the source hardware address will not be
   * our own -- in case of 'echoed' packets)
   *
   * 2. another node already has the same address - this is done via
   * ARPOP_REPLY with the source IP address set to our candidate IP
   * address. The target IP address will be broadcast, since we used
   * that in our probe, but it will be directed to our MAC address
   */

  if (ntohs(p.hdr.ether_type) != ETHERTYPE_ARP)
    return 0;

  /* okay an ARP packet, let's check more deeply */

  if (ntohs(p.arp.ar_op) == ARPOP_REQUEST) {

    /* conflict 1? */
    if ((p.source_ip.s_addr == null_ip.s_addr) &&
	(p.target_ip.s_addr == ip.s_addr)) {

      conflict_count++;
	
      return 1;
		
    }

  } else if (ntohs(p.arp.ar_op) == ARPOP_REPLY) {

    /* conflict 2? */
    if ((p.source_ip.s_addr == ip.s_addr) &&
	(p.target_ip.s_addr == null_ip.s_addr)) { /*&&
						    (memcmp(&addr, &p.target_addr, ETH_ALEN) != 0)) {*/

      conflict_count++;

      return 1;

    }

  } else {
    if (verbose) {
      printf("arp packet but didn't seem to be for us\n");
    }
  }
  return 0;
}

/* 
 * Subtract the `struct timeval' values X and Y,
 *  storing the result in RESULT.
 *  Return 1 if the difference is negative, otherwise 0.  
 *  taken from the GNU Lib C documentation
 */
static int
timeval_subtract(struct timeval *result, struct timeval *x, struct timeval *y)
{
  /* Perform the carry for the later subtraction by updating Y. */
  if (x->tv_usec < y->tv_usec) {
    int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
    y->tv_usec -= 1000000 * nsec;
    y->tv_sec += nsec;
  }
  if (x->tv_usec - y->tv_usec > 1000000) {
    int nsec = (x->tv_usec - y->tv_usec) / 1000000;
    y->tv_usec += 1000000 * nsec;
    y->tv_sec -= nsec;
  }

  /* 
   * Compute the time remaining to wait.
   *  `tv_usec' is certainly positive. 
   */
  result->tv_sec = x->tv_sec - y->tv_sec;
  result->tv_usec = x->tv_usec - y->tv_usec;

  /* Return 1 if result is negative. */
  return x->tv_sec < y->tv_sec;
}

static void reduce_timeout(int *timeout, struct timeval tv1)
{
  struct timeval result, tv2;

  gettimeofday(&tv2,NULL);

  /* timeout = timeout - tv2 - tv1; */

  timeval_subtract(&result, &tv2, &tv1);

  timeout = timeout - (result.tv_sec * 1000) - (result.tv_usec % 1000);

  /* we could have actually used up all our time too! */
  if (timeout < 0)
    timeout = 0;

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
  struct ifreq ifr;
  struct ether_addr addr;
  struct timeval tv;
  struct in_addr ip = {0};
  int fd; /* ak */
  int quit = 0;
  int ready = 0;
  int foreground = 0;
  int timeout = 0; /* ak */
  int nprobes = 0; /* ak */
  int nclaims = 0;
  int failby = 0;
  int notime = 0; /* ak */
  int ioevents = 0; /* ak */
  int next_state = 0; /* ak */
  int i = 1;
  int zeroconf_state = ADDR_PROBE; /* ak */

  // init
  prog = argv[0];

  /* parse arguments */
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
      usage("invalid argument");
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

  /* RFC 2.2.1
   * initial timeout is between 0 and PROBE_WAIT seconds
   * FIXME: actually it is the amount we should wait before continuing;
   */
  timeout = gen_msec_timeout(0, PROBE_WAIT);

  // prepare for polling
  fds[0].fd = fd;
  fds[0].events = POLLIN | POLLERR;

  while (1) {
    if (verbose) {
      printf("%s %s: polling %d, nprobes=%d, nclaims=%d\n", prog, intf, timeout, nprobes, nclaims);
    }
    fds[0].revents = 0;
    gettimeofday(&tv,NULL);
    switch (poll(fds, 1, timeout)) {
    case 0: /* timeout */
      if (verbose) {
	fprintf(stderr, "%s: timeout\n", prog);
      }
      ioevents = 0;
      notime = 1;
      break;

    case 1: /* I/O events */
      if (verbose) {
	fprintf(stderr, "%s: ioevents\n", prog);
      }
      notime = 0;
      ioevents = 1;
      break;

    default:
      /* something odd, abort */
      fprintf(stderr, "%s: unexpect fd returned\n", prog);
      exit(1);
      break;
    }

    /* we use next_state to 'continue' to loop around so the
     * state machine.  Unless we say 'break' at the end, we
     * can put each action into a each state
     */
    next_state = 1;
    while (next_state) {

      switch (zeroconf_state) {
    
      case ADDR_PROBE:
	// ARP probe
	if (verbose) {
	  fprintf(stderr, "%s %s: ARP probe %s\n", prog, intf, inet_ntoa(ip));
	}

	arp(fd, &saddr, ARPOP_REQUEST, &addr, null_ip, &null_addr, ip);
	nprobes++;

	if (nprobes < PROBE_NUM) {
	  timeout = gen_msec_timeout(PROBE_MIN, PROBE_MAX);
	} else {
	  timeout = ANNOUNCE_WAIT * 1000;
	}

	zeroconf_state = ADDR_PROBE_WAIT;
	break;

      case ADDR_PROBE_WAIT:
	if (ioevents) {
	  if (check_arp_conflict(fd,intf,ip,addr)) {
	    zeroconf_state = ADDR_PROBE_CONFLICT;
	    continue;
	  } else {
	    reduce_timeout(&timeout, tv);
	  }
	}

	if (notime) {

	  /* excellent, nothing happened */
	  if (nprobes < PROBE_NUM) {

	    if (conflict_count < MAX_CONFLICTS) {
	      zeroconf_state = ADDR_PROBE;
	      continue;
	    } else {
	      zeroconf_state = ADDR_PROBE_RATELIMIT;
	      continue;
	    }

	  } else {
	    zeroconf_state = ADDR_CLAIM;
	    continue;
	  }

	}
	break;

      case ADDR_PROBE_CONFLICT:

	if (verbose) {
	  fprintf(stderr, "%s %s: ARP conflict %s (%d)\n", prog, intf, inet_ntoa(ip), conflict_count);
	}

	/* if we've already assigned the address, remove it 
	 * and grab another one and reset everything
	 */
	if (ready) {
	  ready = 0;
	  run(script, "deconfig", intf, &ip);
	}

	pick(&ip);

	/*
	 * resetting everything here will allow us to reuse the
	 * state logic in the PROBE_WAIT case
	 */
	nprobes = 0;
	nclaims = 0;
	ioevents = 0;
	timeout = 0;
	notime = 0;

	zeroconf_state = ADDR_PROBE_WAIT;
	continue;

	break;

      case ADDR_PROBE_RATELIMIT:

	/* too many conflicts, let's back off and keeping trying but slower */
	if (verbose) {
	  fprintf(stderr, "%s %s: ARP ratelimit probe %s\n", prog, intf, inet_ntoa(ip));
	}
	arp(fd, &saddr, ARPOP_REQUEST, &addr, null_ip, &null_addr, ip);
	nprobes++;
	timeout = RATE_LIMIT_INTERVAL_APPLE * 1000;
	zeroconf_state = ADDR_PROBE_WAIT;

	break;

      case ADDR_CLAIM:

	if (verbose) {
	  fprintf(stderr, "%s %s: ARP claim %s\n", prog, intf, inet_ntoa(ip));
	}

	arp(fd, &saddr, ARPOP_REQUEST, &addr, ip, &addr, ip);
	nclaims++;
	timeout = ANNOUNCE_INTERVAL * 1000;

	if (nclaims >= ANNOUNCE_NUM) {
	  zeroconf_state = ADDR_TAKE;
	} else {
	  zeroconf_state = ADDR_PROBE_WAIT;
	}

	break;

      case ADDR_TAKE:
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

	zeroconf_state = ADDR_DEFEND;

	break;

      case ADDR_DEFEND:
	/*
	 * check if it is for our address, if so, perform defence
	 * i.e. send an address clam
	 * then move to _DEFEND_FINAL and set timeout to DEFEND_INTERVAL
	 */
	if (check_arp_conflict(fd,intf,ip,addr)) {
	  /* send defence packet */
	  arp(fd, &saddr, ARPOP_REQUEST, &addr, ip, &addr, ip);
	  timeout = DEFEND_INTERVAL * 1000;
	  zeroconf_state = ADDR_DEFEND_FINAL;
	}

	break;

      case ADDR_DEFEND_FINAL:
	/* if another conflicting arp packet is received, remove our address,
	 * reset everything and go back to addr_probe
	 */
	if (check_arp_conflict(fd,intf,ip,addr)) {
	  
	  if (ready) {
	    ready = 0;
	    run(script, "deconfig", intf, &ip);
	  }
	  
	  nclaims = 0;
	  nprobes = 0;
	  conflict_count = 0;
	  zeroconf_state = ADDR_PROBE;
	  continue;
	}

	reduce_timeout(&timeout, tv);

	/* if we've run out of time, our defence must have been successful */
	if (notime)
	  zeroconf_state = ADDR_DEFEND;

	break;

      default:
	fprintf(stderr, "%s %s: unexpected zeroconf state\n", prog, intf);
	exit(1);
	break;


	if ((failby != 0) && (failby < time(0))) {
	  fprintf(stderr, "%s %s: failed to obtain address\n", prog, intf);
	  exit(1);
	}

      }

      next_state = 0;

    }
  }
}

