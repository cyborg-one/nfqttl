#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>


#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <src/internal.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <getopt.h>
#include <string.h>
#include <pwd.h>
#include <fcntl.h>

#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/pktbuff.h>

#include <libnetfilter_queue/libnetfilter_queue_ipv6.h>
#include <sys/resource.h>
#include <sys/capability.h>
#include <sys/prctl.h>

#define NFNL_MAX_SUBSYS                 16 /* enough for now */

struct nfq_handle
{
        struct nfnl_handle *nfnlh;
        struct nfnl_subsys_handle *nfnlssh;
        struct nfq_q_handle *qh_list;
};

struct nfnl_subsys_handle {
        struct nfnl_handle      *nfnlh;
        u_int32_t               subscriptions;
        u_int8_t                subsys_id;
        u_int8_t                cb_count;
        struct nfnl_callback    *cb;
};

struct nfnl_handle {
        int                     fd;
        struct sockaddr_nl      local;
        struct sockaddr_nl      peer;
        u_int32_t               subscriptions;
        u_int32_t               seq;
        u_int32_t               dump;
        u_int32_t               rcv_buffer_size;
        u_int32_t               flags;
        struct nlmsghdr         *last_nlhdr;
        struct nfnl_subsys_handle subsys[NFNL_MAX_SUBSYS+1];
};


struct globalArgs_t {
    uint16_t ttl;                    /* Tim to live */
    uint16_t numq;              /* number queue */
    uint16_t daemon;
    uint32_t sizepacket;
} globalArgs;

static const char *optString = "t:n:l:dh?";

static const struct option longOpts[] = {
    { "ttl", required_argument, NULL, 't' },
    { "num-queue", required_argument, NULL, 'n' },
    { "sizepacket", required_argument, NULL, 'l' },
    { "daemon", no_argument, NULL, 'd' },
    { "help", no_argument, NULL, 'h' },
    { NULL, no_argument, NULL, 0 }
};

int *p = NULL;
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
        int id = 0;
        struct nfqnl_msg_packet_hdr *ph;
        ph = nfq_get_msg_packet_hdr(nfa);
        uint8_t *newdata;
        int len = nfq_get_payload(nfa, &newdata);
        int ret = 0;
        if (ph) {
                id = ntohl(ph->packet_id);
		if(len > globalArgs.sizepacket){
			ret = nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
		}
                else if(ntohs(ph->hw_protocol) == 0x0800){
                        struct iphdr *iphdr = (struct iphdr *) newdata;
                        iphdr->ttl = globalArgs.ttl;
                        nfq_ip_set_checksum(iphdr);
                        ret = nfq_set_verdict(qh, id, NF_ACCEPT, len, newdata);
			if(ret == -1){
				printf("nfq_set_verdict == -1 payload len %i\n", len);
				perror("nfq_set_verdict");
				ret = nfq_set_verdict(qh, id, NF_DROP, 0, NULL);

			}

                }
                else if(ntohs(ph->hw_protocol) == 0x86dd){
                        struct ip6_hdr *ip6hdr  = (struct ip6_hdr *) newdata;
			ip6hdr->ip6_hlim = globalArgs.ttl;
                        ret = nfq_set_verdict(qh, id, NF_ACCEPT, len, newdata);
			if(ret == -1){
				printf("nfq_set_verdict == -1 payload len %i\n", len);
				perror("nfq_set_verdict");
				ret = nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
			}
                } else ret = nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

        }
        return ret;
}

void daemonize()
{
	int pid;

	pid = fork();
	if (pid == -1)
	{
		perror("fork: ");
		exit(2);
	}
	else if (pid != 0)
		exit(0);

	if (setsid() == -1)
		exit(2);
	if (chdir("/") == -1)
		exit(2);

	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	/* redirect fd's 0,1,2 to /dev/null */
	open("/dev/null", O_RDWR);
	/* stdin */
	dup(0);
	/* stdout */
	dup(0);
	/* stderror */
}


void display_usage( void )
{
	puts( "Usage:\n -d --daemon;\tdo not demonize\n -n --num-queue=1-65535;\tnum queue, default 6464\n -t --ttl=1-255;\tset time to live, default 64\n -h --help;\tprint help\n" );

	exit( EXIT_FAILURE );
}


int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	int bufsize = 16384*5;
	char buf[bufsize] __attribute__ ((aligned));
	int on = 1;

	int opt = 0;
	int option_index = 0;
	globalArgs.ttl = 64;
	globalArgs.numq = 6464;
	globalArgs.daemon = 1;
	globalArgs.sizepacket = 32768;
	uint32_t opta;

	opt = getopt_long( argc, argv, optString, longOpts, &option_index );

	while( opt != -1 ) {
	    switch( opt ) {
			case 't':
				opta = atoi(optarg);
				if(opta > 0 && opta <= 255){
				    globalArgs.ttl = opta;
    				    break;
				} else{
				    printf("Wrong ttl value: %d\n", opta);
				    display_usage();
				}

			case 'n':
				opta = atoi(optarg);
				if(opta > 0 && opta <= 65535){
				    globalArgs.numq = opta;
    				    break;
				} else{
				    printf("Wrong number queue value: %d\n", opta);
				    display_usage();
				}
			case 'd':
				    globalArgs.daemon = 0;
    				    break;
			case 'l':
				opta = atoi(optarg);
				if(opta > 0 && opta <= 4294967295){
				    globalArgs.sizepacket = opta;
    				    break;
				} else{
				    printf("Wrong size limit value: %d\n", opta);
				    display_usage();
				}

			case 'h':	/* fall-through is intentional */
			case '?':
				display_usage();
				break;

			default:
				display_usage();
				break;
		}

		opt = getopt_long( argc, argv, optString, longOpts, &option_index );
	}


	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

        if(nfnl_rcvbufsiz(h->nfnlh, bufsize) == -1) {
		printf("nfnl_rcvbufsize error\n");
		exit(1);
	}

	if(setsockopt(h->nfnlh->fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &on, sizeof(int)) == -1){
	    printf("NETLINK_NO_ENOBUFS ERROR\n");
	    exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}



	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET6) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET6) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}



	printf("binding this socket to queue '%d', change ttl to '%d'\n", globalArgs.numq, globalArgs.ttl);
	qh = nfq_create_queue(h, globalArgs.numq, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	if (nfq_set_queue_maxlen(qh, 1024) < 0) {
		perror("can't set queue maxlen");
		exit(1);
	}

	if (nfq_set_queue_flags(qh, NFQA_CFG_F_FAIL_OPEN , NFQA_CFG_F_FAIL_OPEN))
	{
		fprintf(stderr, "can't set queue flags. its OK on linux <3.6\n");
	}

	printf("Waiting for packets...\n");

	fd = nfq_fd(h);

	if(globalArgs.daemon == 1){
	    printf("demonize");
	    daemonize();

	}
	if(setpriority(PRIO_PROCESS, getpid(), -20) == -1)printf("set priority error\n");

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
//			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;

		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
