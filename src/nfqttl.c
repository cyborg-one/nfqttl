#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <stdint.h>
#include <getopt.h>
#include <string.h>
#define  __USE_MISC 1


#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <src/internal.h>


#include <pwd.h>
#include <fcntl.h>

#include <sys/capability.h>
#include <sys/prctl.h>


#include <sys/poll.h>


#define Version "v2.8"


#include <sys/resource.h>


#include <linux/rtnetlink.h>


#include <linux/netlink.h>
#include <libnfnetlink/libnfnetlink.h>

#include <time.h>
#include <libmnl/libmnl.h>
#include <libnetlink/libnetlink.h>




struct globalArgs_t {
    uint8_t ttl;
    uint8_t ttlwan;
    uint8_t ttllan;
    uint8_t tos;
    uint16_t queue_num;
    uint16_t daemon;

    uint32_t mark;
    uint32_t uid;

    uint32_t sizepacket;
    char interfacename[64];

    uint16_t index;

    struct pollfd if_fd[1];
    struct nlif_handle *h;

    int countpacket;
    int counthttp;
    int countsyn;

    int splittcp;
    int splittcpsizepacket;

    int sock;

    struct rtnl_handle_ rth;
} globalArgs;
static const char *optString = "t:n:l:m::s::u::dh?";

static const struct option longOpts[] = {
    { "ttllan", required_argument, NULL, 0 },
    { "sizepacket", required_argument, NULL, 'l' },
    { "mark", optional_argument, NULL, 'm' },
    { "ttl", required_argument, NULL, 't' },
    { "queue-num", required_argument, NULL, 'n' },
    { "split-tcp", optional_argument, NULL, 's' },
    { "uid", optional_argument, NULL, 'u' },
    { "daemon", no_argument, NULL, 'd' },
    { "help", no_argument, NULL, 'h' },
    { "splittcpsizepacket", required_argument, NULL, 0 },
    { "countsyn", required_argument, NULL, 0 },
    { "counthttp", required_argument, NULL, 0 },
    { "countpacket", required_argument, NULL, 0 },
    { NULL, no_argument, NULL, 0 }
};

struct countpacket{
    uint8_t notsplit;
    uint32_t countsyn;
    uint32_t counthttp;
    uint32_t count;
    __u32  addr;
    time_t currenttime;
    uint8_t mark;
}countPacket[256];

int checkhost(uint8_t *data, int *len){
	if(globalArgs.splittcpsizepacket >= *len){
		return 0;
	}
        for(int i = 0; *len > i; i++){
                if(data[i] == 'h' || data[i] == 'H'){
                        if((data[i+1] == 't' || data[i+1] == 'T') && (data[i+2] == 't' || data[i+2] == 'T') && (data[i+3] == 'p' || data[i+3] == 'P')){
				if(globalArgs.splittcp == 1){
					for(int n = i; n; n--){
                                                if(data[n] == '.' && (data[n+1]>='a'&&data[n+1]<='z') && (data[n+2]>='a'&&data[n+2]<='z') && (data[n-1]>='0'&&data[n-1]<='z')){
							while(data[n] >= '.' && data[n] <= 'z')n--;
//							printf("name %s\n", data+n+1);
							*len = n;
							if(*len < 1){
								return 0;
							}else return 1;
						}
					}
				}else if(globalArgs.splittcp < *len){
					*len = globalArgs.splittcp;
					return 1;
				}else return 0;
                        }
                }
        }
        return 0;
}

int filtersplit(struct iphdr *iphdr, struct tcphdr *tcphdr, uint8_t *pointer_payload, int *len_payload, uint32_t *mark){
	for(int i = 0; i < 256 ; i++){

		if(i == 255 && countPacket[i].addr != 0){
			for(int n = 0; n < 256; n++){

				if(countPacket[n].currenttime < countPacket[i].currenttime){
					i = n;
//					printf("i %u %u n %u %u\n", i, countPacket[i].currenttime, n, countPacket[n].currenttime);
				}
			}
			countPacket[i].notsplit = 0;
			countPacket[i].count = 0;
			countPacket[i].countsyn = 0;
			countPacket[i].counthttp = 0;
			countPacket[i].currenttime = time(NULL);
			countPacket[i].addr = 0;
		}

		if(countPacket[i].addr == 0){
			countPacket[i].notsplit = 0;
			countPacket[i].count = 0;
			countPacket[i].countsyn = 0;
			countPacket[i].counthttp = 0;
			countPacket[i].addr = iphdr->daddr;
			countPacket[i].currenttime = time(NULL);
		}

		if(countPacket[i].addr == iphdr->daddr){
			if(countPacket[i].notsplit == 1){
				if(countPacket[i].mark == 1){
					*mark = globalArgs.mark;
				}
				return 0;
			}

			tcphdr->syn ? countPacket[i].countsyn++ : countPacket[i].count++;

			if(countPacket[i].count == 0 && countPacket[i].countsyn > globalArgs.countsyn){
				printf("only syn fin countsyn %i count %i http %i\n",  countPacket[i].countsyn, countPacket[i].count, countPacket[i].counthttp);
				printf("addr %hhu.%hhu.%hhu.%hhu\n", (((char*)&countPacket[i].addr)[0]), (((char*)&countPacket[i].addr)[1]), (((char*)&countPacket[i].addr)[2]), *(((char*)&countPacket[i].addr)+3));
				countPacket[i].notsplit = 1;
				if(globalArgs.mark){
					*mark = globalArgs.mark;
					countPacket[i].mark = 1;
				}
				return 0;
			}


			if(((countPacket[i].count - countPacket[i].counthttp) < countPacket[i].counthttp) && tcphdr->fin && countPacket[i].countsyn){
				printf("fin countsyn %i count %i http %i\n",  countPacket[i].countsyn, countPacket[i].count, countPacket[i].counthttp);
				printf("addr %hhu.%hhu.%hhu.%hhu\n", (((char*)&countPacket[i].addr)[0]), (((char*)&countPacket[i].addr)[1]), (((char*)&countPacket[i].addr)[2]), *(((char*)&countPacket[i].addr)+3));
				countPacket[i].notsplit = 1;
				if(globalArgs.mark){
					*mark = globalArgs.mark;
					countPacket[i].mark = 1;
				}
				return 0;
			}

			if((countPacket[i].countsyn - countPacket[i].counthttp) < 5 && countPacket[i].count < globalArgs.countpacket && countPacket[i].counthttp > globalArgs.counthttp){
				printf("countsyn %i count %i http %i\n",  countPacket[i].countsyn, countPacket[i].count, countPacket[i].counthttp);
				printf("addr %hhu.%hhu.%hhu.%hhu\n", (((char*)&countPacket[i].addr)[0]), (((char*)&countPacket[i].addr)[1]), (((char*)&countPacket[i].addr)[2]), *(((char*)&countPacket[i].addr)+3));
				countPacket[i].notsplit = 1;
				return 0;
			}

			if(checkhost(pointer_payload, len_payload)){
			        countPacket[i].counthttp++;
				return 1;
			}
			break;
		}
	}
	return 0;
}


int splittcp(uint8_t *data, int len, uint32_t *mark, uint32_t index) {
	if(globalArgs.splittcp == 0)
		return 0;

	int sock = 0;
	uint8_t newdata[len];
	memcpy(newdata, data, len);
	struct iphdr *iphdr = (struct iphdr *)newdata;

	if(iphdr->protocol != IPPROTO_TCP){
		return 0;
	}

	if(iphdr->ttl != 64 && iphdr->ttl != 128){
		return 0;
	}
	uint16_t iphdrl = iphdr->ihl*4;
	struct tcphdr *tcphdr = (struct tcphdr *)( newdata + iphdrl);

	uint16_t dport = ntohs(tcphdr->dest);
	if(dport != 443 && dport != 80 && dport)
		return 0;

	int tcphdrl = tcphdr->doff*4;
	int allhdrl = iphdrl+tcphdrl;
	int len_payload = len-iphdrl-tcphdrl;
	int newlen = len-iphdrl-tcphdrl;

	if(filtersplit(iphdr, tcphdr, data + allhdrl, &newlen, mark) == 0) return 0;

	iphdr->tot_len = htons(allhdrl+newlen);

	iphdr->ttl = globalArgs.ttl;
//	iphdr->frag_off = 0;
	nfq_tcp_compute_checksum_ipv4(tcphdr, iphdr);

	struct sockaddr_in si;
	memset(&si, 0, sizeof(si));
	si.sin_family=AF_INET;
	si.sin_port = tcphdr ? tcphdr->dest : 0;
	si.sin_addr.s_addr = iphdr->daddr;
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock == -1)	{
		perror("sock");
		return 0;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_MARK, mark, sizeof(mark)) == -1) {
	        perror("setsockopt not success mark");
	}

	if(index)
		if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, globalArgs.interfacename, strlen(globalArgs.interfacename)) == -1) {
    			perror("setsockopt bindtodevice");

		}

	if (sendto(sock, (char*)newdata, allhdrl+newlen, 0, (struct sockaddr*)&si, sizeof(struct sockaddr)) == -1) {
		perror("sendto 1");
		return 0;
	}

	memcpy((char*)newdata+iphdrl+sizeof(struct tcphdr), (char*)data+newlen+allhdrl, len_payload-newlen);

	iphdr->tot_len = htons(len_payload-newlen+iphdrl+sizeof(struct tcphdr));

	tcphdr->seq = htonl(ntohl(tcphdr->seq)+newlen);
	tcphdr->doff = 5;
	nfq_tcp_compute_checksum_ipv4(tcphdr, iphdr);
	int len2 = len_payload-newlen+iphdrl+sizeof(struct tcphdr);

	if(sendto(sock, (char*)newdata, len2, 0, (struct sockaddr*)&si, sizeof(struct sockaddr)) == -1)	{
		perror("sendto 2");
	}
	close(sock);

	return 1;
}


static inline int rtm_get_table(struct rtmsg *r, struct rtattr **tb)
{
        __u32 table = r->rtm_table;

        if (tb[RTA_TABLE])
                table = rta_getattr_u32(tb[RTA_TABLE]);
        return table;
}
static int iproute_dump_filter(struct nlmsghdr *nlh, int reqlen)
{       
        int err;
        
                err = addattr32(nlh, reqlen, RTA_TABLE, RT_TABLE_UNSPEC);
                if (err)
                        return err;
                        
        return 0;
}
int print_route(struct nlmsghdr *n, void *arg)
{
        struct rtmsg *r = NLMSG_DATA(n);
        int len = n->nlmsg_len;
        struct rtattr *tb[RTA_MAX+1];

        if (n->nlmsg_type != RTM_NEWROUTE && n->nlmsg_type != RTM_DELROUTE) {
                fprintf(stderr, "Not a route: %08x %08x %08x\n",
                        n->nlmsg_len, n->nlmsg_type, n->nlmsg_flags);
                return -1;
        }


        len -= NLMSG_LENGTH(sizeof(*r));
        if (len < 0) {
                fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
                return -1;
        }
        
        
        parse_rtattr(tb, RTA_MAX, RTM_RTA(r), len);
	if(r->rtm_scope == RT_SCOPE_UNIVERSE){
		globalArgs.index = rta_getattr_u32(tb[RTA_OIF]);
		globalArgs.ttl = globalArgs.ttlwan;

	}
        if (tb[RTA_DST] && rta_getattr_u32(tb[RTA_OIF]) == globalArgs.index && globalArgs.index) {
                if (r->rtm_dst_len == 24) {
			globalArgs.ttl = globalArgs.ttllan;
		}
	}
        return 0;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{

	int id = 0;
        struct nfqnl_msg_packet_hdr *ph;
        ph = nfq_get_msg_packet_hdr(nfa);
	uint32_t iout = nfq_get_outdev (nfa);
	uint32_t iin = nfq_get_indev (nfa);
	uint32_t mark = nfq_get_nfmark(nfa);
	uint8_t *newdata;
	int len = nfq_get_payload(nfa, &newdata);
	int ret = 0;



	if(poll(globalArgs.if_fd, 1, 0)|| globalArgs.index == 0){

		globalArgs.index = 0;
		globalArgs.interfacename[0] = 0;

	        if (rtnl_routedump_req(&globalArgs.rth, AF_INET, iproute_dump_filter) < 0) {
    		        perror("Cannot send dump request");
    		}
	        if (rtnl_dump_filter_nc(&globalArgs.rth, print_route, stdout, 0) < 0) {
    		        fprintf(stderr, "Dump terminated\n");
	        }
		for( int i = 0 ; i <= 255 ; i++){
			countPacket[i].addr = 0;
		}
		nlif_query(globalArgs.h);
		nlif_catch(globalArgs.h);
		nlif_index2name(globalArgs.h, globalArgs.index, globalArgs.interfacename);
		printf("name index ttl iout iin %s %u %hhu %u %u\n", globalArgs.interfacename, globalArgs.index, globalArgs.ttl, iout, iin);
	}

        if (ph) {
		id = ntohl(ph->packet_id);
	        if (len > globalArgs.sizepacket) {
                        ret = nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
                } else if(globalArgs.index){
			if(ntohs(ph->hw_protocol) == 0x0800){
				struct iphdr *iphdr = (struct iphdr *) newdata;
				if(iin){
					if (iin == globalArgs.index){
						if(iphdr->ttl == 1 && globalArgs.ttl == globalArgs.ttlwan){
		    					iphdr->ttl = globalArgs.ttl;
							nfq_ip_set_checksum(iphdr);
							ret = nfq_set_verdict(qh, id, NF_ACCEPT, len, newdata);
						}else ret = nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
					}else if (iin != globalArgs.index){
						if(iphdr->ttl == globalArgs.ttlwan || iphdr->ttl == 128){
							if(splittcp(newdata, len, &mark, 0)){
								ret = nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
							}else if(!globalArgs.mark || (globalArgs.mark && mark != globalArgs.mark)){
								iphdr->ttl = globalArgs.ttl == globalArgs.ttllan ? 66 : globalArgs.ttllan;
								nfq_ip_set_checksum(iphdr);
								ret = nfq_set_verdict(qh, id, NF_ACCEPT, len, newdata);
							}else ret = nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
						}else ret = nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
					}else ret = nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
				}else if(iout == globalArgs.index){
					if(iphdr->ttl == globalArgs.ttlwan){
						if(splittcp(newdata, len, &mark, iout)){
							ret = nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
						}else if(!globalArgs.mark || (globalArgs.mark && mark != globalArgs.mark)){
							iphdr->ttl = globalArgs.ttl;
							nfq_ip_set_checksum(iphdr);
							ret = nfq_set_verdict(qh, id, NF_ACCEPT, len, newdata);
						}else ret = nfq_set_verdict2(qh, id, NF_ACCEPT, mark, 0, NULL);
					}else ret = nfq_set_verdict2(qh, id, NF_ACCEPT, mark, 0, NULL);
				}else ret = nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
			}else if(ntohs(ph->hw_protocol) == 0x86dd){
				struct ip6_hdr *ip6hdr = (struct ip6_hdr *) newdata;
				if(iout == globalArgs.index && ip6hdr->ip6_hops != globalArgs.ttl){
					ret = nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
				}else ret = nfq_set_verdict(qh, id, NF_ACCEPT, len, newdata);
			}else ret = nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
		}else ret = nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
	return ret;
}
int changeuid(){

        if(prctl(8, 1))
		printf("error prctl\n");
	struct __user_cap_header_struct hdr = {0};
	hdr.version = _LINUX_CAPABILITY_VERSION;
	hdr.pid = getpid();
	struct __user_cap_data_struct data = {0};
	data.effective &= ~CAP_TO_MASK(CAP_IPC_LOCK);
	data.permitted &= ~CAP_TO_MASK(CAP_IPC_LOCK);
	if (capget(&hdr, &data) < 0){
    		printf("capset failed: %m");
		return 1;
	}
	setuid(globalArgs.uid);
	setgid(globalArgs.uid);

        if (capset(&hdr, &data) < 0){
	        printf("capset failed: %m");
		return 1;
	}
	printf("set uid %i \n", getuid());
	return 0;
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


void display_usage(int status)
{
	printf(	"Nfqttl version %s\n"
		"Commands:\n"
		"  -d         --daemon             demonize\n"
		"  -n1-65535  --queue-num=1-65535  queue number, default 6464\n"
		"  -t1-255    --ttl=1-255          set time to live, default 64\n"
		"  -s1-65535  --split-tcp=1-65535  split tcp sequence, default disable\n"
		"  -u1-65535  --uid=1-65535        set uid and gid process\n"
		"  -h         --help               print help\n",
		Version );
	exit(status);
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

        globalArgs.ttl = 64;
        globalArgs.ttllan = 65;
        globalArgs.ttlwan = 64;
	globalArgs.index = 0;

        globalArgs.queue_num = 6464;
	globalArgs.uid = 0;
	globalArgs.sizepacket = 32768;

	globalArgs.mark = 0;

	globalArgs.splittcp = 0;
	globalArgs.splittcpsizepacket = 20;

	globalArgs.countsyn = 15;
	globalArgs.counthttp = 12;
	globalArgs.countpacket = 40;

	globalArgs.rth.fd = -1;

	int opt = 0;
	int option_index = 0;
	uint32_t opta;


	while(1) {
		opt = getopt_long( argc, argv, optString, longOpts, &option_index );
    		if (opt == -1)
        		break;
		switch( opt ) {
			case 't':
				    opta = atoi(optarg);
				    if(opta > 0 && opta <= 255){
					    globalArgs.ttlwan = opta;
				    }else{
					    printf("Wrong ttl value: %u\n", opta);
					    display_usage(EXIT_FAILURE);
				    }
				    break;
			case 'n':
				    opta = atoi(optarg);
				    if(opta > 0 && opta <= 65535){
					    globalArgs.queue_num = opta;
				    }else{
					    printf("Wrong queue number value: %d\n", opta);
					    display_usage(EXIT_FAILURE);
				    }
				    break;
			case 's':
				    if(optarg){
					    opta = atoi(optarg);
					    if(opta > 0 && opta <= 65535){
						    globalArgs.splittcp = opta;
					    }else{
						    printf("Wrong split tcp pakage value: %d\n", opta);
						    display_usage(EXIT_FAILURE);
					    }
				    }else{
					    globalArgs.splittcp = 1;
				    }
				    break;
			case 'u':
				    if(optarg) {
					    opta = atoi(optarg);
					    if(opta > 0 && opta <= 65535){
						    globalArgs.uid = opta;
					    } else{
						    printf("Wrong uid number value: %d\n", opta);
						    display_usage(EXIT_FAILURE);
					    }
				    }else{
					    globalArgs.uid = 6464;
				    }
    				    break;
			case 'l':
	            			opta = atoi(optarg);
    		            		if(opta > 0 && opta <= 4294967295){
            	    	            		globalArgs.sizepacket = opta;
						printf("sizepacket %u\n", globalArgs.sizepacket);
                            		} else{
                                		printf("Wrong size value: %d\n", opta);
                                		display_usage(EXIT_FAILURE);
            	                	}
					break;

			case 'm':
				if(optarg){
		            		opta = atoi(optarg);
    			                if(opta > 0 && opta <= 4294967295){
            		    	            	globalArgs.mark = opta;
						printf("mark 0x%x\n", globalArgs.mark);
                            		} else{
                                		printf("Wrong mark value: %d\n", opta);
                                		display_usage(EXIT_FAILURE);
					}
                    		} else {
					globalArgs.mark = 0x10000064;
					printf("mark 0x%x\n", globalArgs.mark);
				}
					break;
			case 'd':
				globalArgs.daemon = 1;
    				break;
			case 'h':
				display_usage(EXIT_SUCCESS);
			case '?':
				display_usage(EXIT_FAILURE);
			case 0:
        			if( strcmp( "ttllan", longOpts[option_index].name ) == 0 ) {
				    opta = atoi(optarg);
				    if(opta > 0 && opta <= 255){
					    globalArgs.ttllan = opta;
				    }else{
					    printf("Wrong ttllan value: %u\n", opta);
					    display_usage(EXIT_FAILURE);
				    }
				    break;
				}
			if( strcmp( "splittcpsizepacket", longOpts[option_index].name ) == 0 ) {
				    opta = atoi(optarg);
				    if(opta > 0 && opta <= 65535){
					    globalArgs.splittcpsizepacket = opta;
				    }else{
					    printf("Wrong splittcpsizepacket value: %u\n", opta);
					    display_usage(EXIT_FAILURE);
				    }
				    break;
				}
			if( strcmp( "countsyn", longOpts[option_index].name ) == 0 ) {
				    opta = atoi(optarg);
				    if(opta > 0 && opta <= 65535){
					    globalArgs.countsyn = opta;
				    }else{
					    printf("Wrong countsyn value: %u\n", opta);
					    display_usage(EXIT_FAILURE);
				    }
				    break;
				}
			if( strcmp( "counthttp", longOpts[option_index].name ) == 0 ) {
				    opta = atoi(optarg);
				    if(opta > 0 && opta <= 65535){
					    globalArgs.counthttp = opta;
				    }else{
					    printf("Wrong counthttp value: %u\n", opta);
					    display_usage(EXIT_FAILURE);
				    }
				    break;
				}
			if( strcmp( "countpacket", longOpts[option_index].name ) == 0 ) {
				    opta = atoi(optarg);
				    if(opta > 0 && opta <= 65535){
					    globalArgs.countpacket = opta;
				    }else{
					    printf("Wrong countpacket value: %u\n", opta);
					    display_usage(EXIT_FAILURE);
				    }
				    break;
				}
				break;
			default:
				display_usage(EXIT_SUCCESS);
		}

	}

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}
        if(nfnl_rcvbufsiz(nfq_nfnlh(h), bufsize) == -1) {
                printf("nfnl_rcvbufsize error\n");
                exit(1);
        }


	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET6 (if any)\n");
        if (nfq_unbind_pf(h, AF_INET6) < 0) {
	    fprintf(stderr, "error during nfq_unbind_pf()\n");
	    exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

        printf("binding nfnetlink_queue as nf_queue handler for AF_INET6\n");
        if (nfq_bind_pf(h, AF_INET6) < 0) {
	    fprintf(stderr, "error during nfq_bind_pf()\n");
	    exit(1);
        }

	printf("binding this socket to queue '%u'\nchange ttl to '%hhu'\nSplit tcp package '%i'\n",
		globalArgs.queue_num, globalArgs.ttlwan, globalArgs.splittcp);
	qh = nfq_create_queue(h, globalArgs.queue_num, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}
	if(globalArgs.uid){
		if(changeuid()){
			fprintf(stderr, "can't change uid\n");
			exit(1);
		}
	}
	if(globalArgs.daemon == 1) {
		printf("daemonize\n");
		daemonize();
	}
        if(setpriority(PRIO_PROCESS, getpid(), -20) == -1)printf("set priority error\n");


	fd = nfq_fd(h);
        
	if(setsockopt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &on, sizeof(int)) == -1){
            printf("NETLINK_NO_ENOBUFS ERROR\n");
            exit(1);
        }

	globalArgs.h = nlif_open();
	int flags = fcntl(nlif_fd(globalArgs.h), F_GETFL, 0);
			if(flags != O_NONBLOCK)
				fcntl(nlif_fd(globalArgs.h), F_SETFL, (flags | O_NONBLOCK));
			nlif_query(globalArgs.h);
        if (rtnl_open_(&globalArgs.rth, RTMGRP_IPV4_ROUTE) < 0) {
                fprintf(stderr, "Cannot open rtnetlink\n");
                exit(EXIT_FAILURE);
        }
	flags = fcntl(globalArgs.rth.fd, F_GETFL, 0);
	if(flags != O_NONBLOCK)
		fcntl(globalArgs.rth.fd, F_SETFL, (flags | O_NONBLOCK));
	globalArgs.if_fd[0].fd = globalArgs.rth.fd;
	globalArgs.if_fd[0].events = POLLIN;



	printf("Waiting for packets...\n");
	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
//			printf("pkt received\n");
			int r = nfq_handle_packet(h, buf, rv);
			if (r) printf("nfq_handle_packet %i rv %i\n", r, rv);
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
