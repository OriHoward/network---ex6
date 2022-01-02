#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

/* Ethernet header */
struct ethheader
{
    u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
    u_short ether_type;                 /* IP? ARP? RARP? etc */
};

struct ipheader
{
    unsigned char iph_ihl : 4,       //IP header length
        iph_ver : 4;                 //IP version
    unsigned char iph_tos;           //Type of service
    unsigned short int iph_len;      //IP Packet length (data + header)
    unsigned short int iph_ident;    //Identification
    unsigned short int iph_flag : 3, //Fragmentation flags
        iph_offset : 13;             //Flags offset
    unsigned char iph_ttl;           //Time to Live
    unsigned char iph_protocol;      //Protocol type
    unsigned short int iph_chksum;   //IP datagram checksum
    struct in_addr iph_sourceip;     //Source IP address
    struct in_addr iph_destip;       //Destination IP address
};

struct icmphdr
{
    unsigned char icmp_type;
    unsigned char icmp_code;
    unsigned short int icmph_chksum; //ICMP datagram checksum - not used but according to Tirgul its neccesery
};

void spoofNewPkt(struct ipheader *ip)
{
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr = ip->iph_destip;
    int enable = 1;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

    sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&sin, sizeof(sin));
    close(sock);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800)
    { // 0x0800 is IP type
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        int ip_hdrln = ip->iph_ihl * 4;
        struct icmphdr *icmp = ((struct icmphdr *)(packet + sizeof(struct ethheader) + ip_hdrln));

        if (ip->iph_protocol == IPPROTO_ICMP)
        {
            int pktLen = 1024;
            const char data[pktLen];
            memset((char *)data, 0, pktLen);
            memcpy((char *)data, ip, ntohs(ip->iph_len));
            struct ipheader *spoofedIp = (struct ipheader *)data;
            struct icmphdr *spoofedIcmp = (struct icmpheader *)(data + ip->iph_ihl * 4);

            spoofedIp->iph_sourceip = ip->iph_destip;
            spoofedIp->iph_destip = ip->iph_sourceip;
            spoofedIp->iph_ttl = 64;

            spoofedIcmp->icmp_type = 0;

            spoofNewPkt(spoofedIp);
        }
    }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ip proto icmp";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name eth3 for ethernet and enp0s3 - for internet
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        printf("can not open live pcap session, err\n you should run as admin: %s\n", errbuf);
        return -1;
    }
    printf("live session opened\n");
    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    // Step 3: Capture packets
    printf("start sniffing...\n");
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle); //Close the handle
    printf("socket closed\n");
    return 0;
}
