#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

// based on tirgul

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

struct tcphdr
{
    __u16 srcPort;
    __u16 destPort;
    __u32 srcAddr;
    __u32 destAddr;
    unsigned char *dataStartPtr;
    unsigned char *dataEndPtr;
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;
    if (ntohs(eth->ether_type) == 0x0800)
    { // 0x0800 is IP type
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        int ip_hdrln = ip->iph_ihl * 4;
        struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ethheader) + ip_hdrln);
        printf("From %s\n", inet_ntoa(ip->iph_sourceip));
        printf("To %s\n", inet_ntoa(ip->iph_destip));

        if (ip->iph_protocol == IPPROTO_TCP)
        {
            printf("srouce port: %d\n", tcp->srcPort);
            printf("dest port: %d\n", tcp->destPort);
        }
        unsigned char *pass = (unsigned char *)(packet + (sizeof(struct ethheader) + sizeof(struct ipheader) + sizeof(struct tcphdr)));
        int sizeData = 0;
        sizeData = ntohs(ip->iph_len) - (sizeof(struct ipheader) + sizeof(struct tcphdr));
        if (sizeData > 0)
        {
            printf(" Payload (%d bytes): \n", sizeData);
            for (int i = 0; i < sizeData; i++)
            {
                if (isprint(*pass))
                {
                    printf("data = %c\n", pass[i]);
        
                }
                else
                {
                    printf(".");
                }
            
            }
        }
    }
}
int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "proto TCP and dst portrange 10-100";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name eth3 for ethernet and enp0s3 - for internet
    handle = pcap_open_live("br-3d50edc4535c", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        printf("can not open live pcap session, err\n you should run as admin: %s\n", errbuf);
        return -1;
    }
    printf("live session opened\n");
    // Step 2: Compile filter_exp into BPF psuedo-code

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
        printf("filter %s does not exists\n", filter_exp);
        return -1;
    }
    pcap_setfilter(handle, &fp);
    // Step 3: Capture packets
    printf("start sniffing...\n");
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle); //Close the handle
    printf("socket closed\n");
    return 0;
}