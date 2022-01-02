#include <stdio.h>

#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>
#include <asm/byteorder.h>

#define SOURCE_IP "1.2.3.4"
#define DESTINATION_IP "10.9.0.5"
#define ICMP_HDRLEN 8

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

struct icmpheader {
  unsigned char icmp_type;
  unsigned char icmp_code; 
  unsigned short int icmp_chksum; 
};


unsigned short calculate_checksum(unsigned short *paddress, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = paddress;
    unsigned short answer = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1)
    {
        *((unsigned char *)&answer) = *((unsigned char *)w);
        sum += answer;
    }

    // add back carry outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    answer = ~sum;                      // truncate to 16 bits

    return answer;
}

void send_raw_ip_packet(struct ipheader* ip) {
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr = ip->iph_destip;
	int enable = 1;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    setsockopt(sock, IPPROTO_IP, IP_HDRINCL,&enable, sizeof(enable));

    sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&sin, sizeof(sin));
    close(sock);
}

int main() {

    char data[1500];
    memset(data,0,1500);

   struct icmpheader *icmp = (struct icmpheader *)(data + sizeof(struct ipheader));
   icmp->icmp_type = 8; 

   icmp->icmp_chksum = 0;
   icmp->icmp_chksum = calculate_checksum((unsigned short *)icmp,sizeof(struct icmpheader));

   struct ipheader *ip = (struct ipheader *) data;
   ip->iph_ver = 4;
   ip->iph_ihl = 5;
   ip->iph_ttl = 20;
   ip->iph_sourceip.s_addr = inet_addr(DESTINATION_IP);
   ip->iph_destip.s_addr = inet_addr(SOURCE_IP);
   ip->iph_protocol = IPPROTO_ICMP;
   ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));
   send_raw_ip_packet(ip);
   printf("packet sent\n");

   return 0;

}
