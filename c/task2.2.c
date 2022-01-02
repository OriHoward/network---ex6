// #include <sys/socket.h>
// #include <linux/if_packet.h>
// #include <net/ethernet.h>
// #include <stdio.h>
// #include <pcap.h>
// #include <arpa/inet.h>

// #define ECHO_REQ 8
// #define ECHO_REP 0

// struct ipheader {
//     unsigned char iph_ihl: 4,       //IP header length
//     iph_ver: 4;                 //IP version
//     unsigned char iph_tos;           //Type of service
//     unsigned short int iph_len;      //IP Packet length (data + header)
//     unsigned short int iph_ident;    //Identification
//     unsigned short int iph_flag: 3, //Fragmentation flags
//     iph_offset: 13;             //Flags offset
//     unsigned char iph_ttl;           //Time to Live
//     unsigned char iph_protocol;      //Protocol type
//     unsigned short int iph_chksum;   //IP datagram checksum
//     struct in_addr iph_sourceip;     //Source IP address
//     struct in_addr iph_destip;       //Destination IP address
// };

// struct icmpheader {
//     unsigned char icmp_type;
//     unsigned char icmp_code;
//     unsigned short int icmph_chksum;   //ICMP datagram checksum - not used but according to Tirgul its neccesery
// //Do we need some more?? I think so..
// };

// int main() {
//     struct icmpheader icmphdr;
//     char data[] = "This is the ping\n";
//     int datalen = strlen(data) + 1;

//     icmphdr.icmp_type = ECHO_REQ;
//     // Identifier (16 bits): some number to trace the response.
//     // It will be copied to the response packet and used to map response to the request sent earlier.
//     // Thus, it serves as a Transaction-ID when we need to make "ping"
//     icmphdr.icmp_id = 18; // hai
//     icmphdr.icmp_code = 0;
//     // Combine the packet
//     char packet[IP_MAXPACKET];

//     // Next, ICMP header
//     memcpy((packet), &icmphdr, ICMP_HDRLEN);

//     // After ICMP header, add the ICMP data.
//     memcpy(packet + ICMP_HDRLEN, data, datalen);

//     // Calculate the ICMP header checksum
//     // ICMP header checksum (16 bits): set to 0 not to include into checksum calculation
//     icmphdr.icmp_cksum = 0;
//     icmphdr.icmp_cksum = calculate_checksum((unsigned short *) (packet), ICMP_HDRLEN + datalen);
//     memcpy((packet), &icmphdr, ICMP_HDRLEN);

//     struct sockaddr_in dest;
//     memset (&dest,0, sizeof(struct sockaddr_in));
//     dest.sin_family = AF_INET;
//     //should insert the address
//     int sock = -1;
//     if ((sock = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
//         fprintf(stderr, "socket() failed with error: %d", errrno);
//     return 1;
//     }
//     if (sendto (sock, packet, ICMP_HDRLEN + datalen, 0, (struct sockaddr *) &dest_in, sizeof (dest_in)) == -1) {
//         fprintf(stderr, "sendto() failed with error: %d", errno);
//         return 1;
//     }
//     struct timespec start, end;
//     struct icmpheader recieve_header;

//     if (int recv = recvfrom(sock,data,sizeof(data),0,NULL,0)<0){
//         perror("recv")
//     }
//         return 0;
// }

// // Compute checksum (RFC 1071).
// unsigned short calculate_checksum(unsigned short *paddress, int len) {
//     int nleft = len;
//     int sum = 0;
//     unsigned short *w = paddress;
//     unsigned short answer = 0;

//     while (nleft > 1) {
//         sum += *w++;
//         nleft -= 2;
//     }

//     if (nleft == 1) {
//         *((unsigned char *) &answer) = *((unsigned char *) w);
//         sum += answer;
//     }