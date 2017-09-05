#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <netinet/ip_icmp.h>
#include "sockwrap.h"
#include "icmp.h"
#include <time.h>

unsigned char   buffer[IP_MAXPACKET+1];
unsigned char*  buffer_ptr;
int             re;

int main(int argc, char **argv){
    if(argc != 2){
        printf("Usage: ./traceroute <ip>\n");
        return 1;
    }

    int sockfd = Socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    struct sockaddr_in remote_address;
    bzero (&remote_address, sizeof(remote_address));
    remote_address.sin_family = AF_INET;
    inet_pton(AF_INET, argv[1], &remote_address.sin_addr);

    int ttl = 1;

    while(1){
        struct icmp icmp_packet;
        icmp_packet.icmp_type = ICMP_ECHO;
        icmp_packet.icmp_code = 0;
        icmp_packet.icmp_id = 123;      
        icmp_packet.icmp_seq = ttl;     
        icmp_packet.icmp_cksum = 0;
        icmp_packet.icmp_cksum = in_cksum((u_short*)&icmp_packet, 8, 0);

        Setsockopt (sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int));

        Sendto(sockfd, &icmp_packet, ICMP_HEADER_LEN, 0, &remote_address, sizeof(remote_address));
        Sendto(sockfd, &icmp_packet, ICMP_HEADER_LEN, 0, &remote_address, sizeof(remote_address));
        Sendto(sockfd, &icmp_packet, ICMP_HEADER_LEN, 0, &remote_address, sizeof(remote_address));

        clock_t start = clock();
        float seconds = 0;
        while(seconds < 1){
            clock_t c = clock();
            seconds = (float)(c - start)/CLOCKS_PER_SEC;
        }

        struct sockaddr_in sender;  
        socklen_t sender_len = sizeof(sender);
        buffer_ptr = buffer;
        re = Recvfrom (sockfd, buffer_ptr, IP_MAXPACKET, 
                                            0, &sender, &sender_len);

        char str[20]; 
        inet_ntop(AF_INET, &(sender.sin_addr), str, sizeof(str));
        // this printf shows me ip adresses of routers on route to 
        // destination(probably?), but anything below it doesn't seem to work
        // properly :(
        //printf ("%s\n", str);

        struct icmp* icmp_packet_recv = (struct icmp*) buffer_ptr;

        printf("%d %d\n", icmp_packet_recv->icmp_id, icmp_packet_recv->icmp_seq);

        if (icmp_packet_recv->icmp_type == ICMP_TIME_EXCEEDED && 
            icmp_packet_recv->icmp_code == ICMP_EXC_TTL) {

            struct ip* packet_orig = (struct ip*) buffer_ptr;

            if (packet_orig->ip_p == IPPROTO_ICMP) {
                if(icmp_packet_recv->icmp_seq == ttl && icmp_packet_recv->icmp_id == 123)
                    printf ("%s\n", str);
            }
        }
        if (icmp_packet_recv->icmp_type == ICMP_ECHOREPLY) {
            printf ("%s\n", str);
            return 0;
        }

        ttl++;
    }

    return 0;
}
