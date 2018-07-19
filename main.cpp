#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "psy_header.h"

#define ETH_HEADER_SIZE 14 // IP_HEADER_JMP --> ETH_HEADER_SIZE Fixed

void net_err(uint32_t chk,pcap_if_t *alldevs);
uint16_t print_ether_header(const uint8_t *pkt_data);
int print_ip_header(const uint8_t *pkt_data);
int print_tcp_header(const uint8_t *pkt_data);
int print_udp_header(const uint8_t *pkt_data);
void print_data(const uint8_t *pkt_data);


int PORT_FLAG = 1;
uint16_t TOTAL_LENGTH;
uint16_t ETH_TYPE=0;
uint8_t PROTO=0;

int main(int argc, char **argv)
{
    int IP_HEADER_SIZE,TCP_HEADER_SIZE,UDP_HEADER_SIZE;
    pcap_if_t *alldevs = NULL;
    pcap_if_t *dev;
    pcap_t *use_dev;
    char errbuf[BUF_SIZE];
    int i, dev_num, res;
    struct pcap_pkthdr *header;
    const uint8_t *pkt_data;


    if (pcap_findalldevs(&alldevs, errbuf) < 0)
    {
        printf("Device Find Error\n");
        return -1;
    }

    for (dev = alldevs, i = 0; dev != NULL; dev = dev->next)
        printf("%d번 Device : %s (%s)\n", ++i, dev->name, dev->description);

    printf("INPUT_NUMBER : ");
    scanf("%d", &dev_num);

    for (dev = alldevs, i = 0; i < dev_num - 1; dev = dev->next, i++);

    if ((use_dev = pcap_open_live(dev->name, SNAPLEN, 1, 1000, errbuf)) == NULL)
    {
        net_err(1,alldevs);         // pcap_freealldevs(alldevs) overlap Fixed!
    }
    printf("=====================PCAP_OPEN_SUCCESS====================\n");

    /*                    pcap_open_success                */

    pcap_freealldevs(alldevs); //캡처 네트워크를 제외한 네트워크 해제


    while ((res = pcap_next_ex(use_dev, &header, &pkt_data)) >= 0)
    {
        if (res == 0) continue;

        ETH_TYPE = print_ether_header(pkt_data);

        if(ETH_TYPE==0x0800)
        {
            pkt_data += ETH_HEADER_SIZE;
            IP_HEADER_SIZE = print_ip_header(pkt_data); // IP_Header_Size Check Fixed
            pkt_data += IP_HEADER_SIZE;

            if(PORT_FLAG && PROTO == 0x06)
            {
                printf("PROTOCOL] TCP %X\n",PROTO);
                TCP_HEADER_SIZE = print_tcp_header(pkt_data); // TCP_Header_Size Check Fixe
                pkt_data += TCP_HEADER_SIZE;

                if(TOTAL_LENGTH - (ETH_HEADER_SIZE+IP_HEADER_SIZE+TCP_HEADER_SIZE)) // DATA_packet Check Fixed
                    print_data(pkt_data);
            }
            else if(PORT_FLAG && PROTO == 0x11)
            {
                printf("PROTOCOL UDP %X\n",PROTO);
                UDP_HEADER_SIZE = print_udp_header(pkt_data);
                pkt_data += UDP_HEADER_SIZE;

                if(TOTAL_LENGTH - (ETH_HEADER_SIZE+IP_HEADER_SIZE+UDP_HEADER_SIZE)) // DATA_packet Check Fixed
                    print_data(pkt_data);
            }
            else
                printf("PROTOCOL ICMP %X\n",PROTO);


        }
        else
            continue;


    }

}

/*print_function*/
uint16_t print_ether_header(const uint8_t *pkt_data)
{
    struct eth_header *eh;
    eh = (struct eth_header *)pkt_data;
    uint16_t ether_type = ntohs(eh->eth_type);
    if (ether_type == 0x0800) printf("======= IPv4 =======\n");
    printf("Src MAC : ");
    for (int i = 0; i <= 5; i++) printf("%02X ", eh->src_mac[i]);
    printf("\nDes MAC : ");
    for (int i = 0; i <= 5; i++)printf("%02X ", eh->des_mac[i]);
    printf("\n");
    PORT_FLAG = 1;
    return ether_type;
}

int print_ip_header(const uint8_t *pkt_data)
{
    struct ip_header *ih;
    ih = (struct ip_header *)pkt_data;

    if (ih->ip_protocol == 0x06)
    {
        PROTO = ih->ip_protocol;
        printf("[TCP]");
        printf("Src IP : %s\n", inet_ntoa(ih->ip_src_add));
        printf("[TCP]");
        printf("Des IP : %s\n", inet_ntoa(ih->ip_des_add));
    }
    else if (ih->ip_protocol == 0x11)
    {
        PROTO = ih->ip_protocol;
        printf("[UDP]");
        printf("Src IP : %s\n", inet_ntoa(ih->ip_src_add));
        printf("[UDP]");
        printf("Des IP : %s\n", inet_ntoa(ih->ip_des_add));
    }
    else //(ih->ip_protocol == 0x01)
    {
        PROTO = ih->ip_protocol;
        PORT_FLAG = 0;
        printf("[ICMP]");
        printf("Src IP : %s\n", inet_ntoa(ih->ip_src_add));
        printf("[ICMP]");
        printf("Des IP : %s\n", inet_ntoa(ih->ip_des_add));
    }

    TOTAL_LENGTH = ntohs(ih->ip_total_length);
    printf("TOTAL_LEN : %d\n",((char)ih->ip_header_length)*4);
    return ((char)ih->ip_header_length)*4;
}
int print_tcp_header(const uint8_t *pkt_data)
{
    struct tcp_header *th;
    th = (struct tcp_header *)pkt_data;

    printf("Src Port : %d\n", ntohs(th->src_port));
    printf("Des Port : %d\n", ntohs(th->des_port));
    printf("====================\n\n");

    return ((char)th->offset)*4;
}

int print_udp_header(const uint8_t *pkt_data)
{
    struct udp_header *uh;
    uh = (struct udp_header *)pkt_data;

    printf("Src Port : %d\n", ntohs(uh->uh_sport));
    printf("Dst Port : %d\n", ntohs(uh->uh_dport));
    printf("====================\n\n");

    return (ntohs(uh->len));

}


void print_data(const uint8_t *pkt_data)
{
    printf("========DATA========\n");
    for(int i=0; i<16; i++)
        printf("%x",pkt_data[i]);
    printf("\n====================\n\n");
}


void net_err(uint32_t chk,pcap_if_t *alldevs)
{
    switch(chk)
    {
    case 1:
        printf("pcap_open ERROR!\n");
        pcap_freealldevs(alldevs);
        break;
    case 2:
        printf("pcap_compile ERROR!\n");
        pcap_freealldevs(alldevs);
        break;
    case 3:
        printf("pcap_setfilter ERROR!\n");
        pcap_freealldevs(alldevs);
    default:
        printf("ERROR!\n");
    }
}
