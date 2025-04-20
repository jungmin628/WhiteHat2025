#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>       // IP 구조체 사용
#include <netinet/ip.h>       // IP 헤더용
#include <netinet/tcp.h>      // TCP 헤더용
#include <netinet/udp.h>      // UDP 헤더용
#include <linux/if_packet.h>  // Raw socket용
#include <net/ethernet.h>     // Ethernet 프로토콜 정의

#define BUF_LEN 1500

void error(const char *msg) {
    perror(msg);
    exit(1);
}

int main(void) {
    struct sockaddr_in server, client;
    struct sockaddr saddr;
    socklen_t clientlen = sizeof(client);
    char buf[BUF_LEN];

    // UDP 소켓 생성
    int udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_sock < 0) error("UDP socket creation failed");

    memset((char *)&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(9090);

    // UDP 바인드
    if (bind(udp_sock, (struct sockaddr *)&server, sizeof(server)) < 0)
        error("ERROR on binding");

    printf("UDP Server listening on port 9090...\n");

    // UDP 수신 루프
    while (1) {
        memset(buf, 0, BUF_LEN);
        if (recvfrom(udp_sock, buf, BUF_LEN - 1, 0, (struct sockaddr *)&client, &clientlen) < 0)
            error("ERROR receiving UDP packet");
        printf("Received UDP message: %s \n", buf);
    }

    // Raw socket 생성 (이 부분은 별도로 실행해야 함)
    int raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_sock < 0) error("Raw socket creation failed");

    struct packet_mreq mr;
    memset(&mr, 0, sizeof(mr));
    mr.mr_type = PACKET_MR_PROMISC;

    // Raw socket을 promiscuous 모드로 설정
    if (setsockopt(raw_sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0)
        error("Setting raw socket to promiscuous mode failed");

    printf("Raw packet sniffer started...\n");

    char buffer[BUF_LEN];

    // Raw 패킷 수신 루프
    while (1) {
        int data_size = recvfrom(raw_sock, buffer, BUF_LEN, 0, &saddr, (socklen_t *)sizeof(saddr));
        if (data_size > 0) printf("Got one packet\n");
    }

    close(udp_sock);
    close(raw_sock);

    return 0;
}
