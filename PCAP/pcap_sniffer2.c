#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <string.h>

#define SNAP_LEN 1518 // 최대 캡처 길이
#define MSG_LEN 32    // 출력할 메시지 길이 제한

// 패킷 캡처 콜백 함수
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethhdr *eth = (struct ethhdr *)packet;               // Ethernet 헤더
    struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ethhdr)); // IP 헤더
    int ip_header_len = ip_hdr->ip_hl * 4;                      // IP 헤더 길이
    struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ethhdr) + ip_header_len); // TCP 헤더
    int tcp_header_len = tcp_hdr->th_off * 4;                   // TCP 헤더 길이

    // 메시지 시작 위치
    const u_char *message = packet + sizeof(struct ethhdr) + ip_header_len + tcp_header_len;
    int message_len = ntohs(ip_hdr->ip_len) - (ip_header_len + tcp_header_len);

printf("\n======================================\n");
    // MAC 주소 출력
    printf("\n[Ethernet Header]\n");
    printf(" Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
        eth->h_source[0], eth->h_source[1], eth->h_source[2], 
        eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    printf(" Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
        eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], 
        eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

    // IP 주소 출력
    printf("\n[IP Header]\n");
    printf(" Src IP: %s\n", inet_ntoa(ip_hdr->ip_src));
    printf(" Dst IP: %s\n", inet_ntoa(ip_hdr->ip_dst));

    // TCP 포트 출력
    printf("\n[TCP Header]\n");
    printf(" Src Port: %d\n", ntohs(tcp_hdr->th_sport));
    printf(" Dst Port: %d\n", ntohs(tcp_hdr->th_dport));

    // 메시지 출력 (적당한 길이로)
    printf("\n[Message]\n");
    if (message_len > 0) {
        int print_len = (message_len > MSG_LEN) ? MSG_LEN : message_len;
        printf(" Data (%d bytes): ", print_len);
        for (int i = 0; i < print_len; i++) {
            printf("%c", (message[i] >= 32 && message[i] <= 126) ? message[i] : '.'); // 가독성 있는 문자만 출력
        }
        printf("\n");
    } else {
        printf(" No data\n");
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp and greater 64";  // TCP 패킷만 캡처
    bpf_u_int32 net, mask;
    char *dev = "ens33";  // ✅ 네트워크 인터페이스 설정

    // 네트워크 장치 정보 가져오기
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device: %s\n", errbuf);
        net = 0;
    }

    // 네트워크 인터페이스 열기
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 1;
    }

    // 필터 설정 (TCP만 캡처)
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1 || pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    // 패킷 캡처 시작
    printf("Listening on %s...\n", dev);
    pcap_loop(handle, 0, packet_handler, NULL);

    // 정리 작업
    pcap_freecode(&fp);
    pcap_close(handle);
    return 0;
}
