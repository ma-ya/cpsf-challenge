#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <pcap.h>
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN  6

/*
libpcapのサンプル
ubuntuとかdebianのひとは
libpcap0.8-dev をapt-getとかで入れる
コンパイルするときはライブラリでpcapを指定する
gcc for_cpsf.c -lpcap
詳しくはここにかいてあるので宛先が80番ポートのTCPパケットだけ表示するプログラムを書いてください．
*/

//イーサネットヘッダ
struct struct_ethernet {
	u_char  ether_dhost[ETHER_ADDR_LEN];
	u_char  ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
};

struct pcap_pkthdr {
	struct timeval ts; // タイムスタンプ //
	bpf_u_int32 caplen; // 得られたパケットの長さ //
	bpf_u_int32 len; // 元々のパケットの長さ //
};

struct sniff_tcp {
	u_short th_sport;	// 送信元ポート //
	u_short th_dport;	// 送信先ポート //
	tcp_seq th_seq;		// シーケンス番号 //
	tcp_seq th_ack;		// 確認応答番号 //
	u_char th_offx2;	// データオフセット、予約ビット //
}

main(int argc, char *argv[]) {
	pcap_t *pd;
	int snaplen = 64;
    int pflag = 0;
    int timeout = 1000;
    char ebuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 localnet, netmask;
    pcap_handler callback;
    void print_ethaddr(u_char *, const struct pcap_pkthdr *, const u_char *packet);
    struct bpf_program;

	//macならen0とかubuntuならeth1とか
    if ((pd = pcap_open_live("en1", snaplen, !pflag, timeout, ebuf)) == NULL) {
		exit(1);
    }	

	if (pcap_lookupnet("en1", &localnet, &netmask, ebuf) < 0) {
		exit(1);
    }
    callback = print_ethaddr;
    if (pcap_loop(pd, -1, callback, NULL) < 0) {
		exit(1);
    }
	pcap_close(pd);
	exit(0);
}

void print_ethaddr(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	const struct struct_ethernet *eh;        
	eh = (struct struct_ethernet *)(packet);
	int i;
	
	//送信元MACアドレス
    for (i = 0; i < 6; ++i) {
		printf("%02x", (int)eh->ether_shost[i]);
		if(i < 5){
			printf(":");
		}
	}
    printf(" -> ");
	 //送信先MACアドレス
    for (i = 0; i < 6; ++i) {
		printf("%02x", (int)eh->ether_dhost[i]);
		if(i < 5){
			printf(":");
		}
	}
	printf("\n");
	printf("source port:%d\r\n",ntohs(tcph->source));
	printf("dest port:%d\r\n",ntohs(tcph->dest));
	printf("packet length:");
    printf("%d\r\n", h->len);
}
