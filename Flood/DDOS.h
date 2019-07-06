#pragma once
//g++ ../../../Main.cpp ../../../DDOS.cpp -lpthread
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h> 
#include <arpa/inet.h>
#include <pthread.h>
// -lpthread

struct ip{
	unsigned char       hl;
	unsigned char       tos;
	unsigned short      total_len;
	unsigned short      id;
	unsigned short      frag_and_flags;
	unsigned char       ttl;
	unsigned char       proto;
	unsigned short      checksum;
	unsigned int        sourceIP;
	unsigned int        destIP;
};
struct tcphdr{
	unsigned short      sport;
	unsigned short      dport;
	unsigned int        seq;
	unsigned int        ack;
	unsigned char       lenres;
	unsigned char       flag;
	unsigned short      win;
	unsigned short      sum;
	unsigned short      urp;
};
struct pseudohdr
{
	unsigned int	    saddr;
	unsigned int 	    daddr;
	char                zero;
	char                protocol;
	unsigned short      length;
};



class DOS
{
	int m_socket = 0;
	int m_alive = 1;
	char m_dest_IP[64] = { 0 };
	int m_dest_Port = -1;
	struct hostent *m_hostent = NULL;
	struct sockaddr_in m_addr;
	int m_threadNum = 0;
	pthread_t *m_thread = NULL;
	int m_sendPackageNum = 0;
public:
	static DOS *getInstance();
	void initDos(const char *IP = NULL,const int Port = 80);
	void initDos(const char *IP = NULL, const char *Port = "80");
	void init_header(struct ip *ip, struct tcphdr *tcp, struct pseudohdr *pseudoheader);
	void judge_argc(int argc);
	static void sig_int(int alive);
	void createSocket();
	int setPower();
	void run();
	void setThread(int thread);
	static void *sendFlood(void *addr);
	void joinThread();
	int closeSocket();
	unsigned short inline checksum(unsigned short *buffer, unsigned short size);
private:
	DOS();
	~DOS();
};

#define FLOOD DOS::getInstance()