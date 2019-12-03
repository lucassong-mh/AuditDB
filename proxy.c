#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#define ADDR "172.17.0.1"
#define PORT 1234
#define PG_SERV_ADDR "127.0.0.1"
#define PG_SERV_PORT 5432
#define MAXBUFF 16384

char fe_buff[MAXBUFF], be_buff[MAXBUFF];

int fe_socket_fd, fe_connect_fd;
struct sockaddr_in fe_addr;

int be_socket_fd;
struct sockaddr_in be_addr;

int optval = 1;

struct timeval timeout = {1, 0};

int main(int argc, char **argv)
{
	//PG Client <=====> Proxy

	if ((fe_socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)) == -1)
	{
		printf("PG Client <===> Proxy create socket error: %s(errno: %d)\n", strerror(errno), errno);
		exit(0);
	}
	memset(&fe_addr, 0, sizeof(fe_addr));
	fe_addr.sin_family = AF_INET;
	fe_addr.sin_addr.s_addr = inet_addr(ADDR);
	printf("Proxy IP: %s\n", ADDR);
	fe_addr.sin_port = htons(PORT);

	setsockopt(fe_socket_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval));

	if (bind(fe_socket_fd, (struct sockaddr *)&fe_addr, sizeof(fe_addr)) == -1)
	{
		printf("PG Client <===> Proxy bind socket error: %s(errno: %d)\n", strerror(errno), errno);
		exit(0);
	}
	if (listen(fe_socket_fd, 10) == -1)
	{
		printf("PG Client <===> Proxy listen socket error: %s(errno: %d)\n", strerror(errno), errno);
		exit(0);
	}
	printf("======waiting for PG Client's request======\n");

	if ((fe_connect_fd = accept(fe_socket_fd, (struct sockaddr *)NULL, NULL)) < 0)
	{
		printf("accept socket error: %s(errno: %d)", strerror(errno), errno);
	}
	fe_config();


	//Proxy <=====> PG Server

	if ((be_socket_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_IP)) < 0)
	{
		printf("Proxy <===> PG Server create socket error: %s(errno: %d)\n", strerror(errno), errno);
		exit(0);
	}

	be_config();

	memset(&be_addr, 0, sizeof(be_addr));
	be_addr.sin_family = AF_INET;
	be_addr.sin_addr.s_addr = inet_addr(PG_SERV_ADDR);
	printf("PG Server IP: %s\n", PG_SERV_ADDR);
	be_addr.sin_port = htons(PG_SERV_PORT);

	if (connect(be_socket_fd, (struct sockaddr *)&be_addr, sizeof(be_addr)) < 0)
	{
		printf("Proxy <===> PG Server connect error: %s(errno: %d)\n", strerror(errno), errno);
		exit(0);
	}
	printf("======waiting for PG Server's response======\n");

	// printf("fe socket fd: %d, be socket fd: %d\n", fe_socket_fd, be_socket_fd);


	while (1)
	{
		if (!isSocketConnected(fe_connect_fd))
		{
			reconnect();
		}

		int cn;
		int send_sn;

		printf("Waiting======================\n");

		while (1)
		{
			if (!isSocketConnected(fe_connect_fd))
			{
				reconnect();
				break;
			}
			// printf("C===P\n");
			cn = (int)recv(fe_connect_fd, fe_buff, MAXBUFF, 0);
			// printf("cn: %d, errno: %d\n", cn, errno);
			for (int i = 0; i < 8; i++)
			{
				printf("%c ", fe_buff[i]);
			}
			puts("");
			if (cn > 0)
			{
				printf("recv msg from client(%d): %d\n", fe_connect_fd, cn);
				if ((send_sn = send(be_socket_fd, fe_buff, cn, 0)) < 0)
				{
					perror("send to server error");
					exit(1);
				}
				printf("send msg to server(%d): %d\n", be_socket_fd, send_sn);
				break;
			}
			else
			{
				if ((cn < 0) && ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR)))
				{
					continue;
				}
				break;
			}
		}

		int sn;
		int send_cn;
		while (1)
		{
			if (!isSocketConnected(fe_connect_fd))
			{
				reconnect();
				break;
			}
			// printf("P===S\n");
			sn = (int)recv(be_socket_fd, be_buff, MAXBUFF, 0);
			// printf("sn: %d, errno: %d\n", sn, errno);
			for (int i = 0; i < 8; i++)
			{
				printf("%c ", be_buff[i]);
			}
			puts("");
			if (sn > 0)
			{

				printf("recv msg from server(%d): %d\n", be_socket_fd, sn);
				if ((send_cn = send(fe_connect_fd, be_buff, sn, 0)) < 0)
				{
					perror("send to client error");
					exit(1);
				}
				printf("send msg to client(%d): %d\n", fe_connect_fd, send_cn);
				if (be_buff[0] == 'E')
				{
					continue;
				}
				break;
			}
			else
			{
				if ((sn < 0) && ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR)))
				{
					continue;
				}
				break;
			}
		}
	}

	close(fe_connect_fd);
	close(fe_socket_fd);
	close(be_socket_fd);
}

int isSocketConnected(int socket_fd)
{
	if (socket_fd <= 0)
		return 0;
	struct tcp_info info;
	int len = sizeof(info);
	getsockopt(socket_fd, IPPROTO_TCP, TCP_INFO, &info, (socklen_t *)&len);
	if ((info.tcpi_state == TCP_ESTABLISHED))
	{
		printf("socket connected\n");
		return 1;
	}
	else
	{
		printf("socket disconnected\n");
		return 0;
	}
}

int reconnect()
{
	fe_connect_fd = accept(fe_socket_fd, (struct sockaddr *)NULL, NULL);
	fe_config();
	close(be_socket_fd);
	be_socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	be_config();
	connect(be_socket_fd, (struct sockaddr *)&be_addr, sizeof(be_addr));
}

void fe_config()
{
	setsockopt(fe_connect_fd, SOL_TCP, TCP_NODELAY, (char *)&optval, sizeof(optval));
	setsockopt(fe_connect_fd, SOL_SOCKET, SO_KEEPALIVE, (char *)&optval, sizeof(optval));
	// setsockopt(fe_connect_fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(struct timeval));
	// setsockopt(fe_connect_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));
}

void be_config()
{
	setsockopt(be_socket_fd, SOL_TCP, TCP_NODELAY, (char *)&optval, sizeof(optval));
	setsockopt(be_socket_fd, SOL_SOCKET, SO_KEEPALIVE, (char *)&optval, sizeof(optval));
	// setsockopt(be_socket_fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(struct timeval));
	// setsockopt(be_socket_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));
}