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

int be_socket_fd;

// struct timeval timeout = {1, 0};

//PG Client <=====> Proxy
void connect_fe(const char *addr, unsigned int port)
{

	struct sockaddr_in fe_addr;
	if ((fe_socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)) == -1)
	{
		printf("PG Client <===> Proxy create socket error: %s(errno: %d)\n", strerror(errno), errno);
		exit(0);
	}
	memset(&fe_addr, 0, sizeof(fe_addr));
	fe_addr.sin_family = AF_INET;
	fe_addr.sin_addr.s_addr = inet_addr(addr);
	fe_addr.sin_port = htons(port);
	printf("Proxy IP: %s  Port: %d\n", addr, port);

	int optval = 1;
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
	printf(" Connection with PG Client Succeed!\n");

	if ((fe_connect_fd = accept(fe_socket_fd, (struct sockaddr *)NULL, NULL)) < 0)
	{
		printf("accept socket error: %s(errno: %d)", strerror(errno), errno);
	}
	fe_config();
}

//Proxy <=====> PG Server
void connect_be(const char *addr, unsigned int port)
{
	struct sockaddr_in be_addr;

	if ((be_socket_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_IP)) < 0)
	{
		printf("Proxy <===> PG Server create socket error: %s(errno: %d)\n", strerror(errno), errno);
		exit(0);
	}

	be_config();

	memset(&be_addr, 0, sizeof(be_addr));
	be_addr.sin_family = AF_INET;
	be_addr.sin_addr.s_addr = inet_addr(addr);
	be_addr.sin_port = htons(port);

	printf("PG Server IP: %s  Port: %d\n", addr, port);

	if (connect(be_socket_fd, (struct sockaddr *)&be_addr, sizeof(be_addr)) < 0)
	{
		printf("Proxy <===> PG Server connect error: %s(errno: %d)\n", strerror(errno), errno);
		exit(0);
	}
	printf(" Connection with PG Server Succeed!\n");
}

int main(int argc, char **argv)
{
	connect_be(PG_SERV_ADDR, PG_SERV_PORT);
	connect_fe(ADDR, PORT);

	while (1)
	{
		if (!isSocketConnected(fe_connect_fd))
		{
			reconnect(PG_SERV_ADDR, PG_SERV_PORT);
		}

		int cn;
		int send_sn;

		printf("Waiting======================\n");

		while (1)
		{
			if (!isSocketConnected(fe_connect_fd))
			{
				reconnect(PG_SERV_ADDR, PG_SERV_PORT);
				break;
			}
			cn = (int)recv(fe_connect_fd, fe_buff, MAXBUFF, 0);
			// printf("cn: %d, errno: %d\n", cn, errno);
			// for (int i = 0; i < 8; i++)
			// {
			// 	printf("%c ", fe_buff[i]);
			// }
			// puts("");
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
				reconnect(PG_SERV_ADDR, PG_SERV_PORT);
				break;
			}
			sn = (int)recv(be_socket_fd, be_buff, MAXBUFF, 0);
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

int reconnect(const char *addr, unsigned int port)
{
	fe_connect_fd = accept(fe_socket_fd, (struct sockaddr *)NULL, NULL);
	fe_config();
	close(be_socket_fd);
	be_socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	be_config();
	struct sockaddr_in be_addr;
	memset(&be_addr, 0, sizeof(be_addr));
	be_addr.sin_family = AF_INET;
	be_addr.sin_addr.s_addr = inet_addr(addr);
	be_addr.sin_port = htons(port);
	connect(be_socket_fd, (struct sockaddr *)&be_addr, sizeof(be_addr));
}

void fe_config()
{
	int optval = 1;
	setsockopt(fe_connect_fd, SOL_TCP, TCP_NODELAY, (char *)&optval, sizeof(optval));
	setsockopt(fe_connect_fd, SOL_SOCKET, SO_KEEPALIVE, (char *)&optval, sizeof(optval));
	// setsockopt(fe_connect_fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(struct timeval));
	// setsockopt(fe_connect_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));
}

void be_config()
{
	int optval = 1;
	setsockopt(be_socket_fd, SOL_TCP, TCP_NODELAY, (char *)&optval, sizeof(optval));
	setsockopt(be_socket_fd, SOL_SOCKET, SO_KEEPALIVE, (char *)&optval, sizeof(optval));
	// setsockopt(be_socket_fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(struct timeval));
	// setsockopt(be_socket_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));
}