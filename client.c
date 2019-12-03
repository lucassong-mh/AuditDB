#include<stdio.h>  
#include<stdlib.h>  
#include<string.h>  
#include<errno.h>  
#include<sys/types.h>  
#include<sys/socket.h>  
#include<netinet/in.h>  
  
#define MAXLINE 4096
  
int main(int argc, char** argv)  
{  
    int sockfd, n, rec_len;  
    char recvline[4096], sendline[4096];  
    char buf[MAXLINE];  
    struct sockaddr_in servaddr;  
  
    if( argc != 2){
        printf("usage: ./client <ipaddress>\n");
        exit(0);
    }
  
    if( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        printf("create socket error: %s(errno: %d)\n", strerror(errno),errno);
        exit(0);
    }  
  
    memset(&servaddr, 0, sizeof(servaddr));  
    servaddr.sin_family = AF_INET;  
    servaddr.sin_port = htons(1234);
	//inet_pton是Linux下IP地址转换函数，将IP地址在“点分十进制”和“整数”之间转换
    if( inet_pton(AF_INET, argv[1], &servaddr.sin_addr) <= 0){
        printf("inet_pton error for %s\n",argv[1]);  
        exit(0);  
    }  
   
    if( connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0){  
        printf("connect error: %s(errno: %d)\n",strerror(errno),errno);  
        exit(0);  
    }  
  
    printf("send msg to server: \n");  
    fgets(sendline, 4096, stdin);  
    if( send(sockfd, sendline, strlen(sendline), 0) < 0)  {  
        printf("send msg error: %s(errno: %d)\n", strerror(errno), errno);  
        exit(0);  
    }  
    if((rec_len = recv(sockfd, buf, MAXLINE,0)) == -1) {  
       perror("recv error");  
       exit(1);  
    }  
    buf[rec_len]  = '\0';  
    printf("Received : %s ",buf);  
    close(sockfd);  
    exit(0);  
}



accept(3, {sa_family=AF_INET, sin_port=htons(55486), sin_addr=inet_addr("127.0.0.1")}, [16]) = 9
getsockname(9, {sa_family=AF_INET, sin_port=htons(5432), sin_addr=inet_addr("127.0.0.1")}, [16]) = 0
setsockopt(9, SOL_TCP, TCP_NODELAY, [1], 4) = 0
setsockopt(9, SOL_SOCKET, SO_KEEPALIVE, [1], 4) = 0




socket(PF_INET, SOCK_STREAM, IPPROTO_IP) = 3
setsockopt(3, SOL_TCP, TCP_NODELAY, [1], 4) = 0
setsockopt(3, SOL_SOCKET, SO_KEEPALIVE, [1], 4) = 0
connect(3, {sa_family=AF_INET, sin_port=htons(5432), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 EINPROGRESS (Operation now in progress)
getsockopt(3, SOL_SOCKET, SO_ERROR, [0], [4]) = 0
getsockname(3, {sa_family=AF_INET, sin_port=htons(55486), sin_addr=inet_addr("127.0.0.1")}, [16]) = 0














server

accept(3, {sa_family=AF_INET, sin_port=htons(52838), sin_addr=inet_addr("127.0.0.1")}, [16]) = 10
getsockname(10, {sa_family=AF_INET, sin_port=htons(5432), sin_addr=inet_addr("127.0.0.1")}, [16]) = 0
setsockopt(10, SOL_TCP, TCP_NODELAY, [1], 4) = 0
setsockopt(10, SOL_SOCKET, SO_KEEPALIVE, [1], 4) = 0
strace: Process 28828 attached
[pid 28828] recvfrom(10, "\0\0\0T\0\3\0\0user\0postgres\0database\0p"..., 8192, 0, NULL, NULL) = 84
[pid 28828] sendto(10, "R\0\0\0\f\0\0\0\5$\260N\307", 13, 0, NULL, 0) = 13
[pid 28828] recvfrom(10, 0xcf4140, 8192, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable)
[pid 28828] recvfrom(10, 0xcf4140, 8192, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable)
[pid 28828] recvfrom(10, "", 8192, 0, NULL, NULL) = 0
[pid 28828] +++ exited with 0 +++
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=28828, si_uid=1001, si_status=0, si_utime=0, si_stime=0} ---
// Password for user postgres: 

accept(3, {sa_family=AF_INET, sin_port=htons(52850), sin_addr=inet_addr("127.0.0.1")}, [16]) = 10
getsockname(10, {sa_family=AF_INET, sin_port=htons(5432), sin_addr=inet_addr("127.0.0.1")}, [16]) = 0
setsockopt(10, SOL_TCP, TCP_NODELAY, [1], 4) = 0
setsockopt(10, SOL_SOCKET, SO_KEEPALIVE, [1], 4) = 0
strace: Process 28908 attached
[pid 28908] recvfrom(10, "\0\0\0T\0\3\0\0user\0postgres\0database\0p"..., 8192, 0, NULL, NULL) = 84
[pid 28908] sendto(10, "R\0\0\0\f\0\0\0\5*\7h\324", 13, 0, NULL, 0) = 13
[pid 28908] recvfrom(10, 0xcf4140, 8192, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable)
[pid 28908] recvfrom(10, 0xcf4140, 8192, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable)
[pid 28908] recvfrom(10, "p\0\0\0(md5db918226f224e5d2426ca0fa"..., 8192, 0, NULL, NULL) = 41
[pid 28908] sendto(9, "\2\0\0\0\250\3\0\0u0\0\0\10\0\0\0\1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"..., 936, 0, NULL, 0) = 936
[pid 28908] sendto(9, "\2\0\0\0x\1\0\0u0\0\0\3\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"..., 376, 0, NULL, 0) = 376
[pid 28908] sendto(9, "\2\0\0\0008\3\0\0\0\0\0\0\7\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"..., 824, 0, NULL, 0) = 824
[pid 28908] sendto(10, "R\0\0\0\10\0\0\0\0S\0\0\0\32application_name\0p"..., 331, 0, NULL, 0) = 331
[pid 28908] recvfrom(10, 0xcf4140, 8192, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable)






client

socket(PF_LOCAL, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0) = 3
connect(3, {sa_family=AF_LOCAL, sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT (No such file or directory)
socket(PF_LOCAL, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0) = 3
connect(3, {sa_family=AF_LOCAL, sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT (No such file or directory)


socket(PF_INET, SOCK_STREAM, IPPROTO_IP) = 3
setsockopt(3, SOL_TCP, TCP_NODELAY, [1], 4) = 0
setsockopt(3, SOL_SOCKET, SO_KEEPALIVE, [1], 4) = 0
connect(3, {sa_family=AF_INET, sin_port=htons(5432), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 EINPROGRESS (Operation now in progress)
getsockopt(3, SOL_SOCKET, SO_ERROR, [0], [4]) = 0
getsockname(3, {sa_family=AF_INET, sin_port=htons(52838), sin_addr=inet_addr("127.0.0.1")}, [16]) = 0
sendto(3, "\0\0\0T\0\3\0\0user\0postgres\0database\0p"..., 84, MSG_NOSIGNAL, NULL, 0) = 84
 ===> fe_send(84) ---> len:84 ptr:
recvfrom(3, "R\0\0\0\f\0\0\0\5$\260N\307", 16384, 0, NULL, NULL) = 13
 ===> fe_recv(13) ---> len:16384 ptr:R
// Password for user postgres: 

socket(PF_LOCAL, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0) = 3
connect(3, {sa_family=AF_LOCAL, sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT (No such file or directory)
socket(PF_LOCAL, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0) = 3
connect(3, {sa_family=AF_LOCAL, sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT (No such file or directory)

socket(PF_INET, SOCK_STREAM, IPPROTO_IP) = 3
setsockopt(3, SOL_TCP, TCP_NODELAY, [1], 4) = 0
setsockopt(3, SOL_SOCKET, SO_KEEPALIVE, [1], 4) = 0
connect(3, {sa_family=AF_INET, sin_port=htons(5432), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 EINPROGRESS (Operation now in progress)
getsockopt(3, SOL_SOCKET, SO_ERROR, [0], [4]) = 0
getsockname(3, {sa_family=AF_INET, sin_port=htons(52838), sin_addr=inet_addr("127.0.0.1")}, [16]) = 0
sendto(3, "\0\0\0T\0\3\0\0user\0postgres\0database\0p"..., 84, MSG_NOSIGNAL, NULL, 0) = 84
 ===> fe_send(84) ---> len:84 ptr:
recvfrom(3, "R\0\0\0\f\0\0\0\5$\260N\307", 16384, 0, NULL, NULL) = 13
 ===> fe_recv(13) ---> len:16384 ptr:R
Password for user postgres: 
socket(PF_INET, SOCK_STREAM, IPPROTO_IP) = 3
setsockopt(3, SOL_TCP, TCP_NODELAY, [1], 4) = 0
setsockopt(3, SOL_SOCKET, SO_KEEPALIVE, [1], 4) = 0
connect(3, {sa_family=AF_INET, sin_port=htons(5432), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 EINPROGRESS (Operation now in progress)
getsockopt(3, SOL_SOCKET, SO_ERROR, [0], [4]) = 0
getsockname(3, {sa_family=AF_INET, sin_port=htons(52850), sin_addr=inet_addr("127.0.0.1")}, [16]) = 0
sendto(3, "\0\0\0T\0\3\0\0user\0postgres\0database\0p"..., 84, MSG_NOSIGNAL, NULL, 0) = 84
 ===> fe_send(84) ---> len:84 ptr:
recvfrom(3, "R\0\0\0\f\0\0\0\5*\7h\324", 16384, 0, NULL, NULL) = 13
 ===> fe_recv(13) ---> len:16384 ptr:R
sendto(3, "p\0\0\0(md5db918226f224e5d2426ca0fa"..., 41, MSG_NOSIGNAL, NULL, 0) = 41
 ===> fe_send(41) ---> len:41 ptr:p
recvfrom(3, "R\0\0\0\10\0\0\0\0S\0\0\0\32application_name\0p"..., 16384, 0, NULL, NULL) = 331
 ===> fe_recv(331) ---> len:16384 ptr:R



