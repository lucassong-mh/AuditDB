#include "Ocall_wrappers.h"

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include "tcp_enclave_types.h"

#define INADDR_NONE ((unsigned long int)0xffffffff)

#define ADDR "172.17.0.1"
#define PORT 1234
#define PG_SERV_ADDR "127.0.0.1"
#define PG_SERV_PORT 5432
#define MAXBUFF 16384

char fe_buff[MAXBUFF], be_buff[MAXBUFF];

int fe_socket_fd, fe_connect_fd;

int be_socket_fd;

static void init_openssl()
{
    OpenSSL_add_ssl_algorithms();
    OpenSSL_add_all_ciphers();
    SSL_load_error_strings();
}

static void cleanup_openssl()
{
    EVP_cleanup();
}

static SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLSv1_2_method();

    ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        printe("Unable to create SSL context");
        exit(EXIT_FAILURE);
    }
    return ctx;
}

static int password_cb(char *buf, int size, int rwflag, void *password)
{
    strncpy(buf, (char *)(password), size);
    buf[size - 1] = '\0';
    return strlen(buf);
}

static EVP_PKEY *generatePrivateKey()
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048);
    EVP_PKEY_keygen(pctx, &pkey);
    return pkey;
}

static X509 *generateCertificate(EVP_PKEY *pkey)
{
    X509 *x509 = X509_new();
    X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 0);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), (long)60 * 60 * 24 * 365);
    X509_set_pubkey(x509, pkey);

    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char *)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)"YourCN", -1, -1, 0);
    X509_set_issuer_name(x509, name);
    X509_sign(x509, pkey, EVP_md5());
    return x509;
}

static void configure_context(SSL_CTX *ctx)
{
    EVP_PKEY *pkey = generatePrivateKey();
    X509 *x509 = generateCertificate(pkey);

    SSL_CTX_use_certificate(ctx, x509);
    SSL_CTX_set_default_passwd_cb(ctx, password_cb);
    SSL_CTX_use_PrivateKey(ctx, pkey);

    RSA *rsa = RSA_generate_key(512, RSA_F4, NULL, NULL);
    SSL_CTX_set_tmp_rsa(ctx, rsa);
    RSA_free(rsa);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);
}

static int
isascii(int c)
{
    return ((c & ~0x7F) == 0);
}

/* inet_aton from https://android.googlesource.com/platform/bionic.git/+/android-4.0.1_r1/libc/inet/inet_aton.c */
static int inet_aton(const char *cp, struct in_addr *addr)
{
    u_long val, base, n;
    char c;
    u_long parts[4], *pp = parts;

    for (;;)
    {
        /*
		 * Collect number up to ``.''.
		 * Values are specified as for C:
		 * 0x=hex, 0=octal, other=decimal.
		 */
        val = 0;
        base = 10;
        if (*cp == '0')
        {
            if (*++cp == 'x' || *cp == 'X')
                base = 16, cp++;
            else
                base = 8;
        }
        while ((c = *cp) != '\0')
        {
            if (isascii(c) && isdigit(c))
            {
                val = (val * base) + (c - '0');
                cp++;
                continue;
            }
            if (base == 16 && isascii(c) && isxdigit(c))
            {
                val = (val << 4) +
                      (c + 10 - (islower(c) ? 'a' : 'A'));
                cp++;
                continue;
            }
            break;
        }
        if (*cp == '.')
        {
            /*
			 * Internet format:
			 *	a.b.c.d
			 *	a.b.c	(with c treated as 16-bits)
			 *	a.b	(with b treated as 24 bits)
			 */
            if (pp >= parts + 3 || val > 0xff)
                return (0);
            *pp++ = val, cp++;
        }
        else
            break;
    }
    /*
	 * Check for trailing characters.
	 */
    if (*cp && (!isascii(*cp) || !isspace(*cp)))
        return (0);
    /*
	 * Concoct the address according to
	 * the number of parts specified.
	 */
    n = pp - parts + 1;
    switch (n)
    {

    case 1: /* a -- 32 bits */
        break;

    case 2: /* a.b -- 8.24 bits */
        if (val > 0xffffff)
            return (0);
        val |= parts[0] << 24;
        break;

    case 3: /* a.b.c -- 8.8.16 bits */
        if (val > 0xffff)
            return (0);
        val |= (parts[0] << 24) | (parts[1] << 16);
        break;

    case 4: /* a.b.c.d -- 8.8.8.8 bits */
        if (val > 0xff)
            return (0);
        val |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8);
        break;
    }
    if (addr)
        addr->s_addr = htonl(val);
    return (1);
}

static in_addr_t inet_addr(const char *cp)
{
    struct in_addr val;

    if (inet_aton(cp, &val))
        return (val.s_addr);
    return (INADDR_NONE);
}

void fe_config()
{
    int optval = 1;
    setsockopt(fe_connect_fd, SOL_TCP, TCP_NODELAY, (char *)&optval, sizeof(optval));
    setsockopt(fe_connect_fd, SOL_SOCKET, SO_KEEPALIVE, (char *)&optval, sizeof(optval));
}

void be_config()
{
    int optval = 1;
    setsockopt(be_socket_fd, SOL_TCP, TCP_NODELAY, (char *)&optval, sizeof(optval));
    setsockopt(be_socket_fd, SOL_SOCKET, SO_KEEPALIVE, (char *)&optval, sizeof(optval));
}

//PG Client <=====> Proxy
static void connect_fe(const char *ip, uint32_t port)
{
    int optval = 1;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = (long)inet_addr(ip);
    addr.sin_port = htons(port);

    fe_socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (fe_socket_fd < 0)
    {
        printe("sgx_socket error");
        exit(EXIT_FAILURE);
    }
    if (setsockopt(fe_socket_fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(int)) < 0)
    {
        printe("sgx_setsockopt error");
        exit(EXIT_FAILURE);
    }
    if (bind(fe_socket_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        printe("sgx_bind");
        exit(EXIT_FAILURE);
    }
    // if (listen(s, 128) < 0)
    if (listen(fe_socket_fd, 10) < 0)
    {
        printe("sgx_listen error");
        exit(EXIT_FAILURE);
    }

    printf("Proxy IP: %s  Port:%d\n", ip, port);
    printf(" Waiting for PG Client's Request...\n");
    
    if ((fe_connect_fd = accept(fe_socket_fd, (struct sockaddr *)NULL, NULL)) < 0)
    {
        printe("sgx_accept error\n");
        exit(EXIT_FAILURE);
    }
    fe_config();
}

//Proxy <=====> PG Server
static void connect_be(const char *ip, uint32_t port)
{
    struct sockaddr_in dest_addr;

    be_socket_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_IP);
    if (be_socket_fd < 0)
    {
        printe("sgx_socket error");
        exit(EXIT_FAILURE);
    }

    be_config();

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = (long)inet_addr(ip);
    dest_addr.sin_port = htons(port);
    memset(&(dest_addr.sin_zero), '\0', 8);

    if (connect(be_socket_fd, (struct sockaddr *)&dest_addr, sizeof(struct sockaddr)) == -1)
    {
        printe("sgx_connect error");
        exit(EXIT_FAILURE);
    }
    printf("Proxy IP: %s  Port:%d\n", ip, port);
    printf(" Connection with PG Server Succeed!\n");
}

int reconnect(const char *ip, uint32_t port)
{
    fe_connect_fd = accept(fe_socket_fd, (struct sockaddr *)NULL, NULL);
    if (fe_connect_fd < 0)
    {
        printe("Unable to accept");
        exit(EXIT_FAILURE);
    }
    fe_config();
    sgx_close(be_socket_fd);
    be_socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (be_socket_fd < 0)
    {
        printe("Unable to connect");
        exit(EXIT_FAILURE);
    }
    be_config();
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = (long)inet_addr(ip);
    dest_addr.sin_port = htons(port);
    memset(&(dest_addr.sin_zero), '\0', 8);
    connect(be_socket_fd, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    printf("reconnect!\n");
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

void ecall_start_tls_auditor(void)
{
    // SSL_CTX *ctx;

    // printl("OPENSSL Version = %s", SSLeay_version(SSLEAY_VERSION));
    // init_openssl();
    // ctx = create_context();
    // configure_context(ctx);

    // if ((fe_socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)) == -1)
    // {
    //     printe("PG Client <===> Proxy create socket error\n");
    //     exit(EXIT_FAILURE);
    // }
    // memset(&fe_addr, 0, sizeof(fe_addr));
    // fe_addr.sin_family = AF_INET;
    // fe_addr.sin_addr.s_addr = inet_addr(ADDR);
    // printf("Proxy IP: %s\n", ADDR);
    // fe_addr.sin_port = htons(PORT);

    // setsockopt(fe_socket_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval));

    // if (bind(fe_socket_fd, (struct sockaddr *)&fe_addr, sizeof(fe_addr)) == -1)
    // {
    //     printf("PG Client <===> Proxy bind socket error\n");
    //     exit(EXIT_FAILURE);
    // }
    // if (listen(fe_socket_fd, 10) == -1)
    // {
    //     printf("PG Client <===> Proxy listen socket error\n");
    //     exit(EXIT_FAILURE);
    // }
    // printf("======waiting for PG Client's request======\n");

    // if ((fe_connect_fd = accept(fe_socket_fd, (struct sockaddr *)NULL, NULL)) < 0)
    // {
    //     printe("accept socket error\n");
    //     exit(EXIT_FAILURE);
    // }
    // fe_config();

    // if ((be_socket_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_IP)) < 0)
    // {
    //     printf("Proxy <===> PG Server create socket error\n");
    //     exit(EXIT_FAILURE);
    // }

    // be_config();

    // memset(&be_addr, 0, sizeof(be_addr));
    // be_addr.sin_family = AF_INET;
    // be_addr.sin_addr.s_addr = inet_addr(PG_SERV_ADDR);
    // printf("PG Server IP: %s\n", PG_SERV_ADDR);
    // be_addr.sin_port = htons(PG_SERV_PORT);

    // if (connect(be_socket_fd, (struct sockaddr *)&be_addr, sizeof(be_addr)) < 0)
    // {
    //     printf("Proxy <===> PG Server connect error\n");
    //     exit(EXIT_FAILURE);
    // }
    // printf("======waiting for PG Server's response======\n");

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
            cn = sgx_read(fe_connect_fd, fe_buff, MAXBUFF);
            // for (int i = 0; i < 8; i++)
            // {
            //     printf("%c ", fe_buff[i]);
            // }
            // printf("\n");
            if (cn > 0)
            {
                printf("recv msg from client(%d): %d\n", fe_connect_fd, cn);
                if ((send_sn = sgx_write(be_socket_fd, fe_buff, cn)) < 0)
                {
                    printe("send to server error");
                    exit(EXIT_FAILURE);
                }
                printf("send msg to server(%d): %d\n", be_socket_fd, send_sn);
                break;
            }
            else
            {
                // if ((cn < 0) && ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR)))
                if (cn < 0)
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
            sn = sgx_read(be_socket_fd, be_buff, MAXBUFF);
            if (sn > 0)
            {

                printf("recv msg from server(%d): %d\n", be_socket_fd, sn);
                if ((send_cn = sgx_write(fe_connect_fd, be_buff, sn)) < 0)
                {
                    printe("send to client error");
                    exit(EXIT_FAILURE);
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
                // if ((sn < 0) && ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR)))
                if (sn < 0)
                {
                    continue;
                }
                break;
            }
        }
    }

    sgx_close(fe_connect_fd);
    sgx_close(fe_socket_fd);
    sgx_close(be_socket_fd);

    // cli = SSL_new(ctx);
    // SSL_set_fd(cli, fe_connect_fd);
    // if (SSL_accept(cli) <= 0)
    // {
    //     printe("SSL_accept");
    //     exit(EXIT_FAILURE);
    // }

    // printl("ciphersuit: %s", SSL_get_current_cipher(cli)->name);
    // /* Receive buffer from TLS server */
    // r = SSL_read(cli, read_buf, sizeof(read_buf));
    // printl("read_buf: length = %d : %s", r, read_buf);
    // memset(read_buf, 0, sizeof(read_buf));

    // printl("Close SSL/TLS client");
    // SSL_free(cli);
    // sgx_close(fe_connect_fd);
    // }

    // sgx_close(fe_socket_fd);
    // SSL_CTX_free(ctx);
    // cleanup_openssl();
}
