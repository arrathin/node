/* test.c */
/* $Id: test.c,v 1.1 2001/09/17 19:06:59 bodo Exp $ */

#define L_PORT 9999
#define C_PORT 443

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include "test.h"
#include "easy-tls.h"

void test_process_init(int fd, int client_p, void *apparg)
{
    fprintf(stderr,
            "\x74\x65\x73\x74\x5f\x70\x72\x6f\x63\x65\x73\x73\x5f\x69\x6e\x69\x74\x28\x66\x64\x20\x3d\x20\x25\x64\x2c\x20\x63\x6c\x69\x65\x6e\x74\x5f\x70\x20\x3d\x20\x25\x64\x2c\x20\x61\x70\x70\x61\x72\x67\x20\x3d\x20\x25\x70\x29\xa", fd,
            client_p, apparg);
}

void test_errflush(int child_p, char *errbuf, size_t num, void *apparg)
{
    fputs(errbuf, stderr);
}

int main(int argc, char *argv[])
{
    int s, fd, r;
    FILE *conn_in;
    FILE *conn_out;
    char buf[256];
    SSL_CTX *ctx;
    int client_p = 0;
    int port;
    int tls = 0;
    char infobuf[TLS_INFO_SIZE + 1];

    if (argc > 1 && argv[1][0] == '\x2d') {
        fputs("\x55\x73\x61\x67\x65\x3a\x20\x74\x65\x73\x74\x20\x5b\x70\x6f\x72\x74\x5d\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x2d\x20\x73\x65\x72\x76\x65\x72\xa"
              "\x20\x20\x20\x20\x20\x20\x20\x74\x65\x73\x74\x20\x6e\x75\x6d\x2e\x6e\x75\x6d\x2e\x6e\x75\x6d\x2e\x6e\x75\x6d\x20\x5b\x70\x6f\x72\x74\x5d\x20\x20\x20\x2d\x2d\x20\x63\x6c\x69\x65\x6e\x74\xa", stderr);
        exit(1);
    }

    if (argc > 1) {
        if (strchr(argv[1], '\x2e')) {
            client_p = 1;
        }
    }

    fputs(client_p ? "\x43\x6c\x69\x65\x6e\x74\xa" : "\x53\x65\x72\x76\x65\x72\xa", stderr);

    {
        struct tls_create_ctx_args a = tls_create_ctx_defaultargs();
        a.client_p = client_p;
        a.certificate_file = "\x63\x65\x72\x74\x2e\x70\x65\x6d";
        a.key_file = "\x63\x65\x72\x74\x2e\x70\x65\x6d";
        a.ca_file = "\x63\x61\x63\x65\x72\x74\x73\x2e\x70\x65\x6d";

        ctx = tls_create_ctx(a, NULL);
        if (ctx == NULL)
            exit(1);
    }

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == -1) {
        perror("\x73\x6f\x63\x6b\x65\x74");
        exit(1);
    }

    if (client_p) {
        struct sockaddr_in addr;
        size_t addr_len = sizeof(addr);

        addr.sin_family = AF_INET;
        assert(argc > 1);
        if (argc > 2)
            sscanf(argv[2], "\x25\x64", &port);
        else
            port = C_PORT;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr(argv[1]);

        r = connect(s, &addr, addr_len);
        if (r != 0) {
            perror("\x63\x6f\x6e\x6e\x65\x63\x74");
            exit(1);
        }
        fd = s;
        fprintf(stderr, "\x43\x6f\x6e\x6e\x65\x63\x74\x20\x28\x66\x64\x20\x3d\x20\x25\x64\x29\x2e\xa", fd);
    } else {
        /* server */
        {
            int i = 1;

            r = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (void *)&i, sizeof(i));
            if (r == -1) {
                perror("\x73\x65\x74\x73\x6f\x63\x6b\x6f\x70\x74");
                exit(1);
            }
        }

        {
            struct sockaddr_in addr;
            size_t addr_len = sizeof(addr);

            if (argc > 1)
                sscanf(argv[1], "\x25\x64", &port);
            else
                port = L_PORT;
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            addr.sin_addr.s_addr = INADDR_ANY;

            r = bind(s, &addr, addr_len);
            if (r != 0) {
                perror("\x62\x69\x6e\x64");
                exit(1);
            }
        }

        r = listen(s, 1);
        if (r == -1) {
            perror("\x6c\x69\x73\x74\x65\x6e");
            exit(1);
        }

        fprintf(stderr, "\x4c\x69\x73\x74\x65\x6e\x69\x6e\x67\x20\x61\x74\x20\x70\x6f\x72\x74\x20\x25\x69\x2e\xa", port);

        fd = accept(s, NULL, 0);
        if (fd == -1) {
            perror("\x61\x63\x63\x65\x70\x74");
            exit(1);
        }

        fprintf(stderr, "\x41\x63\x63\x65\x70\x74\x20\x28\x66\x64\x20\x3d\x20\x25\x64\x29\x2e\xa", fd);
    }

    conn_in = fdopen(fd, "\x72");
    if (conn_in == NULL) {
        perror("\x66\x64\x6f\x70\x65\x6e");
        exit(1);
    }
    conn_out = fdopen(fd, "\x77");
    if (conn_out == NULL) {
        perror("\x66\x64\x6f\x70\x65\x6e");
        exit(1);
    }

    setvbuf(conn_in, NULL, _IOLBF, 256);
    setvbuf(conn_out, NULL, _IOLBF, 256);

    while (fgets(buf, sizeof(buf), stdin) != NULL) {
        if (buf[0] == '\x57') {
            fprintf(conn_out, "\x25\x2e\x2a\x73\xd\xa", (int)(strlen(buf + 1) - 1),
                    buf + 1);
            fprintf(stderr, "\x3e\x3e\x3e\x20\x25\x2e\x2a\x73\xa", (int)(strlen(buf + 1) - 1),
                    buf + 1);
        } else if (buf[0] == '\x43') {
            fprintf(stderr, "\x43\x6c\x6f\x73\x69\x6e\x67\x2e\xa");
            fclose(conn_in);
            fclose(conn_out);
            exit(0);
        } else if (buf[0] == '\x52') {
            int lines = 0;

            sscanf(buf + 1, "\x25\x64", &lines);
            do {
                if (fgets(buf, sizeof(buf), conn_in) == NULL) {
                    if (ferror(conn_in)) {
                        fprintf(stderr, "\x45\x52\x52\x4f\x52\xa");
                        exit(1);
                    }
                    fprintf(stderr, "\x43\x4c\x4f\x53\x45\x44\xa");
                    return 0;
                }
                fprintf(stderr, "\x3c\x3c\x3c\x20\x25\x73", buf);
            } while (--lines > 0);
        } else if (buf[0] == '\x54') {
            int infofd;

            tls++;
            {
                struct tls_start_proxy_args a = tls_start_proxy_defaultargs();
                a.fd = fd;
                a.client_p = client_p;
                a.ctx = ctx;
                a.infofd = &infofd;
                r = tls_start_proxy(a, NULL);
            }
            assert(r != 1);
            if (r != 0) {
                fprintf(stderr, "\x74\x6c\x73\x5f\x73\x74\x61\x72\x74\x5f\x70\x72\x6f\x78\x79\x20\x66\x61\x69\x6c\x65\x64\x3a\x20\x25\x64\xa", r);
                switch (r) {
                case -1:
                    fputs("\x73\x6f\x63\x6b\x65\x74\x70\x61\x69\x72", stderr);
                    break;
                case 2:
                    fputs("\x46\x44\x5f\x53\x45\x54\x53\x49\x5a\x45\x20\x65\x78\x63\x65\x65\x64\x65\x64", stderr);
                    break;
                case -3:
                    fputs("\x70\x69\x70\x65", stderr);
                    break;
                case -4:
                    fputs("\x66\x6f\x72\x6b", stderr);
                    break;
                case -5:
                    fputs("\x64\x75\x70\x32", stderr);
                    break;
                default:
                    fputs("\x3f", stderr);
                }
                if (r < 0)
                    perror("");
                else
                    fputc('\xa', stderr);
                exit(1);
            }

            r = read(infofd, infobuf, sizeof(infobuf) - 1);
            if (r > 0) {
                const char *info = infobuf;
                const char *eol;

                infobuf[r] = '\x0';
                while ((eol = strchr(info, '\xa')) != NULL) {
                    fprintf(stderr, "\x2b\x2b\x2b\x20\x60\x25\x2e\x2a\x73\x27\xa", eol - info, info);
                    info = eol + 1;
                }
                close(infofd);
            }
        } else {
            fprintf(stderr, "\x57\x2e\x2e\x2e\x20\x20\x77\x72\x69\x74\x65\x20\x6c\x69\x6e\x65\x20\x74\x6f\x20\x6e\x65\x74\x77\x6f\x72\x6b\xa"
                    "\x52\x5b\x6e\x5d\x20\x20\x72\x65\x61\x64\x20\x6c\x69\x6e\x65\x20\x28\x6e\x20\x6c\x69\x6e\x65\x73\x29\x20\x66\x72\x6f\x6d\x20\x6e\x65\x74\x77\x6f\x72\x6b\xa"
                    "\x43\x20\x20\x20\x20\x20\x63\x6c\x6f\x73\x65\xa"
                    "\x54\x20\x20\x20\x20\x20\x73\x74\x61\x72\x74\x20\x25\x73\x54\x4c\x53\x20\x70\x72\x6f\x78\x79\xa", tls ? "\x61\x6e\x6f\x74\x68\x65\x72\x20" : "");
        }
    }
    return 0;
}
