//
//  socks5.c
//  SOCKS5
//
//  Created by Kevin on 2016/12/15.
//  Copyright © 2016年 Kevin. All rights reserved.
//

#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/select.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <netdb.h>

#define PORT htons(9998)
#define BUFFSIZE 8192

#define ERR_EXIT(x) \
do { perror(x); exit(1); } while ( 0 )

#define ERR_RETURN(x) \
do { perror(x); return(-1); } while ( 0 )

#define STA_AUTH 1
#define STA_RQST 2
#define STA_TRAS 3

typedef struct connection {
    int  client;
    int  server;
    unsigned char status: 2;
} connection;

connection *connections[FD_SETSIZE];
char        buff[BUFFSIZE];
fd_set      read_events, write_events;

int  set_fd(int fd, int flag);
void Close(int fd);
int  noblock_connect(char *dst, unsigned short port);

int handle_auth(int fd);
int handle_rqst(int fd);
int handle_tras(int fd);

int main(int argc, const char * argv[]) {

    int sockfd;
    if ( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 )
        ERR_EXIT("socket() error");

    set_fd(sockfd, O_NONBLOCK);

    struct sockaddr_in addr;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_family      = AF_INET;
    addr.sin_port        = PORT;

    int reuse = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
        ERR_EXIT("SO_REUSEADDR error");

    if ( bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0 )
        ERR_EXIT("bind() error");

    if ( listen(sockfd, 50) < 0 )
        ERR_EXIT("listen() error");

    fd_set read_testevs, write_testevs;
    FD_ZERO(&read_events);
    FD_ZERO(&write_events);

    FD_SET(sockfd, &read_events);

    while ( 1 ) {

        FD_ZERO(&read_testevs);
        FD_ZERO(&write_testevs);

        read_testevs  = read_events;
        write_testevs = write_events;

        int result = select(FD_SETSIZE, &read_testevs, &write_testevs, NULL, NULL);

        if ( result == -1 )
            ERR_EXIT("select() error");

        if ( result == 0 )
            continue;

        for ( int fd = 0; fd < FD_SETSIZE; fd++ ) {

            /* Assume we have a connections that client = x, server = x + y(y>0), both client and server are readable, but this con was closed
             during handle client fd(x), the con struct will be freed, and connections[server] will be set to NULL, then when we reach
             server fd (server's fd is larger than client's), we got a NULL, so we need to check if connection still exist before handle it.
             */

            if ( fd != sockfd && connections[fd] == NULL )
                continue;

            if ( FD_ISSET(fd, &read_testevs) ) {

                if ( fd == sockfd ) {
                    // new connection
                    struct sockaddr_in client;
                    socklen_t len = sizeof(client);
                    int c_fd;
                    if ( (c_fd = accept(sockfd, (struct sockaddr *)&client, &len)) < 0 ) {
                        perror("cannot accept()");
                        break;
                    } else {
                        char address[INET_ADDRSTRLEN];
                        printf("%s connected\n", inet_ntop(AF_INET, &client.sin_addr, address, INET_ADDRSTRLEN));
                        set_fd(c_fd, O_NONBLOCK);
                        FD_SET(c_fd, &read_events);
                        connection *new = (connection*)malloc(sizeof(connection));
                        if ( new == NULL )
                            ERR_EXIT("cannot malloc");
                        new->client = c_fd;
                        new->server = -1;
                        new->status = STA_AUTH;
                        connections[c_fd] = new;
                    }

                } else {

                    // read events
                    int size;
                    ioctl(fd, FIONREAD, &size);
                    int server_fd;

                    if ( size <= 0 ) {
                        // connected closed
                        printf("%d %d disconnected\n", size, fd);
                        Close(fd);
                        continue;
                    } else {
                        switch (connections[fd]->status) {
                            case STA_AUTH:
                                if (handle_auth(fd))
                                    Close(fd);
                                else
                                    connections[fd]->status = STA_RQST;
                                break;
                            case STA_RQST:
                                if ( (server_fd = handle_rqst(fd)) < 0 )
                                    Close(fd);
                                else {
                                    FD_SET(server_fd, &write_events);
                                    FD_SET(server_fd, &read_events);
                                    /*
                                     if server_fd connect failed, it will be returned in select()'s read_set and readable bytes is zero
                                     so it's necessary to add it in read_set to handle it when it failed.
                                     */
                                    connections[fd]->server = server_fd;
                                    connections[server_fd]  = connections[fd];
                                }
                                break;
                            case STA_TRAS:
                                if (handle_tras(fd))
                                    Close(fd);
                                break;
                            default:
                                printf("unknown connection status");
                                Close(fd);
                                break;
                        }
                        continue;
                    }
                }
            }

            /*
             If a nonblock connect() fd successfully established, it will be writeable and returned by select in write_set.
             if a nonblock connect() fd failed, it will returned by select in both write_set and read_set, and readable bytes is zero,
             so if check read_set first and determine close the fd or not according to readable bytes, it can handle the failed
             case correctly.
             */

            // write event only be used to handle successfully connect().
            if ( FD_ISSET(fd, &write_testevs) ) {
                if ( connections[fd]->status == STA_RQST ) {
                    char reply[] = "\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00";
                    int len = sizeof(reply) - 1;
                    unsigned short port = PORT;
                    memcpy(&reply[len-1], &port, sizeof(port));

                    if ( send(connections[fd]->client, reply, len, 0) != len ) {
                        if ( errno != EAGAIN ) {
                            printf("send() error");
                            Close(fd);
                        }
                    } else {
                        FD_CLR(fd, &write_events);
                        connections[fd]->status = STA_TRAS;
                        printf("connected to server fd: %d\n", fd);
                    }
                }
            }

        }
    }

    return 0;
}

int handle_auth(int fd) {
    const char reply[] = "\x05\x00";
    size_t len         = sizeof(reply) - 1;
    ssize_t n;
    if ( (n = recv(fd, buff, BUFFSIZE, MSG_PEEK)) < 0 ) {
        perror("recv error");
        return -1;
    }
    buff[n] = 0;
    if ( buff[0] == '\x05' ) {
        if ( send(fd, reply, len, 0) != len ) {
            if ( errno == EAGAIN  )
                return 0;
            else return -1;
        }
        if ( recv(fd, buff, n, 0) < 0 ) {
            perror("recv error");
            return -1;
        }
        return 0;
    } else {
        printf("unexpected SOCKS VERSION\n");
        return -1;
    }
}

int handle_rqst(int fd) {
    ssize_t n;
    if ( (n = recv(fd, buff, BUFFSIZE, 0)) < 0 ) {
        perror("recv error");
        return -1;
    }
    if ( buff[0] != '\x05' ) {
        printf("unexpected SOCKS VERSION\n");
        return -1;
    }
    if ( buff[1] != '\x01' ) {
        printf("Unsupported CMD\n");
        return -1;
    }
    if ( buff[2] != '\x00' ) {
        printf("SOCKS FORMAT ERROR\n");
        return -1;
    }

   // char address[INET_ADDRSTRLEN] = {0};
    char domain[0xff] = {0};

    unsigned short port;

//    if ( buff[3] == '\x01' ) {
//        printf("abasdf\n");
//        memcpy(address, &buff[4], INET_ADDRSTRLEN - 1);
//        memcpy(&port, &buff[n-1], 2);
//    }

    if ( buff[3] == '\x03' ) {
        char len = buff[4];
        memcpy(domain, &buff[5], len);
        domain[len] = 0;
        memcpy(&port, &buff[5+len], 2);
        port = ntohs(port);
        printf("%s %d\n", domain, port);
        return noblock_connect(domain, port);
    }

    printf("Unsupported Address Type\n");
    return -1;

}

int handle_tras(int fd) {

    if ( connections[fd] ) {
        int server = connections[fd]->server;
        int client = connections[fd]->client;
        int out;

        if ( fd == server )
            out = client;
        else if ( fd == client )
            out = server;
        else {
            printf("unexpected fd");
            return -1;
        }

        ssize_t nread, nwrite;

        if ( (nread = recv(fd, buff, BUFFSIZE, MSG_PEEK)) < 0 ) {
            perror("recv() error");
            return -1;
        }

        if ( (nwrite = send(out, buff, nread, 0)) < 0 ) {
            if ( errno == EAGAIN ) {
                return 0;
            }
            perror("send() error");
            return -1;
        }

        if ( recv(fd, buff, nwrite, 0) != nwrite ) {
            perror("recv() error");
            return -1;
        }

        printf("%s\n", fd == connections[fd]->server ? "in" : "out");
        return 0;

    }
    return -1;
}

int noblock_connect(char *dst, unsigned short port) {

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);

    struct hostent *host;
    if ( inet_pton(AF_INET, dst, &addr.sin_addr) == 0 ) {
        if ((host = gethostbyname(dst)) == NULL) {
            printf("cannot resolve addr %s\n", dst);
            return -1;
        }
        memcpy(&addr.sin_addr, host->h_addr, host->h_length);
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    set_fd(fd, O_NONBLOCK);
    if ( connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0 ) {
        if ( errno != EINPROGRESS ) {
            perror("connect() error");
            return -1;
        }
    }
    return fd;
}

int set_fd(int fd, int flag) {
    int f;
    if ( (f = fcntl(fd, F_GETFL, 0)) < 0 )
        ERR_RETURN("F_GETFL error");

    f |= flag;

    if ( fcntl(fd, F_SETFL, f) < 0 )
        ERR_RETURN("F_SETFL error");

    return 0;
}

void Close(int fd) {
    if (connections[fd]) {

        int client = connections[fd]->client;
        int server = connections[fd]->server;

        if ( client >= 0 ) {
            FD_CLR(client, &read_events);
            FD_CLR(client, &write_events);
        }
        if ( server >= 0 ) {
            FD_CLR(server, &read_events);
            FD_CLR(server, &write_events);
        }
        if ( server > 0 )
            close(server);
        if ( client > 0 )
            close(client);

        free(connections[fd]);

        connections[server] = NULL;
        connections[client] = NULL;
    }
}
