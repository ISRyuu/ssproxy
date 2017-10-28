//
//  ss_client.c
//  SOCKS5
//
//  Created by Kevin on 2016/12/15.
//  Copyright © 2016年 Kevin. All rights reserved.
//

#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>

#define BUFSIZE 4096
#define PORT      htons(9999)
#define S_PORT    htons(9998)
#define SERVER    "127.0.0.1"
#define KEY       "whatthefuck"

#define ERR_EXIT(x) \
do { perror("x"); exit(1); } while ( 0 )

#define ERR_RETURN(x) \
do { perror("x"); return(1); } while ( 0 )

typedef struct aes_cfb128 {
    unsigned char iv[AES_BLOCK_SIZE];
    int num;
    unsigned char buffer[BUFSIZE];
    int current_index;
    int buff_remain;
} aes_cfb128;

typedef struct connection {
    int server;
    int client;
    aes_cfb128 encryption;
    aes_cfb128 decryption;
} connection;

void Encrypt(unsigned char *in, unsigned char *out, size_t len, unsigned char* iv, unsigned char *key, int *num, int enc);
int set_fd(int fd, int flag);
int nonblock_connection_to_server();
int INIT_AES(aes_cfb128 *aes);
int trans_data(int fd_r);
void Close(int fd);

struct connection* connections[FD_SETSIZE];
char *buff[BUFSIZE];
fd_set write_set, read_set;

int main(int argc, char ** argv) {

    int sock;
    if ( (sock = socket(AF_INET, SOCK_STREAM, 0)) < 0 )
        ERR_EXIT("socket() error");

    int reuse = 1;
    if ( setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0 )
        ERR_EXIT("SO_REUSEADDR error");

    struct sockaddr_in addr;
    addr.sin_addr.s_addr   = htonl(INADDR_ANY);
    addr.sin_port          = PORT;
    addr.sin_family        = AF_INET;

    if ( bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0 )
        ERR_EXIT("bind() error");

    if ( listen(sock, 50) < 0 )
        ERR_EXIT("listen error");

    set_fd(sock, O_NONBLOCK);

    fd_set write_test, read_test;

    FD_ZERO(&write_set);
    FD_ZERO(&read_set);

    FD_SET(sock, &read_set);

    while ( 1 ) {
        read_test  = read_set;
        write_test = write_set;

        int result = select(FD_SETSIZE, &read_test, &write_test, NULL, NULL);

        if ( result == 0 )
            continue;

        if ( result < 0 )
            ERR_EXIT("select() error");

        for ( int fd = 0; fd < FD_SETSIZE; fd++ ) {

            if ( fd != sock && connections[fd] == NULL )
                continue;

            // read event
            if ( FD_ISSET(fd, &read_test) ) {

                // new connection
                if ( fd == sock ) {
                    char straddr[INET_ADDRSTRLEN];
                    struct sockaddr_in addr;
                    socklen_t len = sizeof(addr);
                    int new  = accept(sock, (struct sockaddr*)&addr, &len);
                    if ( new < 0 ) {
                        perror("cannot accept");
                        continue;
                    }
                    if ( set_fd(new, O_NONBLOCK) ) {
                        close(new);
                        continue;
                    }
                    connection* con = (struct connection*)malloc(sizeof(connection));
                    if ( con == NULL ) {
                        perror("cannot malloc");
                        close(new);
                        continue;
                    }
                    con->client = new;
                    con->server = -1;
                    if ( INIT_AES(&con->encryption) ) {
                        printf("RAND_bytes error");
                        close(new);
                        free(con);
                        continue;
                    }
                    memcpy(con->decryption.iv, con->encryption.iv, sizeof(con->encryption.iv));
                    con->decryption.num           = 0;
                    con->decryption.buff_remain   = 0;
                    con->decryption.current_index = 0;
                    if ( (con->server = nonblock_connection_to_server()) < 0 ) {
                        close(new);
                        free(con);
                        continue;
                    }
                    FD_SET(con->server, &read_set);
                    FD_SET(con->server, &write_set);

                    connections[new]         = con;
                    connections[con->server] = con;
                    printf("%s connected, %d\n", inet_ntop(AF_INET, &addr.sin_addr, straddr, INET_ADDRSTRLEN), con->server);
                } else {
                    int size;
                    ioctl(fd, FIONREAD, &size);

                    if ( size <= 0 ) {
                        Close(fd);
                        printf("%d disconnected\n", fd);
                        continue;
                    }

                    trans_data(fd);
                }
                continue;
            }

            // write event
            if ( FD_ISSET(fd, &write_test) ) {
                if ( !FD_ISSET(connections[fd]->client, &read_set) ) {
                    int size = AES_BLOCK_SIZE;
                    if ( send(fd, connections[fd]->encryption.iv, size, 0) != size ) {
                        perror("send() IV error");
                        Close(fd);
                        continue;
                    }
                    FD_CLR(fd, &write_set);
                    FD_SET(connections[fd]->client, &read_set); // All works done, start to handle client data.
                    printf("connected to remote server, fd: %d\n", fd);
                    continue;
                }
                Close(fd);
            }

        }
    }

    return 0;
}

void Close(int fd) {
    if ( connections[fd] ) {
        int client = connections[fd]->client;
        int server = connections[fd]->server;
        FD_CLR(client, &read_set);
        FD_CLR(client, &write_set);
        FD_CLR(server, &read_set);
        FD_CLR(server, &write_set);

        if ( client > 0 )
            close(client);
        if ( server > 0 )
            close(server);

        free(connections[fd]);

        connections[client] = NULL;
        connections[server] = NULL;
    }
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

int nonblock_connection_to_server() {
    int sockfd;
    if ( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 )
        ERR_RETURN("socket() error");

    if ( set_fd(sockfd, O_NONBLOCK) )
        return -1;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port   = S_PORT;
    inet_pton(AF_INET, SERVER, &addr.sin_addr);

    if ( connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0 ) {
        if ( errno == EINPROGRESS )
            return sockfd;
        else {
            perror("connect() error");
            return -1;
        }
    }
    return sockfd;
}

int trans_data(int fd_r) {

    connection  *con   = connections[fd_r];
    aes_cfb128  *cbuf  = NULL;
    char         fd_w  = -1;
    int          enc   = -1;

    if ( fd_r == con->server ) { // data from ss server, need decryption.
        cbuf  = &con->decryption;
        fd_w  = con->client;
        enc   = AES_DECRYPT;

    } else if ( fd_r == con->client ) {  // data from client, need encryption.
        cbuf  = &con->encryption;
        fd_w  = con->server;
        enc   = AES_ENCRYPT;

    } else return -1;

    ssize_t n, m;

    if ( cbuf->buff_remain == 0 ) {
        if ( (n = recv(fd_r, buff, BUFSIZ, MSG_PEEK)) < 0 )
            ERR_RETURN("recv() error");
        Encrypt(buff, cbuf->buffer, n, cbuf->iv, KEY, &cbuf->num, enc);
        cbuf->buff_remain   = n;
        cbuf->current_index = 0;
    }

    if ( (m = send(fd_w, cbuf->buffer + cbuf->current_index, cbuf->buff_remain, 0)) < 0 ) {
        if ( errno == EAGAIN )
            return 0;
         else
            ERR_RETURN("send() error");
    }

    cbuf->buff_remain   -= m;
    cbuf->current_index += m;

    if ( (n = recv(fd_r, buff, m, 0)) != m )
        ERR_RETURN("recv() error");

    return 0;
}

int INIT_AES(aes_cfb128 *aes) {
    if ( !RAND_bytes(aes->iv, AES_BLOCK_SIZE) )
        return -1;
    aes->num           = 0;
    aes->current_index = 0;
    aes->buff_remain   = 0;
    return 0;
}

void Encrypt(unsigned char *in, unsigned char *out, size_t len, unsigned char* iv, unsigned char *key, int *num, int enc) {

    unsigned char keybit[256 / 8] = {0}; // 256 bits;
    memcpy(keybit, key, strlen(key));

    AES_KEY e_key;
    AES_set_encrypt_key(keybit, 256, &e_key);

    unsigned char iv_ec[AES_BLOCK_SIZE];
    memcpy(iv_ec, iv, AES_BLOCK_SIZE);

    AES_cfb128_encrypt(in, out, len, &e_key, iv_ec, num, enc);

    memcpy(iv, iv_ec, AES_BLOCK_SIZE);

}
