//
//  ss_server.c
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
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/select.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <netdb.h>

#define PORT      htons(9998)
#define BUFFSIZE  8192
#define KEY       "whatthefuck"

#define ERR_EXIT(x) \
do { perror(x); exit(1); } while ( 0 )

#define ERR_RETURN(x) \
do { perror(x); return(-1); } while ( 0 )

#define STA_IV   0
#define STA_AUTH 1
#define STA_RQST 2
#define STA_TRAS 3

typedef struct aes_cfb128 {
    unsigned char iv[AES_BLOCK_SIZE];
    int num;
    unsigned char buffer[BUFFSIZE];
    int current_index;
    int buff_remain;
} aes_cfb128;

typedef struct connection {
    int  client;
    int  server;
    unsigned char status: 2;
    aes_cfb128 encryption;
    aes_cfb128 decryption;
} connection;

connection *connections[FD_SETSIZE];
char buff[BUFFSIZE];
fd_set read_events, write_events;

void Encrypt(unsigned char *in, unsigned char *out, size_t len, unsigned char* iv, unsigned char *key, int *num, int enc);
int set_fd(int fd, int flag);
void Close(int fd);
int noblock_connect(char *dst, unsigned short port);

int handle_iv(int fd);

int handle_auth(int fd);
int handle_rqst(int fd);
int handle_tras(int fd_r);

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
                        new->status = STA_IV;
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
                            case STA_IV:
                                if ( handle_iv(fd) )
                                    Close(fd);
                                else
                                    connections[fd]->status = STA_AUTH;
                                break;
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
                                    connections[server_fd] = connections[fd];
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
                    }
                    continue;
                }
            }
            
            /*
             If a nonblock connect() fd successfully established, it will be writeable and returned by select in write_set.
             if a nonblock connect() fd failed, it will returned by select in both write_set and read_set, and readable bytes is zero,
             so if check read_set first and determine close the fd or not according to readable bytes, it can handle the failed
             case correctly.
             */
            
            // read event only be used to handle successfully connect().
            if ( FD_ISSET(fd, &write_testevs) ) {
                if ( connections[fd]->status == STA_RQST ) {
                    char reply[] = "\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00";
                    int len = sizeof(reply) - 1;
                    unsigned short port = PORT;
                    memcpy(&reply[len-1], &port, sizeof(port));
                    
                    unsigned char *cipher = connections[fd]->encryption.buffer;
                    Encrypt(reply, cipher, len, connections[fd]->encryption.iv, KEY, &connections[fd]->encryption.num, AES_ENCRYPT);
                    
                    if ( send(connections[fd]->client, cipher, len, 0) != len ) {
                            Close(fd);
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

int handle_iv(int fd) {
    
    if ( recv(fd, buff, AES_BLOCK_SIZE, 0) != AES_BLOCK_SIZE ) {
        ERR_RETURN("recv0 error");
        return -1;
    }
    
    memcpy(connections[fd]->decryption.iv, buff, AES_BLOCK_SIZE);
    memcpy(connections[fd]->encryption.iv, buff, AES_BLOCK_SIZE);
    
    connections[fd]->decryption.buff_remain   = connections[fd]->encryption.buff_remain   = 0;
    connections[fd]->decryption.current_index = connections[fd]->encryption.current_index = 0;
    connections[fd]->decryption.num           = connections[fd]->encryption.num           = 0;
    
    return 0;
}

int handle_auth(int fd) {
    const int  reply_len = 2;
    const char *reply    = "\x05\x00";
    char       cipher[reply_len];

    ssize_t n;
    if ( (n = recv(fd, buff, BUFFSIZE, 0)) < 0 ) {
        perror("recv1 error");
        return -1;
    }

    Encrypt(buff, connections[fd]->decryption.buffer, n, connections[fd]->decryption.iv, KEY, &connections[fd]->decryption.num, AES_DECRYPT);
    char version = connections[fd]->decryption.buffer[0];
    
    if ( version == 0x05 ) {
        Encrypt(reply, cipher, reply_len, connections[fd]->encryption.iv, KEY, &connections[fd]->encryption.num, AES_ENCRYPT);
        if ( send(fd, cipher, reply_len, 0) != reply_len )
            return -1;
        return 0;
    } else {
        return -1;
    }
}

int handle_rqst(int fd) {
    ssize_t n;
    if ( (n = recv(fd, buff, BUFFSIZE, 0)) < 0 ) {
        perror("recv3 error");
        return -1;
    }

    unsigned char *plain_buf = connections[fd]->decryption.buffer;
 
    Encrypt(buff, plain_buf, n, connections[fd]->decryption.iv, KEY, &connections[fd]->decryption.num, AES_DECRYPT);
    
    printf("\n");
    if ( plain_buf[0] != '\x05' ) {
        printf("unexpected SOCKS VERSION\n");
        return -1;
    }
    if ( plain_buf[1] != '\x01' ) {
        printf("Unsupported CMD\n");
        return -1;
    }
    if ( plain_buf[2] != '\x00' ) {
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
    
    if ( plain_buf[3] == '\x03' ) {
        char len = plain_buf[4];
        memcpy(domain, &plain_buf[5], len);
        domain[len] = 0;
        memcpy(&port, &plain_buf[5+len], 2);
        port = ntohs(port);
        printf("%s %d\n", domain, port);
        return noblock_connect(domain, port);
    }
    
    printf("Unsupported Address Type\n");
    return -1;
    
}

int handle_tras(int fd_r) {
    
    connection  *con   = connections[fd_r];
    aes_cfb128  *cbuf  = NULL;
    char         fd_w  = -1;
    int          enc   = -1;
    
    if ( fd_r == con->server ) { // data from remote server, encrypt data.
        cbuf  = &con->encryption;
        fd_w  = con->client;
        enc   = AES_ENCRYPT;
        
    } else if ( fd_r == con->client ) {  // data from ss client, decrypt data.
        cbuf  = &con->decryption;
        fd_w  = con->server;
        enc   = AES_DECRYPT;
        
    } else return -1;
    
    ssize_t n, m;
    
    if ( cbuf->buff_remain == 0 ) {
        if ( (n = recv(fd_r, buff, BUFSIZ, MSG_PEEK)) < 0 )
            ERR_RETURN("recv4 error");
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
        ERR_RETURN("recv5 error");
    
    return 0;
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

void Encrypt(unsigned char *in, unsigned char *out, size_t len, unsigned char* iv, unsigned char *key, int *num, int enc) {
    
    unsigned char keybit[256 / 8]; // 256 bits;
    bzero(keybit, 256 / 8);
    memcpy(keybit, key, strlen(key));
    
    AES_KEY e_key;
    AES_set_encrypt_key(keybit, 256, &e_key);
    
    unsigned char iv_ec[AES_BLOCK_SIZE];
    memcpy(iv_ec, iv, AES_BLOCK_SIZE);
    
    AES_cfb128_encrypt(in, out, len, &e_key, iv_ec, num, enc);
    
    memcpy(iv, iv_ec, AES_BLOCK_SIZE);
    
}
