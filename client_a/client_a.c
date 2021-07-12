#include <stdio.h>                                                       
#include <netdb.h>                                                       
#include <netinet/in.h>                                                  
#include <stdlib.h>                                                      
#include <string.h>                                                      
#include <unistd.h>                                                      
#include <sys/socket.h>                                                  
#include <sys/types.h>
#include <arpa/inet.h>

#include <time.h>
#include <malloc.h>
#include <resolv.h>
#include <pthread.h>

#include "openssl/ssl.h"
#include "openssl/err.h"

#define MAX_BUFF 65535
#define SA struct sockaddr

int OpenConnection(const char *hostname, int port)
{
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;
    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}

int func(int sockfd)
{
    char buff[MAX_BUFF];
    char* msg;
    int n;
    int msg_size;
    char* tcp_msg;
    
    // Begin Handshake
    bzero(buff, sizeof(buff));
    write(sockfd, "hello", 5);
    
    bzero(buff, sizeof(buff));
    read(sockfd, buff, sizeof(buff));
    if ((strncmp(buff, "hello", 5)) != 0) {
        printf("Handshake fail\n");
        return 0;
    }
    printf("Hello from server!\n");
    bzero(buff, sizeof(buff));
    msg_size = read(sockfd, buff, sizeof(buff));
    if (msg_size>0)
    {
        tcp_msg = malloc(msg_size);
        for (int i=0;i<msg_size;i++)
            tcp_msg[i]=buff[i];
    }    
    printf("Signature received (%d): \n%s \n",msg_size, tcp_msg );
    
    
    for (;;) {
        bzero(buff, sizeof(buff));
        printf("Enter the string : ");
        n = 0;
        while ((buff[n++] = getchar()) != '\n');
            
        write(sockfd, buff, sizeof(buff));
        bzero(buff, sizeof(buff));
        read(sockfd, buff, sizeof(buff));
        printf("From Server : %s", buff);
        if ((strncmp(buff, "exit", 4)) == 0) {
            printf("Client Exit...\n");
            break;
        }
    }
}
  
int main(int count, char *args[])
{
    char *hostname; 
    int portnum;
    if ( count != 3 )
    {
        printf("usage: %s <hostname> <portnum>\n", args[0]);
        exit(0);
    }
    hostname=args[1];  
    portnum = atoi(args[2]); 
    if (portnum > 65535 || portnum <= 0) // check if inserted port number is in range
    {
        printf("Port Number %d is out of range\n", portnum);
        exit(0);
    }
    
    int sockfd = OpenConnection(hostname, portnum);
    // function for chat
    func(sockfd);
  
    // close the socket
    close(sockfd);
} 
