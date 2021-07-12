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

#define MAX_BUFF 80                                                           
#define PORT 8081                                                        
#define SA struct sockaddr
#define MAX_CHANNELS    2

struct client_id {
    char* username;
    int connfd;
};

struct client_id usr_data[MAX_CHANNELS];
int server_sockfd;
pthread_mutex_t mutex_channel[MAX_CHANNELS];

                                                                         
int MessageApp_OpenListener(int port)                                               
{                                                                        
    int sd;
    struct sockaddr_in addr;                                          
    sd = socket(PF_INET, SOCK_STREAM, 0);                                
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        abort();
    }
    if ( listen(sd, 10) != 0 )
    {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}


int MessageApp_launch_param_check (int n_input, char* args[])
{
    int input_port;
    
    if (n_input != 2) // if inserted wrong amount of paramters
    {
        printf("Error inserting parameters\n Use: %s <port>", args[0]);
        return 0;
    }
    
    input_port = atoi(args[1]); 
    if (input_port > 65535 || input_port <= 0) // check if inserted port number is in range
    {
        printf("Port Number %d is out of range\n", input_port);
        return 0;
    }
    // if no erros detected
    return input_port;
}

void *MessageApp_client_connect(void *vargp)
{
    int channel = 0;
    for (int i=0;i<MAX_CHANNELS;i++) // lock all channels - wait for client connection to release them
    {
        pthread_mutex_lock(&mutex_channel[i]);
        printf("Channel %d Locked\n", i);
    }
    
    for(;;)
    {        
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        
        // Now server is ready to listen and verification
        if ((listen(server_sockfd, 5)) != 0) {
            printf("Listen failed...\n");
            exit(0);
        }
        else
            printf("\nWaiting for User connection...\n");

        // Accept the data packet from client and verification
        usr_data[channel].connfd = accept(server_sockfd, (struct sockaddr*)&addr, &len);
        if (usr_data[channel].connfd < 0) {
            printf("server acccept failed...\n");
            exit(0);
        }
        else
            printf("Server acccepted client in channel %d\n", channel);
        
        
                
        pthread_mutex_unlock(&mutex_channel[channel]); // release the communication channel
        channel++;
    }
 
}


// Function designed for chat between client and server.
void* MessageApp_channel_0(void *vargp)
{
    char buff[MAX_BUFF];
    int channel = 0;
    int n;
    int msg_size;
    int usrname_rec = 0;
    
    pthread_mutex_lock(&mutex_channel[0]);    
    printf("Channel 0 Connected (Non-Secure)\nBegin Handshake...");
    
    // begin HANDSHAKE protocol
    bzero(buff, MAX_BUFF);
    msg_size = read(usr_data[channel].connfd, buff, sizeof(buff));
    
    
    
    // infinite loop for chat
    for (;;)
    {
        bzero(buff, MAX_BUFF);
  
        // read the message from client and copy it in buffer
        msg_size = read(usr_data[channel].connfd, buff, sizeof(buff));
        // print buffer which contains the client contents
        if (msg_size>0 && msg_size<65535)
        {
            if (usrname_rec==0){
                usr_data[channel].username = malloc(msg_size);
                for (int i=0;i<msg_size;i++)
                    usr_data[channel].username = buff;
                usrname_rec=1;
                printf("USERNAME From client: %s\n", usr_data[channel].username);
            }
            else
                printf("From client: %s\n", buff);        
        }
        else
            printf("ERROR in msg From client");
        
        bzero(buff, MAX_BUFF);
        n = 0;
        printf("Send client: ");
        // copy server message in the buffer
        while ((buff[n++] = getchar()) != '\n');
            
  
        // and send that buffer to client
        write(usr_data[channel].connfd, buff, sizeof(buff));
  
        // if msg contains "Exit" then server exit and chat ended.
        if (strncmp("exit", buff, 4) == 0) {
            printf("Server Exit...\n");
            break;
        }
    }
    close(server_sockfd);
    for(;;);
}
  
// Driver function
int main(int n_input, char *input_args[])
{
    pthread_t thread_id[MAX_CHANNELS+1];
    
    int port = MessageApp_launch_param_check(n_input, input_args);
    if ( port>0)
        printf("MessageApp Server launched !! connection port: %d\n\n", port);
    else
    {
        printf("MessageApp launch FAILED\n");
        exit(0);
    }
    
    server_sockfd = MessageApp_OpenListener(port);
  
    pthread_create(&thread_id[0], NULL, MessageApp_client_connect, NULL);
    pthread_create(&thread_id[1], NULL, MessageApp_channel_0, NULL);
    
    pthread_join(thread_id[0], NULL);
    pthread_join(thread_id[1], NULL);
    // Function for chatting between client and server
    // func(connfd);
  
    // After chatting close the socket
    close(server_sockfd);
} 

