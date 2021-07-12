#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
 
#include <limits.h> // for INT_MAX
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>

//multithreading
#include <pthread.h>

#define FAIL    -1

SSL *ssl;

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
SSL_CTX* InitCTX(void)
{
    SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    //method = TLSv1_2_client_method();  /* Create new client-method instance */
    method = TLS_client_method();
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

X509 *ShowCerts(SSL* ssl)
{
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("Info: No client certificates configured.\n");
    
    return cert;
}

void check_msg_authentication(unsigned char* clear_text, unsigned char* signed_text, X509* cert)
{
   
    
    
}

void *listen_server(void *vargp)
{
    int bytes = 0;
    char buf[1024];
    printf("Enter loop\n");
    while(1){
            //printf("waiting for msg...\n");
            bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */            
            if (bytes>0){
                buf[bytes] = 0;
                printf("Received (%d): \"%s\"\n",bytes, buf);
            }
        }
        SSL_free(ssl);        /* release connection state */
    
}

void *ping_loop(void *vargp)
{
    for(;;)
    {
        printf("Ping\n\n");
        sleep(2);
    }
}


int main(int count, char *strings[])
{
    SSL_CTX *ctx;
    int server;
    //SSL *ssl;
    char buf[1024];
    char acClientRequest[1024] = {0};
    int bytes = 1;
    char *hostname, *portnum;
    if ( count != 3 )
    {
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }
    SSL_library_init();
    hostname=strings[1];
    portnum=strings[2];
    ctx = InitCTX();
    server = OpenConnection(hostname, atoi(portnum));
    ssl = SSL_new(ctx);      /* create new SSL connection state */
    SSL_set_fd(ssl, server);    /* attach the socket descriptor */
    if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
        ERR_print_errors_fp(stderr);
    else
    {
        char acUsername[16] = {0};
        char acPassword[16] = {0};
        const char *cpRequestMessage = "test";
        //"<Body>\
        //                       <UserName>%s<UserName>\
        //         <Password>%s<Password>\
        //         <\Body>";
        printf("Enter your Registered User Name: ");
        scanf("%16s",acUsername);
        //printf("\n\nEnter the Password : ");
        //scanf("%16s",acPassword);
        sprintf(acClientRequest, cpRequestMessage, acUsername, acPassword);   /* construct reply */
        printf("\n\nConnected with %s encryption\n", SSL_get_cipher(ssl));
        printf("\n\nsprintf %s \n", acClientRequest);
        ShowCerts(ssl);        /* get any certs */
        //SSL_write(ssl,acClientRequest, strlen(acClientRequest));   /* encrypt & send message */
        //SSL_write(ssl,acUsername, strlen(acUsername));   /* encrypt & send message */
        
        FILE* privkey_file = fopen("privkey.pem", "r");
        EVP_PKEY * rsa_priv = PEM_read_PrivateKey(privkey_file, NULL, "alicepwd", NULL);
        if (rsa_priv){printf("privkey OPEN!\n");}
        
        for (;;);
        //char msg[] = "Lorem ipsum dolor sit amet.";
        //unsigned char* signature;
        //int signature_len;
        //signature = malloc(EVP_PKEY_size(privkey_file));
        //EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        //EVP_SignInit(ctx, EVP_sha256());
        //EVP_SignUpdate(ctx, (unsigned char*)msg, sizeof(msg));
        //EVP_SignFinal(ctx, signature, &signature_len, prvkey);
        //EVP_MD_CTX_free(ctx);
        //
        //SSL_write(ssl,acUsername, strlen(acUsername));
        
        pthread_t thread_id1, thread_id2;
        printf("Before Thread\n");
        pthread_create(&thread_id1, NULL, listen_server, NULL);
        pthread_create(&thread_id2, NULL, ping_loop, NULL);
        pthread_join(thread_id1, NULL);
        pthread_join(thread_id2, NULL);
        printf("After Thread\n");
        for(;;);
        
        //listen_server(ssl);
        while(1){
            //printf("waiting for msg...\n");
            bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
            buf[bytes] = 0;
            if (bytes>0){
                printf("Received (%d): \"%s\"\n",bytes, buf);}
        }
        SSL_free(ssl);        /* release connection state */
    }
    close(server);         /* close socket */
    SSL_CTX_free(ctx);        /* release context */
    return 0;
} 
