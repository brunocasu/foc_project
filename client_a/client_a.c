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
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>


#define MAX_BUFF 65535
#define SA struct sockaddr

char* Username;
    
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

int ClientHandshake(int sockfd)
{
    char *buff = malloc(MAX_BUFF);
    int msg_size;
    char* tcp_msg;
    int ret_val;
    
    // Begin Handshake
    write(sockfd, "hello", 5);
    free(buff);
    
    buff = malloc(MAX_BUFF);
    msg_size = read(sockfd, buff, MAX_BUFF);
    if ((msg_size>0)&&(msg_size<MAX_BUFF))
    {
        if ((strncmp(buff, "hello", 5)) != 0) {
            printf("Handshake fail\n");
            return 0;
        }
    }
    printf("hello from server!\n");
    free(buff);
    
    buff = malloc(MAX_BUFF);
    msg_size = read(sockfd, buff, MAX_BUFF);
    if ((msg_size>0)&&(msg_size<MAX_BUFF))
    {
        tcp_msg = malloc(msg_size);
        for (int i=0;i<msg_size;i++)
            tcp_msg[i]=buff[i];
    }
    free(buff);
    printf("Server Signature received (%d): \n",msg_size);
    
    /** BEGIN VERIFY SIGNATURE USING SERVER CERTIFICATE */
    FILE* cert_file = fopen("MessageApp_cert.pem", "r");
    if(cert_file==NULL){printf("Certificate File Open Error\n"); return 0;}
    X509* cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    fclose(cert_file);
    if(cert==NULL){printf("Error: PEM_read_X509 returned NULL\n"); return 0;}
    
    char* tmp = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    char* tmp2 = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
    printf("Certificate of %s\n issued by %s\n",tmp, tmp2);
    free(tmp);
    free(tmp2);
    
    const EVP_MD* md = EVP_sha256();
    // create the signature context:
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if(md_ctx==NULL){printf("Error: EVP_MD_CTX_new returned NULL\n"); return 0;}
    
    ret_val = EVP_VerifyInit(md_ctx, md);
    if(ret_val == 0){printf("Error: EVP_VerifyInit returned NULL\n"); return 0;}
    ret_val = EVP_VerifyUpdate(md_ctx, "hello", 5);  
    if(ret_val == 0){printf("Error: EVP_VerifyUpdate returned NULL\n"); return 0;}
    ret_val = EVP_VerifyFinal(md_ctx, tcp_msg, msg_size, X509_get_pubkey(cert));
    if(ret_val==1)
        printf("Server Authenticated!\n");
    else{
        printf("Server Authentication FAILED (%d)\n", ret_val);
        return 0;}
    EVP_MD_CTX_free(md_ctx);
    free(tcp_msg);
    /** END VERIFY SIGNATURE USING SERVER CERTIFICATE */
    
    /** BEGIN ENCRYPT username USING SERVER RSA PUBKEY */
    Username = malloc(16);
    printf("Enter your Registered User Name: ");
    scanf("%16s", Username);
   
    printf("User Name <%s> (%ld) \n",Username, strlen(Username));
    EVP_PKEY* pubkey = X509_get_pubkey(cert); // Retrieve SERVER PUBKEY from the certificate
    X509_free(cert); // certificate is not used anymore
    
    unsigned char *out;
    size_t outlen;
    
    EVP_PKEY_CTX* ctx_p = EVP_PKEY_CTX_new(pubkey, NULL);
    if (ctx_p==NULL){printf("Error: EVP_PKEY_CTX_new returned NULL\n"); return 0;}
    
    ret_val = EVP_PKEY_encrypt_init(ctx_p);
    if(ret_val <= 0){printf("Error: EVP_PKEY_encrypt_init\n"); return 0;}
    
    ret_val = EVP_PKEY_CTX_set_rsa_padding(ctx_p, RSA_PKCS1_OAEP_PADDING);
    if(ret_val <= 0){printf("Error: EVP_PKEY_CTX_set_rsa_padding\n"); return 0;}

    // Determine buffer size for encrypted length
    if (EVP_PKEY_encrypt(ctx_p, NULL, &outlen, Username, strlen(Username)) <= 0){printf("Error: EVP_PKEY_encrypt\n"); return 0;}
            
    out = OPENSSL_malloc(outlen);
    if (out==NULL){printf("Malloc failed for username encryption\n"); return 0;}

    // encrypt using server pubkey
    ret_val = EVP_PKEY_encrypt(ctx_p, out, &outlen, Username, strlen(Username));
    if (ret_val<=0){printf("ENCRYPTION Error: EVP_PKEY_encrypt\n"); return 0;}
    
    // free(out);
    EVP_PKEY_CTX_free(ctx_p);
    EVP_PKEY_free(pubkey);
    /** END ENCRYPT username USING SERVER RSA PUBKEY */
    
    /** BEGIN COMPUTE CLIENT SIGNATURE USING RSA PRIVKEY  */
    FILE* privkey_file = fopen("privkey.pem", "r");
    if(privkey_file==NULL){printf("Privkey File Open Error\n"); return 0;}
    EVP_PKEY* privkey = PEM_read_PrivateKey(privkey_file, NULL, NULL, NULL);
    fclose(privkey_file);
    if(privkey==NULL){printf("Password Incorrect!!\n"); return 0; }
    else{printf("Password Correct!\n");}
    
    md_ctx = EVP_MD_CTX_new();
    if(md_ctx==NULL){printf("Error: EVP_MD_CTX_new returned NULL\n"); return 0;}
    
    unsigned char* sgnt_buf = (unsigned char*)malloc(EVP_PKEY_size(privkey));
    if(sgnt_buf==NULL) {printf("Error: malloc returned NULL\n"); return 0;}
    
    ret_val = EVP_SignInit(md_ctx, md);
    if(ret_val == 0){printf("Error: EVP_SignInit returned %d\n",ret_val); return 0;}
    ret_val = EVP_SignUpdate(md_ctx, Username, strlen(Username));
    if(ret_val == 0){printf("Error: EVP_SignUpdate returned %d\n",ret_val); return 0;}
    unsigned int sgnt_size;
    ret_val = EVP_SignFinal(md_ctx, sgnt_buf, &sgnt_size, privkey);
    if(ret_val == 0){printf("Error: EVP_SignFinal returned %d\n",ret_val); return 0;}
    
    // delete the digest from memory:
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(privkey);
    
    printf("Send username encrypted with server rsa pubkey (%ld)\n", outlen);
    write(sockfd, out, outlen);
    sleep(1);
    printf("Send Client Signature (%d)\n", sgnt_size);
    write(sockfd, sgnt_buf, sgnt_size);
    free(sgnt_buf);
    /** END COMPUTE CLIENT SIGNATURE USING RSA PRIVKEY  */ 
    
    
    // session key = sha 256 (IV)
    // encrypt "finish" in AES_256_CGM
    
    // finished handshake
    
    return 1;
}    
    
int func(int sockfd)
{   
    char buff[MAX_BUFF];
    int n;
    
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
    char* buff = malloc(16);
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
    
    //printf("\nEnter your privkey password: ");
    //scanf("%16s",buff);
    //Password = malloc(strlen(buff));
    //if(Password){
    //    for(int i=0;i<strlen(buff);i++)
    //        Password[i]=buff[i];
    //}
    //free(buff);
    int sockfd = OpenConnection(hostname, portnum);

    ClientHandshake(sockfd);
    // function for chat
    func(sockfd);
  
    // close the socket
    close(sockfd);
} 
