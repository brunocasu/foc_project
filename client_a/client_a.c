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
unsigned char* iv;
unsigned char session_key[32];
int sockfd;
    
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

// return size of encrypted_msg
int EncryptAES_256_GCM( unsigned char* encrypted_msg,
                        unsigned char* clear_msg, int msg_len, 
                        unsigned char* aad, int aad_len,
                        unsigned char* iv,
                        unsigned char* key,
                        unsigned char* tag)
{
    int len=0;
    int ciphertext_len=0;
    int ret_val;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx==NULL){printf("Error encrypt EVP_CIPHER_CTX_new returned NULL\n"); return -1;}

    ret_val = EVP_EncryptInit(ctx, EVP_aes_256_gcm(), key, iv);
    if (ret_val<=0){printf("Error EVP_EncryptInit\n"); return -1;}

    ret_val = EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len);
    if (ret_val<=0){printf("Error EVP_EncryptUpdate AAD\n"); return -1;}

    ret_val = EVP_EncryptUpdate(ctx, encrypted_msg, &len, clear_msg, msg_len);
    if (ret_val<=0){printf("Error EVP_EncryptUpdate plaintext\n"); return -1;}

    ciphertext_len = len;
	//Finalize Encryption
    if(1 != EVP_EncryptFinal(ctx, encrypted_msg + len, &len))
    if (ret_val<=0){printf("Error EVP_EncryptFinal\n"); return -1;}

    ciphertext_len += len;
    
    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag))
    {printf("Error EVP_CIPHER_CTX_ctrl GET TAG\n"); return -1;}
  
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
} 


// return size of decrypted_msg
int DecryptAES_256_GCM( unsigned char* clear_msg,
                        unsigned char* encrypted_msg, int encrypted_len, 
                        unsigned char* aad, int aad_len,
                        unsigned char* iv,
                        unsigned char* key,
                        unsigned char* tag)
{
    int len;
    int plaintext_len;
    int ret;
    int ret_val;
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx==NULL){printf("Error encrypt EVP_CIPHER_CTX_new returned NULL"); return -1;}
    
    ret_val = EVP_DecryptInit(ctx, EVP_aes_256_gcm(), key, iv);
    if (ret_val<=0){printf("Error EVP_DecryptInit"); return -1;}
    
	//Provide any AAD data.
    ret_val = EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len);
    if (ret_val<=0){printf("Error EVP_DecryptUpdate"); return -1;}
    
	//Provide the message to be decrypted, and obtain the plaintext output.
    ret_val = EVP_DecryptUpdate(ctx, clear_msg, &len, encrypted_msg, encrypted_len);
    if (ret_val<=0){printf("Error EVP_DecryptUpdate"); return -1;}
    
    plaintext_len = len;
    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    ret_val = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag);
    if (ret_val<=0){printf("Error EVP_DecryptUpdate"); return -1;}
    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal(ctx, clear_msg + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_cleanup(ctx);

    if(ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        return -1;
    } 
}

// return number of bytes sent via TCP
int server_secure_send(int sockfd, unsigned char* iv, unsigned char* session_key, unsigned char* send_text, int text_len)
{
    RAND_poll();
    unsigned char* out=malloc(MAX_BUFF);
    unsigned char *aad="AABBCCDDSSKKGGOO";
    //RAND_bytes(aad, 16);
    unsigned char tag[16];
    printf("\nBEGIN Encryption using Shared KEY\n" );
    int outlen = EncryptAES_256_GCM(out, send_text, text_len, aad, 16, iv, session_key, tag);    
    if (outlen<=0){printf("Error: EncryptAES_256_GCM\n"); return 0;}
    
    unsigned char* enc_finish = malloc(outlen+16+16);
    
    for (int v=0;v<16;v++)
        enc_finish[v] = aad[v];
    for (int v=0;v<16;v++)
        enc_finish[v+16] = tag[v];
    for (int v=0;v<outlen;v++)
        enc_finish[v+32] = out[v];

    free(out);    
    /** END ENCRYPT "finish" using SESSION KEY and AES 256 GCM */

    printf("AAD is: ");
    for (int k=0;k<16;k++){
        printf("%02x ", (unsigned char)enc_finish[k]);
    }    
    printf("\nTag is: ");
    for (int k=16;k<32;k++){
        printf("%02x ", (unsigned char)enc_finish[k]);
    }
    printf("\nCyp is: " );
    for (int k=32;k<outlen+32;k++){
        printf("%02x ", (unsigned char)enc_finish[k]);
    }
    
    /** SEND encrypted "finish" using SESSION KEY */
    printf("\nSend finish encrypted mag (%d) \n", outlen+16+16);
    write(sockfd, enc_finish, outlen+16+16);
}

// retuns received text length
int server_secure_receive(int sockfd, unsigned char* iv, unsigned char* key, unsigned char* clear_text)
{
    char* buff = malloc(MAX_BUFF);
    char* tcp_msg;
    int msg_size;
    unsigned char rec_aad[16];
    unsigned char rec_tag[16];
    
    printf("WAITING Message in server Secure Channel...\n");
    msg_size = read(sockfd, buff, MAX_BUFF);

    if ((msg_size>32)&&(msg_size<MAX_BUFF))
    {
        tcp_msg = malloc(msg_size-32);
        for(int i=0;i<16;i++){rec_aad[i] = buff[i];}
        for(int i=0;i<16;i++){rec_tag[i] = buff[i+16];}
        for(int i=0;i<msg_size;i++){tcp_msg[i]=buff[i+32];}            
    }
    else { return 0;}
    free(buff);
    
    unsigned char decrypt_buff[MAX_BUFF];
    int clear_len = DecryptAES_256_GCM(decrypt_buff, tcp_msg, msg_size-32, rec_aad, 16, iv, key, rec_tag);
    if (clear_len<0){printf("AES DECRYPTION FAILED"); return 0;}

    clear_text = malloc(clear_len);
    for (int i=0;i<clear_len;i++)
        clear_text[i] = decrypt_buff[i];
    return clear_len;
}




int ClientHandshake(int sockfd)
{
    char *buff = malloc(MAX_BUFF);
    int msg_size;
    char* tcp_msg;
    int ret_val;
    
    // Begin Handshake
    /** SEND "hello" */
    write(sockfd, "hello", 5);
    free(buff);
    
    /** RECEIVE "hello"*/
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
    
    /** RECEIVE server signature */
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
    
    ret_val = EVP_VerifyInit(md_ctx, EVP_sha256());
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
    //EVP_MD_free(md);
    free(tcp_msg);
    /** END VERIFY SIGNATURE USING SERVER CERTIFICATE */
    
    
    /** BEGIN ENCRYPT username USING SERVER RSA PUBKEY */
    Username = malloc(16);
    printf("Enter your Registered User Name: ");
    scanf("%16s", Username);
    
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
    
    md = EVP_sha256();
    ret_val = EVP_SignInit(md_ctx, EVP_sha256());
    if(ret_val == 0){printf("Error: EVP_SignInit returned %d\n",ret_val); return 0;}
    ret_val = EVP_SignUpdate(md_ctx, Username, strlen(Username));
    if(ret_val == 0){printf("Error: EVP_SignUpdate returned %d\n",ret_val); return 0;}
    unsigned int sgnt_size;
    ret_val = EVP_SignFinal(md_ctx, sgnt_buf, &sgnt_size, privkey);
    if(ret_val == 0){printf("Error: EVP_SignFinal returned %d\n",ret_val); return 0;}
    
    // delete the digest from memory:
    EVP_MD_CTX_free(md_ctx);
    //EVP_MD_free(md);
    /** END COMPUTE CLIENT SIGNATURE USING RSA PRIVKEY  */ 
    
    /** SEND E(username)server_pubkey + client signature*/
    printf("Send username encrypted with server rsa pubkey (%ld)\n", outlen);
    write(sockfd, out, outlen);
    sleep(1);
    printf("Send Client Signature (%d)\n", sgnt_size);
    write(sockfd, sgnt_buf, sgnt_size);
    free(sgnt_buf);
    free(out);
    /** RECEIVE encrypted IV from server */
    buff = malloc(MAX_BUFF);
    msg_size = read(sockfd, buff, MAX_BUFF);
    printf("Encrypted IV received (%d)\n",msg_size);
    if ((msg_size>0)&&(msg_size<MAX_BUFF)) // maximum size for username is 16
    {
        tcp_msg = malloc(msg_size);
        for (int i=0;i<msg_size;i++)
            tcp_msg[i]=buff[i];
    }
    else {printf("Failed to receive IV\n"); return 0;}
    free(buff);
    
    /** BEGIN DECRYPT IV USING RSA PRIVKEY */
    // tcp_msg <- username encrypted by pubkey
    // decrypt IV using privkey
    
    // Decrypt Received Message using privkey
    ctx_p = EVP_PKEY_CTX_new(privkey, NULL);
    if (ctx_p==NULL){printf("Error: EVP_PKEY_CTX_new returned NULL\n"); return 0;}
    if (EVP_PKEY_decrypt_init(ctx_p) <= 0){printf("Error: EVP_PKEY_decrypt_init returned NULL\n"); return 0;}
    if (EVP_PKEY_CTX_set_rsa_padding(ctx_p, RSA_PKCS1_OAEP_PADDING) <= 0){printf("Error: EVP_PKEY_CTX_set_rsa_padding returned NULL\n"); return 0;}
    /* Determine buffer length */
    if (EVP_PKEY_decrypt(ctx_p, NULL, &outlen, tcp_msg, msg_size) <= 0){printf("Error: EVP_PKEY_decrypt returned NULL\n"); return 0;}
    
    iv = malloc(outlen);
    if (!iv){printf("Malloc Failed for IV\n"); return 0;}
        
    ret_val = EVP_PKEY_decrypt(ctx_p, iv, &outlen, tcp_msg, msg_size);
    if (ret_val<=0){printf("DECRYPTION Error: EVP_PKEY_decrypt\n"); return 0;}
    
    EVP_PKEY_free(privkey);
    EVP_PKEY_CTX_free(ctx_p);
    free(tcp_msg);
    printf("DECRYPTED IV (%ld): %s\n",outlen, iv);
    /** END DECRYPT IV USING RSA PRIVKEY  */
    
    
    /** BEGIN GENERATE FRESH SESSION KEY */
    size_t iv_len = outlen;
    unsigned char* digest;
    unsigned int digestlen;
    
    md_ctx = EVP_MD_CTX_new();
    if(md_ctx==NULL){printf("Error: EVP_MD_CTX_new returned NULL\n"); return 0;}
    
    digest = (unsigned char* ) malloc(EVP_MD_size(EVP_sha256()));
    if(digest==NULL){printf("Error: malloc failed for digest\n"); return 0;}
    

    ret_val = EVP_DigestInit(md_ctx, EVP_sha256());
    if(ret_val<=0){printf("Error: DigestInit returned NULL\n"); return 0;}
    ret_val = EVP_DigestUpdate(md_ctx, iv, iv_len);
    if(ret_val<=0){printf("Error: DigestUpdate returned NULL\n"); return 0;}
    ret_val = EVP_DigestFinal(md_ctx, digest, &digestlen);
    if(ret_val<=0){printf("Error: DigestFinal returned NULL\n"); return 0;}
    
    EVP_MD_CTX_free(md_ctx);
    //EVP_MD_free(md);
    printf("Digest is (%d): ", digestlen);
    // session_key = malloc(digestlen);
    for (int k=0;k<digestlen;k++){
        session_key[k] = digest[k];
        printf("%02x ", (unsigned char)session_key[k]);
    }
    //*key_len = digestlen;
    free(digest);
    /** END GENERATE FRESH SESSION KEY */
    
    
    /** BEGIN ENCRYPT "finish" using SESSION KEY and AES 256 GCM */
    RAND_poll();
    unsigned char *aad="AABBCCDDSSKKGGOO";
    //RAND_bytes(aad, 16);
    unsigned char tag[16];
    printf("\nBEGIN Encryption using Shared KEY\n" );
    outlen = EncryptAES_256_GCM(out, "finish", 6, aad, 16, iv, session_key, tag);    
    if (outlen<=0){printf("Error: EncryptAES_256_GCM\n"); return 0;}
    
    unsigned char* enc_finish = malloc(outlen+16+16);
    
    for (int v=0;v<16;v++)
        enc_finish[v] = aad[v];
    for (int v=0;v<16;v++)
        enc_finish[v+16] = tag[v];
    for (int v=0;v<outlen;v++)
        enc_finish[v+32] = out[v];    
    /** END ENCRYPT "finish" using SESSION KEY and AES 256 GCM */

    printf("AAD is: ");
    for (int k=0;k<16;k++){
        printf("%02x ", (unsigned char)enc_finish[k]);
    }    
    printf("\nTag is: ");
    for (int k=16;k<32;k++){
        printf("%02x ", (unsigned char)enc_finish[k]);
    }
    printf("\nCyp is: " );
    for (int k=32;k<outlen+32;k++){
        printf("%02x ", (unsigned char)enc_finish[k]);
    }
    
    /** SEND encrypted "finish" using SESSION KEY */
    printf("\nSend finish encrypted shared Key (%ld) \n", outlen+16+16);
    write(sockfd, enc_finish, outlen+16+16);
    // free(enc_finish);

    /** RECEIVE encrypted "finish" using SESSION KEY */
    //buff = malloc(MAX_BUFF);
    //msg_size = read(sockfd, buff, MAX_BUFF);
    //printf("Encrypted Finish received (%d)\n",msg_size);
    //unsigned char rec_aad[16];
    //unsigned char rec_tag[16];
    //if ((msg_size>32)&&(msg_size<MAX_BUFF)) // maximum size for username is 16
    //{
    //    tcp_msg = malloc(msg_size);
    //    for(int a=0;a<16;a++){rec_aad[a] = buff[a];}
    //    for(int t=16;t<32;t++){rec_tag[t] = buff[t];}
    //    for(int i=32;i<msg_size;i++){tcp_msg[i]=buff[i];}
    //        
    //}
    //else {printf("Failed to receive Finish\n"); return 0;}
    //free(buff);
    //
    ///** BEGIN DECRYPT "finish" using SESSION KEY and AES 256 GCM */
    //unsigned char* clear_msg = malloc(MAX_BUFF);
    //int val = DecryptAES_256_GCM(clear_msg, tcp_msg, msg_size-32, rec_aad, 16, iv, session_key, rec_tag);
    ///** END DECRYPT "finish" using SESSION KEY and AES 256 GCM */
    //
    //printf("clear_msg (%d): %s\n",val, clear_msg);
    // finished handshake
    
    return 1;
}    
    
void* sender_Task(void *vargp)
{   
    char *sbuff;
    int len;
    int n;
    
    for (;;) {
        sbuff = malloc(32);
        printf("\nSESSION IV: ");
        printf("%s", iv);
            
        printf("\nType[cmd][param]->");
        n = 0;
        len = scanf("%32s", sbuff);
        
        server_secure_send(sockfd, iv, session_key, sbuff, len);
        free(sbuff);
    }
}

void* receiver_Task(void *vargp)
{   
    char *buff;
    int n;
    
    for (;;) {
        buff = malloc(MAX_BUFF);
        
        printf("\nclient waiting...");
        read(sockfd, buff, MAX_BUFF);
        printf("\nFrom Server : %s\n", buff);
        if ((strncmp(buff, "exit", 4)) == 0) {
            printf("Client Exit...\n");
            break;
        }
        free(buff);
        
    }
}
  
int main(int count, char *args[])
{
    char* buff = malloc(16);
    char *hostname; 
    int portnum;
    pthread_t rec_id, sen_id;
    
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
    sockfd = OpenConnection(hostname, portnum);

    if (ClientHandshake(sockfd) == 1){
        printf("\nCONNECTED to MessageApp\n");
        // function for chat
        pthread_create(&rec_id, NULL, receiver_Task, NULL);
        pthread_create(&sen_id, NULL, sender_Task, NULL);
    
        pthread_join(rec_id, NULL);
        pthread_join(sen_id, NULL);
    }
    // close the socket
    close(sockfd);
} 
