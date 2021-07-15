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


#define MAX_BUFF 65535                                                           
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
pthread_mutex_t mutex_handshake;
                                                                         
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
    if (ctx==NULL){printf("Error encrypt EVP_CIPHER_CTX_new returned NULL"); return -1;}
    
    ret_val = EVP_EncryptInit(ctx, EVP_aes_256_gcm(), key, iv);
    if (ret_val<=0){printf("Error EVP_EncryptInit"); return -1;}

    ret_val = EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len);
    if (ret_val<=0){printf("Error EVP_EncryptUpdate AAD"); return -1;}

    ret_val = EVP_EncryptUpdate(ctx, encrypted_msg, &len, clear_msg, msg_len);
    if (ret_val<=0){printf("Error EVP_EncryptUpdate plaintext"); return -1;}
    
    ciphertext_len = len;
	//Finalize Encryption
    if(1 != EVP_EncryptFinal(ctx, encrypted_msg + len, &len))
    if (ret_val<=0){printf("Error EVP_EncryptFinal"); return -1;}
    
    ciphertext_len += len;
    
    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag))
    {printf("Error EVP_CIPHER_CTX_ctrl GET TAG"); return -1;}
        
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

int MessageApp_handshake(int channel, unsigned char* session_key, unsigned int* key_len)
{
    char* buff = malloc(MAX_BUFF);
    char* tcp_msg;
    int ret_val;
    int msg_size;
    
    pthread_mutex_lock(&mutex_handshake);
    /** RECEIVE Client hello */
    msg_size = read(usr_data[channel].connfd, buff, MAX_BUFF);
    if ((msg_size>0)&&(msg_size<MAX_BUFF))
    {
        tcp_msg = malloc(msg_size);
        for (int i=0;i<msg_size;i++)
            tcp_msg[i]=buff[i];
    }
    else {printf("Failed to receive hello from Client \n"); return 0;}
    free(buff);
    if(strcmp("hello",tcp_msg) != 0)
        return 0;
    
    /** BEGIN COMPUTE AND SEND SIGNATURE USING RSA PRIVKEY  */
    FILE* privkey_file = fopen("MessageApp_key.pem", "r");
    if(privkey_file==NULL){printf("Privkey File Open Error\n"); return 0;}
    EVP_PKEY* privkey = PEM_read_PrivateKey(privkey_file, NULL, NULL, NULL);
    fclose(privkey_file);
    if(privkey==NULL){printf("Error: PEM_read_PrivateKey returned NULL\n"); return 0; }
    
    const EVP_MD* md = EVP_sha256();
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if(md_ctx==NULL){printf("Error: EVP_MD_CTX_new returned NULL\n"); return 0;}
    
    unsigned char* sgnt_buf = (unsigned char*)malloc(EVP_PKEY_size(privkey));
    if(sgnt_buf==NULL) {printf("Error: malloc returned NULL\n"); return 0;}
    
    ret_val = EVP_SignInit(md_ctx, EVP_sha256());
    if(ret_val == 0){printf("Error: EVP_SignInit returned %d\n",ret_val); return 0;}
    ret_val = EVP_SignUpdate(md_ctx, "hello", 5);
    if(ret_val == 0){printf("Error: EVP_SignUpdate returned %d\n",ret_val); return 0;}
    unsigned int sgnt_size;
    ret_val = EVP_SignFinal(md_ctx, sgnt_buf, &sgnt_size, privkey);
    if(ret_val == 0){printf("Error: EVP_SignFinal returned %d\n",ret_val); return 0;}
    printf("Server Signature size (%d)\n", sgnt_size);
    // delete the digest from memory:
    EVP_MD_CTX_free(md_ctx);
    //EVP_MD_free(md);
    EVP_PKEY_free(privkey);
    free(tcp_msg);
    
    /** SEND "hello" + signature */
    write(usr_data[channel].connfd, "hello", 5);
    sleep(1);
    write(usr_data[channel].connfd, sgnt_buf, sgnt_size);
    printf("Server Signature sent (%d) in Channel (%d)\nWaiting for Client Username...\n", sgnt_size, channel);
    free(sgnt_buf);
    /** END COMPUTE AND SEND SIGNATURE USING RSA PRIVKEY  */
    
    /** RECEIVE encrypted username from client */
    buff = malloc(MAX_BUFF);
    msg_size = read(usr_data[channel].connfd, buff, MAX_BUFF);
    printf("Encrypted Username received (%d)\n",msg_size);
    if ((msg_size>0)&&(msg_size<MAX_BUFF)) // maximum size for username is 16
    {
        tcp_msg = malloc(msg_size);
        for (int i=0;i<msg_size;i++)
            tcp_msg[i]=buff[i];
    }
    else {printf("Failed to receive Username\n"); return 0;}
    free(buff);
    
    /** BEGIN DECRYPT username MESSAGE USING RSA PRIVKEY */
    // tcp_msg <- username encrypted by pubkey
    // decrypt using privkey
    privkey_file = fopen("MessageApp_key.pem", "r");
    if(privkey_file==NULL){printf("Privkey File Open Error\n"); return 0;}
    privkey = PEM_read_PrivateKey(privkey_file, NULL, NULL, NULL);
    fclose(privkey_file);
    if(privkey==NULL){printf("Error: PEM_read_PrivateKey returned NULL\n"); return 0; }
    
    unsigned char *decrypted_msg;
    size_t outlen;
    // Decrypt Received Message using privkey
    EVP_PKEY_CTX* ctx_p = EVP_PKEY_CTX_new(privkey, NULL);
    if (ctx_p==NULL){printf("Error: EVP_PKEY_CTX_new returned NULL\n"); return 0;}
    if (EVP_PKEY_decrypt_init(ctx_p) <= 0){printf("Error: EVP_PKEY_decrypt_init returned NULL\n"); return 0;}
    if (EVP_PKEY_CTX_set_rsa_padding(ctx_p, RSA_PKCS1_OAEP_PADDING) <= 0){printf("Error: EVP_PKEY_CTX_set_rsa_padding returned NULL\n"); return 0;}
    /* Determine buffer length */
    if (EVP_PKEY_decrypt(ctx_p, NULL, &outlen, tcp_msg, msg_size) <= 0){printf("Error: EVP_PKEY_decrypt returned NULL\n"); return 0;}
    
    decrypted_msg = OPENSSL_malloc(outlen);
    if (!decrypted_msg){printf("Malloc Failed for decrypted message\n"); return 0;}
        
    ret_val = EVP_PKEY_decrypt(ctx_p, decrypted_msg, &outlen, tcp_msg, msg_size);
    if (ret_val<=0){printf("DECRYPTION Error: EVP_PKEY_decrypt\n"); return 0;}
    
    EVP_PKEY_free(privkey);
    EVP_PKEY_CTX_free(ctx_p);
    free(tcp_msg);
    printf("DECRYPTED username (%ld): %s\n",outlen, decrypted_msg);
    /** END DECRYPT username MESSAGE USING RSA PRIVKEY  */
    
    /** RECEIVE Client Signature */
    buff = malloc(MAX_BUFF);
    msg_size = read(usr_data[channel].connfd, buff, MAX_BUFF);
    printf("Encrypted Client Signature received (%d)\n",msg_size);
    if ((msg_size>0)&&(msg_size<MAX_BUFF)) 
    {
        tcp_msg = malloc(msg_size);
        for (int i=0;i<msg_size;i++)
            tcp_msg[i]=buff[i];
    }
    else {printf("Failed to receive Client Signature \n"); return 0;}
    free(buff);
    
    /** BEGIN VERIFY CLIENT AUTENTICITY USING REGISTERED PUBKEY */
    char *pubkey_extension = "key.pem";
    char *filename = malloc(outlen+7);
    for (int i=0;i<outlen;i++)
        filename[i] = decrypted_msg[i];
    for (int n=0;n<7;n++)
        filename[n+outlen] = pubkey_extension[n];
    
    printf("Trying to open: <%s> \n", filename);
    FILE* clientpubkey_file = fopen(filename, "r");
    if(clientpubkey_file==NULL){printf("USERNAME NOT REGISTERED\n"); write(usr_data[channel].connfd, "USERNAME NOT REGISTERED", 22); return 0;}
    EVP_PKEY* clientpubkey = PEM_read_PUBKEY(clientpubkey_file, NULL, NULL, NULL);
    fclose(clientpubkey_file);
    if(clientpubkey==NULL){printf("Error: PEM_read_PUBKEY returned NULL\n"); return 0;}
    
    // create the signature context:
    md_ctx = EVP_MD_CTX_new();
    if(md_ctx==NULL){printf("Error: EVP_MD_CTX_new returned NULL\n"); return 0;}
    
    md = EVP_sha256();
    ret_val = EVP_VerifyInit(md_ctx, EVP_sha256());
    if(ret_val == 0){printf("Error: EVP_VerifyInit returned NULL\n"); return 0;}
    ret_val = EVP_VerifyUpdate(md_ctx, decrypted_msg, outlen);  
    if(ret_val == 0){printf("Error: EVP_VerifyUpdate returned NULL\n"); return 0;}
    ret_val = EVP_VerifyFinal(md_ctx, tcp_msg, msg_size, clientpubkey);
    if(ret_val==1)
        printf("Client Authenticated! Username: <%s>\n", decrypted_msg);
    else{printf("Client Authentication FAILED (%d)\n", ret_val); return 0;}
        
    EVP_MD_CTX_free(md_ctx);
    // EVP_MD_free(md);
    // EVP_PKEY_free(clientpubkey);
    free(tcp_msg);
    usr_data[channel].username = malloc(outlen);
    for (int h=0;h<outlen;h++)
        usr_data[channel].username[h] = decrypted_msg[h];
    
    free(decrypted_msg);
    /** END VERIFY CLIENT AUTENTICITY USING REGISTERED PUBKEY */
    
    
    /** BEGIN GENERATE FRESH IV - ENCRYPT WITH USER PUBKEY */
    RAND_poll();
    unsigned char iv[12];
    RAND_bytes(iv, 12); // generate session IV
    printf("IV: %s\n", iv);
    
    unsigned char* out;
    
    ctx_p = EVP_PKEY_CTX_new(clientpubkey, NULL);
    if (ctx_p==NULL){printf("Error: EVP_PKEY_CTX_new returned NULL\n"); return 0;}
    
    ret_val = EVP_PKEY_encrypt_init(ctx_p);
    if(ret_val <= 0){printf("Error: EVP_PKEY_encrypt_init\n"); return 0;}
    
    ret_val = EVP_PKEY_CTX_set_rsa_padding(ctx_p, RSA_PKCS1_OAEP_PADDING);
    if(ret_val <= 0){printf("Error: EVP_PKEY_CTX_set_rsa_padding\n"); return 0;}

    // Determine buffer size for encrypted length
    if (EVP_PKEY_encrypt(ctx_p, NULL, &outlen, iv, sizeof(iv)) <= 0){printf("Error: EVP_PKEY_encrypt\n"); return 0;}
            
    out = OPENSSL_malloc(outlen);
    if (out==NULL){printf("Malloc failed for username encryption\n"); return 0;}

    // encrypt using client pubkey
    ret_val = EVP_PKEY_encrypt(ctx_p, out, &outlen, iv, sizeof(iv));
    if (ret_val<=0){printf("ENCRYPTION Error: EVP_PKEY_encrypt\n"); return 0;}
    
    // free(out);
    EVP_PKEY_CTX_free(ctx_p);
    EVP_PKEY_free(clientpubkey);
    
    /** SEND RSA PUBKEY ENCRYPTED IV */
    printf("Sending IV Encrypted with Client pubkey (%ld)\n", outlen);
    write(usr_data[channel].connfd, out, outlen);
    /** END GENERATE FRESH IV - ENCRYPT WITH USER PUBKEY */

    
    /** BEGIN GENERATE FRESH SESSION KEY */
    unsigned char* digest;
    unsigned int digestlen;
    
    md_ctx = EVP_MD_CTX_new();
    if(md_ctx==NULL){printf("Error: EVP_MD_CTX_new returned NULL\n"); return 0;}
    
    digest = (unsigned char* ) malloc(EVP_MD_size(EVP_sha256()));
    if(digest==NULL){printf("Error: malloc failed for digest\n"); return 0;}
    
    ret_val = EVP_DigestInit(md_ctx, EVP_sha256());
    if(ret_val<=0){printf("Error: DigestInit returned NULL\n"); return 0;}
    ret_val = EVP_DigestUpdate(md_ctx, iv, sizeof(iv));
    if(ret_val<=0){printf("Error: DigestUpdate returned NULL\n"); return 0;}
    ret_val = EVP_DigestFinal(md_ctx, digest, &digestlen);
    if(ret_val<=0){printf("Error: DigestFinal returned NULL\n"); return 0;}
    
    EVP_MD_CTX_free(md_ctx);
    //EVP_MD_free(md);
    printf("Digest is:\n");
    session_key = malloc(digestlen);
    for (int k=0;k<digestlen;k++){
        printf("%02x ", (unsigned char)digest[k]);
        session_key[k] = digest[k];
    }
    *key_len = digestlen;
    free(digest);
    /** END GENERATE FRESH SESSION KEY */
    
    /** RECEIVE ENCRYPTED "finish" using SESSION KEY */
    buff = malloc(MAX_BUFF);
    msg_size = read(usr_data[channel].connfd, buff, MAX_BUFF);
    printf("\nEncrypted Finish received (%d)\n",msg_size);
    unsigned char rec_aad[16];
    unsigned char rec_tag[16];
    if ((msg_size>32)&&(msg_size<MAX_BUFF)) // maximum size for username is 16
    {
        tcp_msg = malloc(msg_size);
        for(int i=0;i<16;i++){rec_aad[i] = buff[i];}
        for(int i=0;i<16;i++){rec_tag[i] = buff[i+16];}
        for(int i=0;i<msg_size;i++){tcp_msg[i]=buff[i+32];}
            
    }
    else {printf("Failed to receive Finish\n"); return 0;}
    free(buff);

    printf("AAD is: ");
    for (int k=0;k<16;k++){
        printf("%02x ", (unsigned char)rec_aad[k]);
    }
    printf("\nTag is: ");
    for (int k=0;k<16;k++){
        printf("%02x ", (unsigned char)rec_tag[k]);
    }    
    printf("\nCyp is: ");
    for (int k=0;k<msg_size-32;k++){
        printf("%02x ", (unsigned char)tcp_msg[k]);
    }    
    
    /** BEGIN DECRYPT "finish" using SESSION KEY and AES 256 GCM */
    unsigned char* decrypt_buff = malloc(MAX_BUFF);
    int clear_len = DecryptAES_256_GCM(decrypt_buff, tcp_msg, msg_size-32, rec_aad, 16, iv, session_key, rec_tag);
    if (clear_len<0){printf("AES DECRYPTION FAILED at finish msg"); return 0;}
    /** END DECRYPT "finish" using SESSION KEY and AES 256 GCM */
    unsigned char* clear_msg = malloc(clear_len);
    for (int i=0;i<clear_len;i++)
        clear_msg[i] = decrypt_buff[i];
    printf("\nclear_msg (%d): %s\n",clear_len, clear_msg);
    
    if (strcmp("finish", clear_msg) == 0){printf("AES 256 SUCESS!!");}
        
    /** BEGIN ENCRYPT "finish" using SESSION KEY and AES 256 GCM */
    ///RAND_poll();
    ///unsigned char aad[16];
    ///RAND_bytes(aad, 16);
    ///unsigned char tag[16];
    ///
    ///outlen = EncryptAES_256_GCM( out, clear_msg, val, aad, 16, iv, session_key, tag);
    ///if (outlen<=0){printf("Error: EncryptAES_256_GCM\n"); return 0;}
    ///
    ///unsigned char* enc_finish = malloc(outlen+sizeof(aad)+16);
    ///for (int v=0;v<sizeof(aad);v++)
    ///    enc_finish[v] = aad[v];
    ///for (int v=sizeof(aad);v<(sizeof(tag)+sizeof(aad));v++)
    ///    enc_finish[v] = tag[v];
    ///for (int v=(sizeof(tag)+sizeof(aad));v<(sizeof(tag)+sizeof(aad)+outlen);v++)
    ///    enc_finish[v] = out[v];
    ///
    ////** END ENCRYPT "finish" using SESSION KEY and AES 256 GCM */
    ///
    ////** SEND encrypted "finish" using SESSION KEY */
    ///printf("Send finish encrypted shared Key (%ld) (%ld)\n", sizeof(enc_finish), outlen);
    ///write(usr_data[channel].connfd, enc_finish, sizeof(enc_finish));
    ///free(enc_finish);
    
    // finished handshake
    pthread_mutex_unlock(&mutex_handshake);
    return 1;
}


// Function designed for chat between client and server.
void* MessageApp_channel_0(void *vargp)
{
    char buff[MAX_BUFF];
    char* tcp_msg;
    int channel = 0;
    int n;
    int msg_size;
    int usrname_rec = 0;
    unsigned char* session_key;
    unsigned int key_len;
    
    pthread_mutex_lock(&mutex_channel[0]);    
    printf("Channel 0 Connected (Non-Secure)\nBegin Handshake...\n");
    
    // begin HANDSHAKE protocol
    if (MessageApp_handshake(channel, session_key, &key_len) !=1)
        printf("Handshake FAILED...\n");
    else
        printf("Handshake SUCCESS...\n");
    // infinite loop for chat
    for (;;)
    {
        bzero(buff, MAX_BUFF);
  
        // read the message from client and copy it in buffer
        msg_size = read(usr_data[channel].connfd, buff, sizeof(buff));
        // print buffer which contains the client contents
        if ((msg_size>0)&&(msg_size<MAX_BUFF))
        {
            if (usrname_rec==0){
                usr_data[channel].username = malloc(msg_size);
                for (int i=0;i<msg_size;i++)
                    usr_data[channel].username = buff;
                usrname_rec=1;
                printf("From client: %s\n", usr_data[channel].username);
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

