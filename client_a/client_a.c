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
char friendname[16];
unsigned char iv[12];
unsigned char session_key[32];
int sockfd;
int caller=0; // caller is 1 if you is the one who started the chat
int chat_with_friend_flag = 0; // flag is set to one to add the chat session key in the encryption
unsigned char* friend_pubkey_txt;
char friend_iv[12];
char friend_session_key[32];
pthread_mutex_t mutex_print;

int hash_256_bits(unsigned char* input, int input_len, unsigned char* output);
    
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
    unsigned char out[MAX_BUFF];
    unsigned char aad[16];
    RAND_bytes(aad, 16);
    unsigned char tag[16];

    int outlen = EncryptAES_256_GCM(out, send_text, text_len, aad, 16, iv, session_key, tag);    
    if (outlen<=0){printf("Error: EncryptAES_256_GCM\n"); return 0;}
    
    unsigned char* enc_finish = malloc(outlen+16+16);
    if (enc_finish==NULL){return 0;}
    
    for (int v=0;v<16;v++)
        enc_finish[v] = aad[v];
    for (int v=0;v<16;v++)
        enc_finish[v+16] = tag[v];
    for (int v=0;v<outlen;v++)
        enc_finish[v+32] = out[v];
    
    int ret_val = write(sockfd, enc_finish, outlen+16+16);
    return ret_val;
}

// retuns received text length
int server_secure_receive(int sockfd, unsigned char* iv, unsigned char* key, unsigned char* clear_text)
{
    char buff[MAX_BUFF];
    char tcp_msg[MAX_BUFF];
    int msg_size;
    unsigned char rec_aad[16];
    unsigned char rec_tag[16];
    fd_set read_set;
    struct timeval timeout;
    
    //printf("WAITING Message in Secure Channel\n");
    timeout.tv_sec = 1800; // Time out after a minute
    timeout.tv_usec = 0;

    FD_ZERO(&read_set);
    FD_SET(sockfd, &read_set);

    int r=select(sockfd+1, &read_set, NULL, NULL, &timeout);

    if( r<=0 ) {return 0;}
    
    msg_size = read(sockfd, buff, MAX_BUFF);

    if ((msg_size>32)&&(msg_size<MAX_BUFF))
    {
        for(int i=0;i<16;i++){rec_aad[i] = buff[i];}
        for(int i=0;i<16;i++){rec_tag[i] = buff[i+16];}
        for(int i=0;i<msg_size;i++){tcp_msg[i]=buff[i+32];}            
    }
    else { return 0;}
    
    unsigned char decrypt_buff[MAX_BUFF];
    int clear_len = DecryptAES_256_GCM(decrypt_buff, tcp_msg, msg_size-32, rec_aad, 16, iv, key, rec_tag);
    if (clear_len<0){printf("AES DECRYPTION FAILED\n"); return 0;}

    for (int i=0;i<clear_len;i++)
        clear_text[i] = decrypt_buff[i];
    
    return clear_len;
}

int hash_256_bits(unsigned char* input, int input_len, unsigned char* output)
{
    unsigned char* digest;
    unsigned int digestlen;
    int ret_val;
    
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if(md_ctx==NULL){printf("Error: EVP_MD_CTX_new returned NULL\n"); return 0;}
    
    digest = (unsigned char* ) malloc(EVP_MD_size(EVP_sha256()));
    if(digest==NULL){printf("Error: malloc failed for digest\n"); return 0;}
    

    ret_val = EVP_DigestInit(md_ctx, EVP_sha256());
    if(ret_val<=0){printf("Error: DigestInit returned NULL\n"); return 0;}
    ret_val = EVP_DigestUpdate(md_ctx, input, input_len);
    if(ret_val<=0){printf("Error: DigestUpdate returned NULL\n"); return 0;}
    ret_val = EVP_DigestFinal(md_ctx, digest, &digestlen);
    if(ret_val<=0){printf("Error: DigestFinal returned NULL\n"); return 0;}
    
    EVP_MD_CTX_free(md_ctx);
    //printf("\nDigest is (%d): ", digestlen);
    
    for (int k=0;k<digestlen;k++){
        output[k] = digest[k];
        //printf("%02x ", (unsigned char)output[k]);
    }

    free(digest);
    return digestlen;
}


int ClientHandshake()
{
    char buff[MAX_BUFF];
    int msg_size;
    char* tcp_msg;
    int ret_val;
    EVP_MD_CTX* md_ctx;
    
    unsigned char handshake_noce_R1[32];
    unsigned char handshake_noce_R2[32];
    unsigned char challenge_noce[32];
    unsigned char rand_val[32];
    
    // Begin Handshake
    /** SEND R1 */
    RAND_poll();
    RAND_bytes(rand_val, 32);
    hash_256_bits(rand_val, 32, handshake_noce_R1);
    printf("Send Hello to server \n");
    write(sockfd, handshake_noce_R1, 32); // Send R1
    
    /** RECEIVE TempPubkey + R2 + {R1+TempPubkey+R2}signed */
    msg_size = read(sockfd, buff, MAX_BUFF);
    printf("\nHello received \n");
    unsigned char TempPubkey_txt[426];
    int TempPubkey_txt_len = 426;
    unsigned char handshake_cmp_buff[490]; // 32 + 426 + 32 -> {R1 + TempPubkey + R2}
    unsigned char *server_signature;
    for (int i=0;i<32;i++){handshake_cmp_buff[i] = handshake_noce_R1[i];}
    
    if ((msg_size>458)&&(msg_size<MAX_BUFF))
    {
        for (int i=0;i<426;i++){TempPubkey_txt[i] = buff[i]; handshake_cmp_buff[i+32]=buff[i];}
        //printf("PUBKEY TXT: %s\n", TempPubkey_txt);
        for (int i=0;i<32;i++){handshake_noce_R2[i] = buff[i+426]; handshake_cmp_buff[i+458]=buff[i+426];}
        server_signature = malloc(msg_size-458);
        for (int i=0;i<msg_size-458;i++){server_signature[i] = buff[i+458];}
        //printf("Server Signature received (%d): \n",msg_size-458);
    }
    else {printf("Hello Received Error\n"); return 0;}
    
    //printf("\nR1 + TempPubk + 2: ");
    //
    //for (int k=0;k<490;k++){
    //    printf("%02x ", (unsigned char)handshake_cmp_buff[k]);
    //}
    
    /** BEGIN AUTHENTICATE SERVER USING CERTIFICATE **/
    FILE* cert_file = fopen("MessageApp_cert.pem", "r");
    if(cert_file==NULL){printf("Certificate File Open Error\n"); return 0;}
    X509* cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    fclose(cert_file);
    if(cert==NULL){printf("Error: PEM_read_X509 returned NULL\n"); return 0;}
    
    char* tmp = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    char* tmp2 = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
    printf("\nCertificate of %s\n issued by %s\n",tmp, tmp2);
    free(tmp);
    free(tmp2);
    // create new context
    md_ctx = EVP_MD_CTX_new();
    if(md_ctx==NULL){printf("Error: EVP_MD_CTX_new returned NULL\n"); return 0;}
    
    ret_val = EVP_VerifyInit(md_ctx, EVP_sha256());
    if(ret_val == 0){printf("Error: EVP_VerifyInit returned NULL\n"); return 0;}
    ret_val = EVP_VerifyUpdate(md_ctx, handshake_cmp_buff, 490);  
    if(ret_val == 0){printf("Error: EVP_VerifyUpdate returned NULL\n"); return 0;}
    ret_val = EVP_VerifyFinal(md_ctx, server_signature, msg_size-458, X509_get_pubkey(cert)); // compare the signed message with the clear text - authenticate using certificate
    if(ret_val==1)
        printf("Server Authenticated!\n");
    else{
        printf("Server Authentication FAILED (%d)\n", ret_val);
        return 0;}
    EVP_MD_CTX_free(md_ctx);
    /** END AUTHENTICATE SERVER USING CERTIFICATE **/
    
    /** BEGIN ENCRYPT R1 + R2 + S + IV USING TEMP PUBKEY**/
    unsigned char pre_master_secret[32];
    RAND_poll();
    RAND_bytes(rand_val, 32);
    hash_256_bits(rand_val, 32, pre_master_secret);
    RAND_poll();
    RAND_bytes(iv, 12);
    
    char session_secret[108];
    for (int i=0;i<32;i++){session_secret[i] = handshake_noce_R1[i];} //R1
    for (int i=0;i<32;i++){session_secret[i+32] = handshake_noce_R2[i];} //R2
    for (int i=0;i<32;i++){session_secret[i+64] = pre_master_secret[i];} // S
    for (int i=0;i<12;i++){session_secret[i+96] = iv[i];} //IV
    
    EVP_PKEY* TempPubkey = EVP_PKEY_new();
    RSA *temp_rsa = NULL;
    BIO* pb_TempPubkey = BIO_new_mem_buf((void*) TempPubkey_txt, TempPubkey_txt_len);
    if (pb_TempPubkey==NULL){printf("BIO_new_mem_buf returned NULL\n");}
    
    temp_rsa = PEM_read_bio_RSAPublicKey(pb_TempPubkey, &temp_rsa, NULL, NULL);
    if (temp_rsa == NULL) {printf("PEM_read_bio_RSAPublicKey returned NULL\n");}
    
    EVP_PKEY_assign_RSA(TempPubkey, temp_rsa); // set TempPubkey to correct format from the text obtained
    
    unsigned char *out;
    size_t outlen;
    
    EVP_PKEY_CTX* ctx_p = EVP_PKEY_CTX_new(TempPubkey, NULL);
    if (ctx_p==NULL){printf("Error: EVP_PKEY_CTX_new returned NULL\n"); return 0;}
    
    ret_val = EVP_PKEY_encrypt_init(ctx_p);
    if(ret_val <= 0){printf("Error: EVP_PKEY_encrypt_init\n"); return 0;}
    
    ret_val = EVP_PKEY_CTX_set_rsa_padding(ctx_p, RSA_PKCS1_OAEP_PADDING);
    if(ret_val <= 0){printf("Error: EVP_PKEY_CTX_set_rsa_padding\n"); return 0;}

    // Determine buffer size for encrypted length
    if (EVP_PKEY_encrypt(ctx_p, NULL, &outlen, session_secret, 108) <= 0)
    {printf("Error: EVP_PKEY_encrypt\n"); return 0;}
    
    out = OPENSSL_malloc(outlen);
    if (out==NULL){printf("Malloc failed for username encryption\n"); return 0;}

    // encrypt using Temporary pubkey
    ret_val = EVP_PKEY_encrypt(ctx_p, out, &outlen, session_secret, 108);
    if (ret_val<=0){printf("ENCRYPTION Error: EVP_PKEY_encrypt\n"); return 0;}
        
    EVP_PKEY_CTX_free(ctx_p);
    EVP_PKEY_free(TempPubkey);
    /** END ENCRYPT R1 + R2 + IV USING TEMP PUBKEY **/
    
    /** SEND {R1 + R2 + IV}TempPubkey */
    write(sockfd, out, outlen); // Send E{R1+R2+pre_master_secret+iv}TempPubkey
    free(out);
    
    /** BEGIN COMPUTE SESSION KEY **/
    hash_256_bits(session_secret, 108, session_key);
    printf("\nSESSION KEY: ");

    for (int k=0;k<32;k++){
        printf("%02x ", (unsigned char)session_key[k]);
    }
    /** END COMPUTE SESSION KEY **/
    
    /** RECEIVE noce Encrypted with session key */
    unsigned char challence_nonce[32]; // M
    unsigned char challenge_secret[140]; // M + R1 + R2 + S + IV - 32+32+32+32+12
    if (server_secure_receive(sockfd, iv, session_key, challence_nonce) != 32){printf("Failed to receive challenge nonce\n");return 0;}
    for(int i=0;i<32;i++){challenge_secret[i] = challence_nonce[i];}
    for(int i=0;i<108;i++){challenge_secret[i+32] = session_secret[i];}
    
    /** BEGIN SIGN CHALLENGE RESPONSE **/
    // get Username
    Username = malloc(128);
    printf("\n\nMessageApp->Enter Username: ");
    scanf("%128s", Username);
    int Username_len = strlen(Username);
    
    FILE* privkey_file = fopen("privkey.pem", "r");
    if(privkey_file==NULL){printf("Privkey File Open Error\n"); return 0;}
    EVP_PKEY* privkey = PEM_read_PrivateKey(privkey_file, NULL, NULL, NULL);
    fclose(privkey_file);
    if(privkey==NULL){printf("Error: PEM_read_PrivateKey returned NULL\n"); return 0; }
    
    md_ctx = EVP_MD_CTX_new();
    if(md_ctx==NULL){printf("Error: EVP_MD_CTX_new returned NULL\n"); return 0;}
    
    unsigned char* sgnt_buff = (unsigned char*)malloc(EVP_PKEY_size(privkey));
    if(sgnt_buff==NULL) {printf("Error: malloc returned NULL\n"); return 0;}
    
    ret_val = EVP_SignInit(md_ctx, EVP_sha256());
    if(ret_val == 0){printf("Error: EVP_SignInit returned %d\n",ret_val); return 0;}
    ret_val = EVP_SignUpdate(md_ctx, challenge_secret, 140);
    if(ret_val == 0){printf("Error: EVP_SignUpdate returned %d\n",ret_val); return 0;}
    unsigned int sgnt_size;
    ret_val = EVP_SignFinal(md_ctx, sgnt_buff, &sgnt_size, privkey); // return the signed message
    if(ret_val == 0){printf("Error: EVP_SignFinal returned %d\n",ret_val); return 0;}

    
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(privkey);
    /** END SIGN CHALLENGE RESPONSE **/
    
    /** SEND Challenge response: {challenge_secret}signed + Username */
    for (int i=0;i<sgnt_size;i++){buff[i] = sgnt_buff[i];}
    for (int i=0;i<Username_len;i++){buff[i+sgnt_size] = Username[i];}
    server_secure_send(sockfd, iv, session_key, buff, sgnt_size+Username_len);
    
    // finish Handshake
    char from_server[1024];
    msg_size = server_secure_receive(sockfd, iv, session_key, buff);
    for(int i=0;i<msg_size;i++){from_server[i]=buff[i];}
    printf("\nFrom Server(%d): %s\n",msg_size, from_server);
    
    return 1;
}


    
void* sender_Task(void *vargp)
{   
    char sbuff[MAX_BUFF];
    char friend_sbuff[MAX_BUFF];
    int len;
    char *cmd_chat ="chat";
    char *cmd_reqt ="reqt";
    char *cmd_pubk ="pubk";
    char *cmd_acpt ="acpt";
    char *cmd_refu ="refu";
    char *cmd_frwd = "frwd";
    char *cmd_list = "list";
    char *cmd_exit ="exit";
    char ipt_cmd[4];

    
        
    for (;;) {
            
        //pthread_mutex_lock(&mutex_print);
        if (chat_with_friend_flag == 0){printf("\nSERVER[cmd][param]->");}
        else if (chat_with_friend_flag == 1){printf("\nMessasgeApp[CHAT]->");}
         // send command to server
        
        fgets(sbuff, MAX_BUFF, stdin);
        if ((strlen(sbuff) > 0) && (sbuff[strlen (sbuff) - 1] == '\n'))
            sbuff[strlen (sbuff) - 1] = '\0';
        
        if (chat_with_friend_flag == 0)
        {            
            for(int i=0;i<4;i++){ipt_cmd[i] = sbuff[i];}
            if(strncmp(ipt_cmd, cmd_chat, 4)==0){caller=1;} // lock until response
            
            if (strlen(sbuff)>0){
                printf("Send to Server: (%ld)\n", strlen(sbuff));
                server_secure_send(sockfd, iv, session_key, sbuff, strlen(sbuff));}
            
        }
        else if (chat_with_friend_flag == 1)
        {
            //encrypted_len = friend_encrypt(encrypted_friend_msg, clear_msg, clear_msg_len);
            for(int i=0;i<4;i++){friend_sbuff[i] = cmd_frwd[i];}
            for(int i=0;i<strlen(sbuff);i++){friend_sbuff[i+4] = sbuff[i];}
            
            if (strlen(friend_sbuff)>0){
                printf("Send to Server: (%ld)\n", strlen(friend_sbuff));
                server_secure_send(sockfd, iv, session_key, friend_sbuff, strlen(friend_sbuff));}
            
        }
        //pthread_mutex_unlock(&mutex_print);
        for (int i=0;i<MAX_BUFF;i++){sbuff[i]='\0';} // clear sbuff
        for (int i=0;i<MAX_BUFF;i++){friend_sbuff[i]='\0';} // clear friend_sbuff
    }
}

void* receiver_Task(void *vargp)
{   
    int n;
    int r;
    int msg_len;
    char tcp_msg[MAX_BUFF];
    char data[MAX_BUFF];
    char onlineusrs[MAX_BUFF];
    char clear_msg[MAX_BUFF];
    char decrypt[MAX_BUFF];
    int dec_size;
    char rec_cmd[4];
    unsigned char clear_text[MAX_BUFF];
    char friend_name[16];
    
    for (;;) {
        
        //printf("\nclient waiting...");
        
        msg_len = server_secure_receive(sockfd, iv, session_key, clear_text);
        //pthread_mutex_lock(&mutex_print);
        printf("From Server (%d)\n",msg_len);
        if (msg_len > 4){
            for (int i=0;i<4;i++){rec_cmd[i]=clear_text[i];} // Save received COMMAND
            for (int i=0;i<msg_len-4;i++){data[i]=clear_text[i+4];} // Save received DATA
            if(strncmp(rec_cmd, "reqt", 4)==0){ //received a request
                for(int i=0;i<msg_len-4;i++){friendname[i] = data[i];}
                printf("\nMessageApp - REQUEST TO CHAT FROM: <%s> ACCEPT?->", friendname); 
            }
            else if (strncmp(rec_cmd, "pubk", 4)==0){
                if (caller==1){
                    printf("\nMessageApp Caller- CHAT ACCEPTED!\n");
                    friend_pubkey_txt = malloc(msg_len-4);
                    for(int k=0;k<msg_len-4;k++){friend_pubkey_txt[k] = data[k];}
                    // friend_begin_negotiation(); // saves the chat session key and iv
                    chat_with_friend_flag = 1;
                }
                else{                    
                    // friend_wait_negotiation(); // saves the chat session key and iv
                    friend_pubkey_txt = malloc(msg_len-4);
                    for(int k=0;k<msg_len-4;k++){friend_pubkey_txt[k] = data[k];}
                    chat_with_friend_flag = 1;
                    printf("\nMessageApp Receiver- CHAT ACCEPTED!\nMessasgeApp[CHAT]->"); 
                }
            }
            else if (strncmp(rec_cmd, "frwd", 4)==0){
                
                // dec_size =  friend_decrypt(decrypt, data, data_len);
                // printf(clear_msg);
                for (int i=0;i< msg_len-4;i++){clear_msg[i]=data[i];}
                printf("\nMessasgeApp[CHAT]->Received<%s>: %s\n", friendname, clear_msg);
                for (int i=0;i< msg_len-4;i++){clear_msg[i]='\0';}
            }
            else if (strncmp(rec_cmd, "refu", 4)==0){
                printf("\nMessageApp - REFUSED BY: %s\nSERVER[cmd][param]->", data); 
            }
            else if (strncmp(rec_cmd, "list", 4)==0){
                printf("\nMessageApp - ONLINE USERS:\n %s", data);
                printf("\nSERVER[cmd][param]->");
            }
            else if (strncmp(rec_cmd, "refu", 4)==0){
                printf("\nMessageApp - ERROR: %s", data);
                printf("\nSERVER[cmd][param]->");
            }
            else {printf("\nMessageApp - Unrecognized CMD\n");}
            //pthread_mutex_unlock(&mutex_print);
        }
        else if (msg_len>0){printf("Server msg too short"); }
        else {close(sockfd); exit(0);} //close connection
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

    if (ClientHandshake() == 1){ // From the handshake, Client gets the session_key and iv
        
        // function for chat
        pthread_create(&rec_id, NULL, receiver_Task, NULL);
        pthread_create(&sen_id, NULL, sender_Task, NULL);
    
        pthread_join(rec_id, NULL);
        pthread_join(sen_id, NULL);
    }
    // close the socket
    close(sockfd);
} 
