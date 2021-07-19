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
    char username[16];
    int username_len;
    int connfd;
    unsigned char iv[12];
    unsigned char key[32];
    int pending;
};

int MessageApp_OpenListener(int port);
int channel_secure_receive(int channel, unsigned char* iv, unsigned char* key, unsigned char* clear_text);
int channel_secure_receive(int channel, unsigned char* iv, unsigned char* key, unsigned char* clear_text);
int EncryptAES_256_GCM( unsigned char* encrypted_msg,
                        unsigned char* clear_msg, int msg_len, 
                        unsigned char* aad, int aad_len,
                        unsigned char* iv,
                        unsigned char* key,
                        unsigned char* tag);

int DecryptAES_256_GCM( unsigned char* clear_msg,
                        unsigned char* encrypted_msg, int encrypted_len, 
                        unsigned char* aad, int aad_len,
                        unsigned char* iv,
                        unsigned char* key,
                        unsigned char* tag);

int get_user_pubkey_text(char* username, int username_len, char* pubkey_txt);
int MessageApp_launch_param_check (int n_input, char* args[]);
int MessageApp_handshake(int channel);
// Threads
void *MessageApp_client_connect(void *vargp);
void* MessageApp_channel_0(void *vargp);

// Globals
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

// return number of bytes sent via TCP
int channel_secure_send(int channel, unsigned char* iv, unsigned char* key, unsigned char* send_text, int text_len)
{
    RAND_poll();
    unsigned char aad[16]; 
    RAND_bytes(aad, 16); // randomize AAD
    unsigned char tag[16];
    unsigned char out[MAX_BUFF];

    int outlen = EncryptAES_256_GCM(out, send_text, text_len, aad, 16, iv, key, tag);    
    if (outlen<=0){printf("Error: EncryptAES_256_GCM\n"); return 0;}
    
    unsigned char* auth_msg = malloc(outlen+16+16);
    if (auth_msg==NULL){return 0;}
    
    for (int v=0;v<16;v++)
        auth_msg[v] = aad[v];
    for (int v=0;v<16;v++)
        auth_msg[v+16] = tag[v];
    for (int v=0;v<outlen;v++)
        auth_msg[v+32] = out[v];

    int ret_val = write(usr_data[channel].connfd, auth_msg, outlen+16+16);
    return ret_val;
}

// retuns received text length
int channel_secure_receive(int channel, unsigned char* iv, unsigned char* key, unsigned char* clear_text)
{
    char buff[MAX_BUFF];
    char tcp_msg[MAX_BUFF];
    int msg_size;
    unsigned char rec_aad[16];
    unsigned char rec_tag[16];
    fd_set read_set;
    struct timeval timeout;
    
    printf("WAITING Message in Secure Channel (%d)...\n", channel);
    timeout.tv_sec = 1800; // Time out after a minute
    timeout.tv_usec = 0;

    FD_ZERO(&read_set);
    FD_SET(usr_data[channel].connfd, &read_set);

    int r=select(usr_data[channel].connfd+1, &read_set, NULL, NULL, &timeout);

    if( r<=0 ) {return 0;}
    
    msg_size = read(usr_data[channel].connfd, buff, MAX_BUFF);

    if ((msg_size>32)&&(msg_size<MAX_BUFF))
    {
        for(int i=0;i<16;i++){rec_aad[i] = buff[i];}
        for(int i=0;i<16;i++){rec_tag[i] = buff[i+16];}
        for(int i=0;i<msg_size;i++){tcp_msg[i]=buff[i+32];}            
    }
    else { return 0;}
    
    unsigned char decrypt_buff[MAX_BUFF];
    int clear_len = DecryptAES_256_GCM(decrypt_buff, tcp_msg, msg_size-32, rec_aad, 16, iv, key, rec_tag);
    if (clear_len<0){printf("AES DECRYPTION FAILED at Channel (%d)", channel); return 0;}

    for (int i=0;i<clear_len;i++)
        clear_text[i] = decrypt_buff[i];
    
    return clear_len;
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

int get_user_pubkey_text(char* username, int username_len, char* pubkey_txt)  // pubkey_txt is an initialized pointer
{
    if (username_len<=0){return 0;}
    char* filename = malloc(username_len+7);
    char* file_ext = "key.pem"; 
    int length;
    char buff[2048];
    
    for(int i=0; i<username_len; i++){filename[i]= username[i]; }
    for(int i=0; i<7; i++){filename[i+username_len]= file_ext[i]; }
    
    printf("TRYING TO OPEN PUBKEY: %s\n", filename );
    FILE * f = fopen (filename, "r");

    if (f)
    {
        fseek (f, 0, SEEK_END);
        length = ftell (f);
        fseek (f, 0, SEEK_SET);
        //buff = malloc (length);
        if (pubkey_txt)
        {
            fread (buff, 1, length, f);
        }
        fclose (f);
    }
    free(filename);
    for (int i=0;i<length;i++){pubkey_txt[i]=buff[i];}
    
    printf("TEXT PUBKEY(%d): \n", length);
    return length;
}

int check_tainted_string(char* tainted_str, int str_len)
{
    int ret_val=0;
    // check for special characters in the string
    char allowed_chars[63]= {'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R',
                                'S','T','U','V','W','X','Y','Z','a','b','c','d','e','f','g','h','i',
                                'j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
                                '0','1','2','3','4','5','6','7','8','9','-'};
    for (int k=0;k<str_len;k++){
        for (int i=0;i<63;i++){
            if (tainted_str[k]==allowed_chars[i]){ret_val++;}
        }
    }
    if (ret_val==str_len){return 0;} // if all character from the string belong to in the allowed list return zero (OK)
    else {return (str_len-ret_val);} // if any characters from the string do not match the allowed list return non-zero (NOK)
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


int hash_256_bits(char* input, int input_len, unsigned char* output)
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
    //printf("Digest is (%d): ", digestlen);
    
    for (int k=0;k<digestlen;k++){
        output[k] = digest[k];
        //printf("%02x ", (unsigned char)output[k]);
    }
    printf("\n");
    free(digest);
    return digestlen;
}


int MessageApp_handshake(int channel)
{
    char buff[MAX_BUFF];
    char* tcp_msg;
    int ret_val=0;
    int msg_size=0;
    EVP_MD_CTX* md_ctx;
    
    unsigned char handshake_nonce_R1[32];
    unsigned char handshake_nonce_R2[32];
    unsigned char rand_val[32];
    
    /** RECEIVE Client hello */
    msg_size = read(usr_data[channel].connfd, buff, MAX_BUFF);
    if (msg_size==32)
    {
        for (int i=0;i<msg_size;i++)
            handshake_nonce_R1[i]=buff[i];
    }
    
    /** BEGIN GENERATE TEMPORARY RSA 2048 KEY PAIR **/
    char *TempPubkey_txt;
    int TempPubkey_txt_len;
    
    BIO *bp_TempPubkey = NULL;
    BIO *bp_TempPrivkey = NULL;
    // EVP_PKEY *TempPubkey = NULL;
    EVP_PKEY *TempPrivkey = NULL;
    
    RSA *r = NULL;
    BIGNUM *bne = NULL;

    bne = BN_new();
    ret_val = BN_set_word(bne, RSA_F4);
    if (ret_val != 1) {printf("BN_set_word FAILED\n"); return 0;}

    r = RSA_new();
    ret_val = RSA_generate_key_ex(r, 2048, bne, NULL);
    if (ret_val != 1) {printf("RSA_generate_key_ex FAILED\n"); return 0;} 

    bp_TempPrivkey = BIO_new(BIO_s_mem());
    ret_val = PEM_write_bio_RSAPrivateKey(bp_TempPrivkey, r, NULL, NULL, 0, NULL, NULL);
    if (ret_val != 1) {printf("PEM_write_bio_RSAPrivateKey FAILED\n"); return 0;} 
    
    TempPrivkey = PEM_read_bio_PrivateKey(bp_TempPrivkey, &TempPrivkey, NULL, NULL); // Temporary PrivKey RSA 2048
    if (TempPrivkey==NULL) {printf("PEM_read_bio_PrivateKey FAILED\n"); return 0;}
    
    bp_TempPubkey = BIO_new(BIO_s_mem());
    ret_val = PEM_write_bio_RSAPublicKey(bp_TempPubkey, r);
    if (ret_val != 1) {printf("PEM_write_bio_RSAPublicKe FAILED\n"); return 0;} // BIO Temporary PubKey RSA 2048
    
    TempPubkey_txt_len = BIO_pending(bp_TempPubkey);
    TempPubkey_txt = (char*) malloc(TempPubkey_txt_len);
    BIO_read(bp_TempPubkey, TempPubkey_txt, TempPubkey_txt_len); // TXT Temporary PubKey RSA 2048 
    printf("Generated TEMP PUBKEY (%d): ",TempPubkey_txt_len );            
    /** END GENERATE TEMPORARY RSA 2048 KEY PAIR **/
    
    /** BEGIN GENERATE SIGNATURE FOR  R1 + TEMP PUBKEY + R2 **/
    RAND_poll();
    RAND_bytes(rand_val, 32);
    hash_256_bits(rand_val, 32, handshake_nonce_R2);
    
    char nonce_buff[TempPubkey_txt_len+64];
    for (int i=0;i<32;i++){nonce_buff[i] = handshake_nonce_R1[i];}
    for (int i=0;i<TempPubkey_txt_len;i++){nonce_buff[i+32] = TempPubkey_txt[i];}
    for (int i=0;i<32;i++){nonce_buff[i+TempPubkey_txt_len+32] = handshake_nonce_R2[i];}
    
    //printf("\nR1 + TempPubk + R2 (%d): ", TempPubkey_txt_len+64);
    //for (int k=0;k<490;k++){
    //    printf("%02x ", (unsigned char)nonce_buff[k]);
    //}
    
    FILE* privkey_file = fopen("MessageApp_key.pem", "r");
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
    ret_val = EVP_SignUpdate(md_ctx, nonce_buff, TempPubkey_txt_len+64);
    if(ret_val == 0){printf("Error: EVP_SignUpdate returned %d\n",ret_val); return 0;}
    unsigned int sgnt_size;
    ret_val = EVP_SignFinal(md_ctx, sgnt_buff, &sgnt_size, privkey); // return the signed message
    if(ret_val == 0){printf("Error: EVP_SignFinal returned %d\n",ret_val); return 0;}
    printf("\nServer Signature size (%d)\n", sgnt_size);
    
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(privkey);
    /** END GENERATE SIGNATURE FOR  R1 + TEMP PUBKEY + R2 **/
    
    /** SEND TempPubkey + R2 + {R1+TempPubkey+R2}signed */
    for (int i=0;i<TempPubkey_txt_len+32;i++){buff[i] = nonce_buff[i+32];}
    for (int i=0;i<sgnt_size;i++){buff[i+TempPubkey_txt_len+32] = sgnt_buff[i];}
    
    printf("Sending signature in Channel (%d) len (%d)\n", channel, TempPubkey_txt_len+32+sgnt_size);
    write(usr_data[channel].connfd, buff, TempPubkey_txt_len+32+sgnt_size);
    
    /** RECEIVE pre-master secret and iv encrypted by TempPubkey */
    msg_size = read(usr_data[channel].connfd, buff, MAX_BUFF);
    if (msg_size<=0){return 0;}
        
    /** BEGIN DECRYPT PRE MASTER SECRET AND IV USING TEMP PRIVKEY **/
    unsigned char *secret;
    size_t outlen;
    // Decrypt Received Message using privkey
    EVP_PKEY_CTX* ctx_p = EVP_PKEY_CTX_new(TempPrivkey, NULL);
    if (ctx_p==NULL){printf("Error: EVP_PKEY_CTX_new returned NULL\n"); return 0;}
    if (EVP_PKEY_decrypt_init(ctx_p) <= 0){printf("Error: EVP_PKEY_decrypt_init returned NULL\n"); return 0;}
    if (EVP_PKEY_CTX_set_rsa_padding(ctx_p, RSA_PKCS1_OAEP_PADDING) <= 0){printf("Error: EVP_PKEY_CTX_set_rsa_padding returned NULL\n"); return 0;}
    /* Determine buffer length */
    if (EVP_PKEY_decrypt(ctx_p, NULL, &outlen, buff, msg_size) <= 0){printf("Error: EVP_PKEY_decrypt returned NULL\n"); return 0;}
    
    secret = OPENSSL_malloc(outlen);
    if (!secret){printf("Malloc Failed for decrypted message\n"); return 0;}
        
    ret_val = EVP_PKEY_decrypt(ctx_p, secret, &outlen, buff, msg_size);
    if (ret_val<=0){printf("DECRYPTION Error: EVP_PKEY_decrypt\n"); return 0;}
    
    EVP_PKEY_free(TempPrivkey);
    EVP_PKEY_CTX_free(ctx_p);
    for (int i=0;i<12;i++){usr_data[channel].iv[i] = secret[i+96];} // Save session IV
    printf("\nCHANNEL (%d) SESSION KEY: ", channel);
    hash_256_bits(secret, outlen, usr_data[channel].key); // compute session key
    for (int k=0;k<32;k++){
        printf("%02x ", usr_data[channel].key[k]);
    }
    /** END DECRYPT PRE MASTER SECRET AND IV USING TEMP PRIVKEY **/
    
    // Client Authentication -- For now on all the communication is secured through a Shared Symmetric Key and encrypted in AES_256_GCM with authentication
    /** SEND Challenge nonce */
    unsigned char challenge_nonce[32];
    RAND_poll();
    RAND_bytes(rand_val, 32);
    hash_256_bits(rand_val, 32, challenge_nonce);
    
    channel_secure_send(channel, usr_data[channel].iv, usr_data[channel].key, challenge_nonce, 32);
    
    /** RECEIVE Username + Signature */
    msg_size = channel_secure_receive(channel, usr_data[channel].iv, usr_data[channel].key, buff);
    if ((msg_size<256)||(msg_size>272)){printf("Username size incompatible!\n"); 
        channel_secure_send(channel, usr_data[channel].iv, usr_data[channel].key, "Username size incompatible!", 27);
        return 0;}
    unsigned char challenge_cmp[140];
    unsigned char user_signature[256];
    
    for (int i=0;i<32;i++){challenge_cmp[i] = challenge_nonce[i];}
    for (int i=0;i<108;i++){challenge_cmp[i+32] = secret[i];}
    for (int i=0;i<256;i++){user_signature[i] = buff[i];}
    //usr_data[channel].username = malloc(msg_size-256);
    usr_data[channel].username_len = msg_size-256;
    for (int i=0;i<usr_data[channel].username_len;i++){usr_data[channel].username[i] = buff[i+256];}
    if (check_tainted_string(usr_data[channel].username, usr_data[channel].username_len)!=0){
        printf("Usarname Contains Unsafe Charcters!\n");
        channel_secure_send(channel, usr_data[channel].iv, usr_data[channel].key, "Usarname Contains Not Allowed Charcters!", 40);
        return 0;}
    
    /** BEGIN AUTHENTICATE USER BY PUBKEY **/
    char *pubkey_extension = "key.pem";
    char *filename = malloc(usr_data[channel].username_len+7);
    if(filename==NULL){printf("filename malloc failed\n"); return 0;}
    for (int i=0;i<usr_data[channel].username_len;i++)
        filename[i] = usr_data[channel].username[i];
    for (int n=0;n<7;n++)
        filename[n+usr_data[channel].username_len] = pubkey_extension[n];
    
    printf("Trying to open: <%s> \n", filename);
    FILE* clientpubkey_file = fopen(filename, "r");
    if(clientpubkey_file==NULL)
    {printf("USERNAME NOT REGISTERED\n"); channel_secure_send(channel, usr_data[channel].iv, usr_data[channel].key, "USERNAME NOT REGISTERED", 23); return 0;}
    
    EVP_PKEY* clientpubkey = PEM_read_PUBKEY(clientpubkey_file, NULL, NULL, NULL);
    fclose(clientpubkey_file);
    if(clientpubkey==NULL){printf("Error: PEM_read_PUBKEY returned NULL\n"); return 0;}
    
    // create the signature context:
    md_ctx = EVP_MD_CTX_new();
    if(md_ctx==NULL){printf("Error: EVP_MD_CTX_new returned NULL\n"); return 0;}
    
    ret_val = EVP_VerifyInit(md_ctx, EVP_sha256());
    if(ret_val == 0){printf("Error: EVP_VerifyInit returned NULL\n"); return 0;}
    ret_val = EVP_VerifyUpdate(md_ctx, challenge_cmp, 140);  
    if(ret_val == 0){printf("Error: EVP_VerifyUpdate returned NULL\n"); return 0;}
    ret_val = EVP_VerifyFinal(md_ctx, user_signature, 256, clientpubkey);
    if(ret_val==1)
        printf("Client Authenticated! Username(%d): <%s>\n",usr_data[channel].username_len, usr_data[channel].username);
    else{printf("Client Authentication FAILED (%d)\n", ret_val); 
        channel_secure_send(channel, usr_data[channel].iv, usr_data[channel].key, "Client Authentication FAILED", 28);
        return 0;}
        
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(clientpubkey);
    /** BEGIN AUTHENTICATE USER BY PUBKEY **/
    
    // finish handshake
    char* finsh_1 = "USER <"; // 6
    char* finsh_2 = "> AUTHENTICATED IN MessageApp"; // 29
    char finish_msg[60];
    for (int i=0;i<6;i++){finish_msg[i]=finsh_1[i];}
    for (int i=0;i<usr_data[channel].username_len;i++){finish_msg[i+6]=usr_data[channel].username[i];}
    for (int i=0;i<29;i++){finish_msg[i+6+usr_data[channel].username_len]=finsh_2[i];}
    channel_secure_send(channel, usr_data[channel].iv, usr_data[channel].key, finish_msg, 35+usr_data[channel].username_len);
    
    return 1;
}



// Function designed for chat between client and server.
void* MessageApp_channel_0(void *vargp)
{
    char client_msg[MAX_BUFF];
    int client_msg_len;
    int outlen = 0;
    char rec_cmd[4] = {0};
    char data[MAX_BUFF];
    int channel = 0;
    char msg_to_send[MAX_BUFF];
    int friend_channel;
    int user_pubkey_len;
    char user_pubkey[2048];
    int in_chat_flag = 0;
    char *cmd_chat ="chat";
    char *cmd_reqt ="reqt";
    char *cmd_pubk ="pubk";
    char *cmd_acpt ="acpt";
    char *cmd_refu ="refu";
    char *cmd_frwd = "frwd";
    char *cmd_list = "list";
    char *cmd_exit ="exit";
    
    pthread_mutex_lock(&mutex_channel[0]);    
    printf("Channel (%d) Connected (Non-Secure)\nBegin Handshake...\n", channel);
    
    // begin HANDSHAKE protocol - it returns the session key, the iv, and will set the username and username_len for this channel
    if (MessageApp_handshake(channel) !=1) // key is 32 bytes long - iv is 12 bytes long
    {
        printf("Handshake FAILED\n");
        close(usr_data[channel].connfd);
        for(;;); // close channel
    }
    else
        printf("Handshake SUCCESS Channel (%d) Connected (Secure) User: <%s>\n", channel, usr_data[channel].username);
    
    usr_data[channel].pending = 0; // start with no pendencies
    
    // infinite loop for chat
    for (;;)
    {
        /** Receive messages from logged Users */
        client_msg_len = channel_secure_receive(channel, usr_data[channel].iv, usr_data[channel].key, client_msg); // client_msg is tainted!
        printf("SERVER Received plaintext (%d): %s\n",client_msg_len ,client_msg);
        if (client_msg_len > 4){
            for (int i=0;i<4;i++){rec_cmd[i]=client_msg[i];} // Save received COMMAND
            for (int i=0;i<client_msg_len-4;i++){data[i]=client_msg[i+4];} // Save received DATA
            
            /** process Command from client */
            if ((strncmp("chat", rec_cmd, 4) == 0)&&(in_chat_flag == 0)&&(usr_data[friend_channel].pending == 0)){ // Request to chat with another user
                if((client_msg_len-4)<16){
                    friend_channel = 0;
                    for(int n=0;n<MAX_CHANNELS;n++){ // search the friend username on the channels
                        if (strncmp(data, usr_data[friend_channel].username, usr_data[friend_channel].username_len) == 0){ // found matching username fomr database
                            //msg_to_send = malloc(4+usr_data[channel].username_len);
                            for(int i=0;i<4;i++){msg_to_send[i] = cmd_reqt[i];}
                            for(int i=0;i<usr_data[channel].username_len;i++){msg_to_send[i+4] = usr_data[channel].username[i];}
                            printf("received chat Send Ch (%d) TO Ch (%d) - (%d): %s\n", channel, friend_channel, 4+usr_data[channel].username_len, msg_to_send);
                            channel_secure_send(friend_channel, usr_data[friend_channel].iv, usr_data[friend_channel].key, msg_to_send, 4+usr_data[channel].username_len);
                            //write(usr_data[channel].connfd, msg_to_send, 4+usr_data[channel].username_len);
                            usr_data[friend_channel].pending = 1;
                            break;} 
                        else {
                            friend_channel++;}
                    }
                    if (friend_channel==MAX_CHANNELS){channel_secure_send(channel, usr_data[channel].iv, usr_data[channel].key, "erroUsername not found", 22);}
                }
                else {channel_secure_send(channel, usr_data[channel].iv, usr_data[channel].key, "erroUsername incorrect", 22);}
            }
            else if ((strncmp("acpt", rec_cmd, 4) == 0)&&(usr_data[channel].pending == 1)){ // User accepted connexion from friend - send each other public keys
                in_chat_flag = 1;
                if((client_msg_len-4)<16){
                    friend_channel = 0;
                    for(int n=0;n<MAX_CHANNELS;n++){ // search the friend username on the channels
                        if (strncmp(data, usr_data[friend_channel].username, usr_data[friend_channel].username_len) == 0){ // found matching username fomr database
                            user_pubkey_len = get_user_pubkey_text(usr_data[channel].username, usr_data[channel].username_len, user_pubkey);                            
                            for(int i=0;i<4;i++){msg_to_send[i] = cmd_pubk[i];}
                            for(int i=0;i<user_pubkey_len;i++){msg_to_send[i+4] = user_pubkey[i];}
                            channel_secure_send(friend_channel, usr_data[friend_channel].iv, usr_data[friend_channel].key, msg_to_send, 4+user_pubkey_len); // found 
                            printf("received acpt Send Ch (%d) TO Ch (%d) - (%d):\n", channel, friend_channel, 4+usr_data[channel].username_len);
                            // send each other the pubkey
                            user_pubkey_len = get_user_pubkey_text(usr_data[friend_channel].username, usr_data[friend_channel].username_len, user_pubkey);                            
                            for(int i=0;i<user_pubkey_len;i++){msg_to_send[i+4] = user_pubkey[i];}
                            channel_secure_send(channel, usr_data[channel].iv, usr_data[channel].key, msg_to_send, 4+user_pubkey_len);
                            printf("received acpt Send Ch (%d) TO Ch (%d) - (%d):\n", channel, friend_channel, 4+usr_data[channel].username_len);
                            break;} 
                        else {friend_channel++;}
                    }
                    printf("friend channel %d\n", friend_channel);
                    usr_data[channel].pending = 2; // conected
                    usr_data[friend_channel].pending = 2; // conected
                    //if (friend_channel==MAX_CHANNELS){channel_secure_send(channel, usr_data[channel].iv, usr_data[channel].key, "erroUsername not found", 22);}
                }
                else {channel_secure_send(channel, usr_data[channel].iv, usr_data[channel].key, "erroUsername incorrect", 22);}                    
            }
            else if ((strncmp("refu", rec_cmd, 4) == 0)&&(usr_data[channel].pending == 1)){
                usr_data[channel].pending = 0;
                for(int i=0;i<4;i++){msg_to_send[i] = cmd_refu[i];}
                for(int i=0;i<client_msg_len-4;i++){msg_to_send[i+4] = data[i];}
                channel_secure_send(friend_channel, usr_data[friend_channel].iv, usr_data[friend_channel].key, msg_to_send, client_msg_len);
            }
            else if ((strncmp("frwd", rec_cmd, 4) == 0)&&(usr_data[channel].pending == 2)){
                for(int i=0;i<4;i++){msg_to_send[i] = cmd_frwd[i];}
                for(int i=0;i<client_msg_len-4;i++){msg_to_send[i+4] = data[i];}
                channel_secure_send(friend_channel, usr_data[friend_channel].iv, usr_data[friend_channel].key, msg_to_send, client_msg_len);
                printf("received frwd Send Ch (%d) TO Ch (%d) - (%d)\n", channel, friend_channel, 4+usr_data[channel].username_len);
                
            }
            else if (strncmp("list", rec_cmd, 4) == 0){
                for(int i=0;i<4;i++){msg_to_send[i] = cmd_list[i];}
                outlen = 4;
                for(int n=0;n<MAX_CHANNELS;n++){
                    if(usr_data[n].username!=NULL){
                        for(int i=0;i<usr_data[n].username_len;i++){
                            msg_to_send[outlen]=usr_data[n].username[i];
                            outlen++;
                        }
                        msg_to_send[outlen]='\n';
                        outlen++;
                    }
                }
                channel_secure_send(channel, usr_data[channel].iv, usr_data[channel].key, msg_to_send, outlen+1);
                printf("received list Send Ch (%d) TO Ch (%d) - (%d)\n", channel, friend_channel, 4+usr_data[channel].username_len);
            }  
            else if (strncmp("exit", rec_cmd, 4) == 0){
                close (usr_data[channel].connfd); break;                 
            }        
        }
        else if (client_msg_len>0){printf("Received msg Error (%d)\n",client_msg_len);}
        else {close (usr_data[channel].connfd); break;}
    }
    // close(server_sockfd);
    for(;;); //close channel
}


void* MessageApp_channel_1(void *vargp)
{
    char client_msg[MAX_BUFF];
    int client_msg_len;
    int outlen = 0;
    char rec_cmd[4] = {0};
    char data[MAX_BUFF];
    int channel = 1;
    char msg_to_send[MAX_BUFF];
    int friend_channel;
    int user_pubkey_len;
    char user_pubkey[2048];
    int in_chat_flag = 0;
    char *cmd_chat ="chat";
    char *cmd_reqt ="reqt";
    char *cmd_pubk ="pubk";
    char *cmd_acpt ="acpt";
    char *cmd_refu ="refu";
    char *cmd_frwd = "frwd";
    char *cmd_list = "list";
    char *cmd_exit ="exit";
    
    pthread_mutex_lock(&mutex_channel[1]);    
    printf("Channel (%d) Connected (Non-Secure)\nBegin Handshake...\n", channel);
    
    // begin HANDSHAKE protocol - it returns the session key, the iv, and will set the username and username_len for this channel
    if (MessageApp_handshake(channel) !=1) // key is 32 bytes long - iv is 12 bytes long
    {
        printf("Handshake FAILED\n");
        close(usr_data[channel].connfd);
        for(;;); // close channel
    }
    else
        printf("Handshake SUCCESS Channel (%d) Connected (Secure) User: <%s>\n", channel, usr_data[channel].username);
    
    usr_data[channel].pending = 0; // start with no pendencies
    
    // infinite loop for chat
    for (;;)
    {
        /** Receive messages from logged Users */
        client_msg_len = channel_secure_receive(channel, usr_data[channel].iv, usr_data[channel].key, client_msg); // client_msg is tainted!
        printf("SERVER Received plaintext (%d): %s\n",client_msg_len ,client_msg);
        if (client_msg_len > 4){
            for (int i=0;i<4;i++){rec_cmd[i]=client_msg[i];} // Save received COMMAND
            for (int i=0;i<client_msg_len-4;i++){data[i]=client_msg[i+4];} // Save received DATA
            
            /** process Command from client */
            if ((strncmp("chat", rec_cmd, 4) == 0)&&(in_chat_flag == 0)&&(usr_data[friend_channel].pending == 0)){ // Request to chat with another user
                if((client_msg_len-4)<16){
                    friend_channel = 0;
                    for(int n=0;n<MAX_CHANNELS;n++){ // search the friend username on the channels
                        if (strncmp(data, usr_data[friend_channel].username, usr_data[friend_channel].username_len) == 0){ // found matching username fomr database
                            //msg_to_send = malloc(4+usr_data[channel].username_len);
                            for(int i=0;i<4;i++){msg_to_send[i] = cmd_reqt[i];}
                            for(int i=0;i<usr_data[channel].username_len;i++){msg_to_send[i+4] = usr_data[channel].username[i];}
                            printf("received chat Send Ch (%d) TO Ch (%d) - (%d) : %s\n", channel, friend_channel, 4+usr_data[channel].username_len, msg_to_send);
                            channel_secure_send(friend_channel, usr_data[friend_channel].iv, usr_data[friend_channel].key, msg_to_send, 4+usr_data[channel].username_len);
                            //write(usr_data[channel].connfd, msg_to_send, 4+usr_data[channel].username_len);
                            usr_data[friend_channel].pending = 1;
                            break;} 
                        else {
                            friend_channel++;}
                    }
                    if (friend_channel==MAX_CHANNELS){channel_secure_send(channel, usr_data[channel].iv, usr_data[channel].key, "erroUsername not found", 22);}
                }
                else {channel_secure_send(channel, usr_data[channel].iv, usr_data[channel].key, "erroUsername incorrect", 22);}
            }
            else if ((strncmp("acpt", rec_cmd, 4) == 0)&&(usr_data[channel].pending == 1)){ // User accepted connexion from friend - send each other public keys
                in_chat_flag = 1;
                if((client_msg_len-4)<16){
                    friend_channel = 0;
                    for(int n=0;n<MAX_CHANNELS;n++){ // search the friend username on the channels
                        if (strncmp(data, usr_data[friend_channel].username, usr_data[friend_channel].username_len) == 0){ // found matching username fomr database
                            user_pubkey_len = get_user_pubkey_text(usr_data[channel].username, usr_data[channel].username_len, user_pubkey);                            
                            for(int i=0;i<4;i++){msg_to_send[i] = cmd_pubk[i];}
                            for(int i=0;i<user_pubkey_len;i++){msg_to_send[i+4] = user_pubkey[i];}
                            channel_secure_send(friend_channel, usr_data[friend_channel].iv, usr_data[friend_channel].key, msg_to_send, 4+user_pubkey_len); // found 
                            printf("received acpt Send Ch (%d) TO Ch (%d) - (%d)\n", channel, friend_channel, 4+usr_data[channel].username_len);
                            // send each other the pubkey
                            user_pubkey_len = get_user_pubkey_text(usr_data[friend_channel].username, usr_data[friend_channel].username_len, user_pubkey);                            
                            for(int i=0;i<user_pubkey_len;i++){msg_to_send[i+4] = user_pubkey[i];}
                            channel_secure_send(channel, usr_data[channel].iv, usr_data[channel].key, msg_to_send, 4+user_pubkey_len);
                            printf("received acpt Send Ch (%d) TO Ch (%d) - (%d)\n", channel, friend_channel, 4+usr_data[channel].username_len);
                            break;} 
                        else {friend_channel++;}
                    }
                    printf("friend channel %d\n", friend_channel);
                    usr_data[channel].pending = 2; // conected
                    usr_data[friend_channel].pending = 2; // conected
                    //if (friend_channel==MAX_CHANNELS){channel_secure_send(channel, usr_data[channel].iv, usr_data[channel].key, "erroUsername not found", 22);}
                }
                else {channel_secure_send(channel, usr_data[channel].iv, usr_data[channel].key, "erroUsername incorrect", 22);}                    
            }
            else if ((strncmp("refu", rec_cmd, 4) == 0)&&(usr_data[channel].pending == 1)){
                usr_data[channel].pending = 0;
                for(int i=0;i<4;i++){msg_to_send[i] = cmd_refu[i];}
                for(int i=0;i<client_msg_len-4;i++){msg_to_send[i+4] = data[i];}
                channel_secure_send(friend_channel, usr_data[friend_channel].iv, usr_data[friend_channel].key, msg_to_send, client_msg_len);
            }
            else if ((strncmp("frwd", rec_cmd, 4) == 0)&&(usr_data[channel].pending == 2)){
                for(int i=0;i<4;i++){msg_to_send[i] = cmd_frwd[i];}
                for(int i=0;i<client_msg_len-4;i++){msg_to_send[i+4] = data[i];}
                channel_secure_send(friend_channel, usr_data[friend_channel].iv, usr_data[friend_channel].key, msg_to_send, client_msg_len);
                printf("received frwd Send Ch (%d) TO Ch (%d) - (%d)\n", channel, friend_channel, 4+usr_data[channel].username_len);
            }
            else if (strncmp("list", rec_cmd, 4) == 0){
                for(int i=0;i<4;i++){msg_to_send[i] = cmd_list[i];}
                outlen = 4;
                for(int n=0;n<MAX_CHANNELS;n++){
                    if(usr_data[n].username!=NULL){
                        for(int i=0;i<usr_data[n].username_len;i++){
                            msg_to_send[outlen]=usr_data[n].username[i];
                            outlen++;
                        }
                        msg_to_send[outlen]='\n';
                        outlen++;
                    }
                }
                channel_secure_send(channel, usr_data[channel].iv, usr_data[channel].key, msg_to_send, outlen+1);
                printf("received list Send Ch (%d) TO Ch (%d) - (%d)\n", channel, friend_channel, 4+usr_data[channel].username_len);
            }  
            else if (strncmp("exit", rec_cmd, 4) == 0){
                close (usr_data[channel].connfd); break;                 
            }        
        }
        else if (client_msg_len>0){printf("Received msg Error (%d)\n",client_msg_len);}
        else {close (usr_data[channel].connfd); break;}
    }
    // close(server_sockfd);
    for(;;); //close channel
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
    pthread_create(&thread_id[2], NULL, MessageApp_channel_1, NULL);
    
    pthread_join(thread_id[0], NULL);
    pthread_join(thread_id[1], NULL);
    pthread_join(thread_id[2], NULL);
    // Function for chatting between client and server
    // func(connfd);
  
    // After chatting close the socket
    close(server_sockfd);
} 

