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
#define MAX_CHANNELS    3

struct client_id {
    char username[16];
    size_t username_len;
    int connfd;
    unsigned char key[32];
    int pending;
    unsigned char counter_client_server[16];
    unsigned char counter_server_client[16];
    int caller_ch;
};

int MessageApp_OpenListener(int port);
int channel_secure_receive(int channel, unsigned char* clear_text);
int channel_secure_receive(int channel, unsigned char* clear_text);
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
void* MessageApp_channel_Task(void *vargp);

// Globals
struct client_id usr_data[MAX_CHANNELS];
int server_sockfd;
pthread_mutex_t mutex_channel[MAX_CHANNELS];

pthread_mutex_t free_channels_arr_mut;
int             free_channels_arr[MAX_CHANNELS];

// pthread_mutex_t mutex_handshake;

                                                                         
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
int channel_secure_send(int channel, unsigned char* send_text, int text_len)
{
    unsigned char *aad;
    int aad_len = 16+usr_data[channel].username_len;
    unsigned char tag[16];
    unsigned char out[MAX_BUFF];
    unsigned char iv[12];
    int carry=0;

    aad = malloc(aad_len);
    for (int i=0;i<usr_data[channel].username_len;i++){aad[i] = usr_data[channel].username[i];}
    for (int i=0;i<16;i++){aad[i+usr_data[channel].username_len] = usr_data[channel].counter_server_client[i];}
    for (int i=0;i<12;i++){iv[i] = usr_data[channel].counter_server_client[i];}
    // increment 16 byte counter
    usr_data[channel].counter_server_client[0] = usr_data[channel].counter_server_client[0]+1; 
    
    if (usr_data[channel].counter_server_client[0]==0){carry=1;}
    for (int n=0;n<15;n++){    
        if (usr_data[channel].counter_server_client[n]==0 && carry==1){
            usr_data[channel].counter_server_client[n+1] = usr_data[channel].counter_server_client[n+1]+1;
            if (usr_data[channel].counter_server_client[n+1]==0)
                carry=1;
            else
                carry=0;
        }
    }
    
    int outlen = EncryptAES_256_GCM(out, send_text, text_len, aad, aad_len, iv, usr_data[channel].key, tag); // return out and tag    
    if (outlen<=0){printf("Error: EncryptAES_256_GCM\n"); return 0;}
    
    unsigned char* auth_msg = malloc(outlen+aad_len+16);
    if (auth_msg==NULL){return 0;}
    
    // build msg
    for (int v=0;v<aad_len;v++)
        auth_msg[v] = aad[v];
    for (int v=0;v<16;v++)
        auth_msg[v+aad_len] = tag[v];
    for (int v=0;v<outlen;v++)
        auth_msg[v+16+aad_len] = out[v];
    
    
    printf("\nSent (%d) AAD (%d): ",outlen+aad_len+16, aad_len);
    for (int i=0;i<aad_len;i++)
        printf("%02x ", aad[i]);
    printf("\n");

    int ret_val = write(usr_data[channel].connfd, auth_msg, outlen+aad_len+16);
    return ret_val;
}

// retuns received text length
int channel_secure_receive(int channel, unsigned char* clear_text)
{
    char buff[MAX_BUFF];
    char tcp_msg[MAX_BUFF];
    int msg_size;

    unsigned char rec_tag[16];
    unsigned char rec_counter_val[16];
    unsigned char rec_username[16];
    unsigned char iv[12];
    int aad_len;
    int carry=0;
    
    fd_set read_set;
    struct timeval timeout;
    
    timeout.tv_sec = 1800; // Time out after 30 minutes
    timeout.tv_usec = 0;

    FD_ZERO(&read_set);
    FD_SET(usr_data[channel].connfd, &read_set);

    int r=select(usr_data[channel].connfd+1, &read_set, NULL, NULL, &timeout);

    if( r<=0 ) {return 0;}
    
    msg_size = read(usr_data[channel].connfd, buff, MAX_BUFF);
    
    if ((msg_size<32+usr_data[channel].username_len)||(msg_size>MAX_BUFF)) {printf("AES Received wrong message length\n"); return 0;}
    printf("AES Received (%d)\n", msg_size);

    
    aad_len = 16+usr_data[channel].username_len;
    unsigned char *rec_aad = malloc(aad_len);
    for(int i=0;i<aad_len;i++){rec_aad[i] = buff[i];}
    //printf("AAD: ");
    //for (int i=0;i<aad_len;i++)
    //    printf("%02x ", rec_aad[i]);
    //printf("\n");
    
    for(int i=0;i<usr_data[channel].username_len;i++){rec_username[i] = buff[i];}
    for(int i=0;i<16;i++){rec_counter_val[i] = buff[i+usr_data[channel].username_len];}
    
    for(int i=0;i<16;i++){rec_tag[i] = buff[i+aad_len];}
    for(int i=0;i<msg_size;i++){tcp_msg[i]=buff[i+32+usr_data[channel].username_len];}            
    
    //printf("rec_username (%ld) <%s>\n",strlen(rec_username), rec_username );
    //printf("username (%ld) <%s>\n",usr_data[channel].username_len, Username );
    
    if(strncmp(rec_username, usr_data[channel].username, usr_data[channel].username_len) != 0){printf("AES WRONG Usrname at Server comm\n"); return 0;}
    if(strncmp(rec_counter_val, usr_data[channel].counter_client_server, 16) != 0){printf("AES WRONG Counter value at Server comm\n"); return 0;}
    for(int i=0;i<12;i++){iv[i] = usr_data[channel].counter_client_server[i];}
    
    unsigned char decrypt_buff[MAX_BUFF];
    int clear_len = DecryptAES_256_GCM(decrypt_buff, tcp_msg, msg_size-(16+aad_len), rec_aad, aad_len, iv, usr_data[channel].key, rec_tag);
    if (clear_len<0){printf("AES DECRYPTION FAILED at at Server comm\n"); return 0;}

    for (int i=0;i<clear_len;i++)
        clear_text[i] = decrypt_buff[i];
    
    // increment 16 byte counter
    usr_data[channel].counter_client_server[0] = usr_data[channel].counter_client_server[0]+1; 
    if (usr_data[channel].counter_client_server[0]==0){carry=1;}
    for (int n=0;n<15;n++){    
        if (usr_data[channel].counter_client_server[n]==0 && carry==1){
            usr_data[channel].counter_client_server[n+1] = usr_data[channel].counter_client_server[n+1]+1;
            if (usr_data[channel].counter_client_server[n+1]==0)
                carry=1;
            else
                carry=0;
        }
    }
    //printf("\nsession counter: ");
    //for (int i=0;i<16;i++)
    //    printf("%02x ", usr_data[channel].counter[i]);
    //printf("\n");
    
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
    char filename[23] = {0};
    char* file_ext = "key.pem"; 
    int length;
    char buff[2048];
    
    for(int i=0; i<username_len; i++){filename[i]= username[i]; }
    for(int i=0; i<7; i++){filename[i+username_len]= file_ext[i]; }
    
    printf("TRYING TO OPEN PUBKEY: %s (%d)\n", filename, username_len+7 );
    FILE * f = fopen (filename, "r");

    if (f==NULL){f = fopen (filename, "r");}
    
    if (f==NULL){printf("FAIL TO OPEN PUBKEY: %s (%d)\n", filename, username_len+7 );return 0;}
    else
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
    
    //free(filename);
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
    
    for (int i=0;i<MAX_CHANNELS;i++) // lock all channels - wait for client connection to release them
    {
        pthread_mutex_lock(&mutex_channel[i]);
        //free_channels_arr[i]=TRUE;
        //printf("Channel %d Locked\n", i);
    }
    
    for(;;)
    {        
        //pthread_mutex_lock(&free_channels_arr_mut);
        
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
        int const curr_fd = accept(server_sockfd, (struct sockaddr*)&addr, &len);
        if (curr_fd < 0) {
            printf("server acccept failed...\n");
        }
        else
        {
            int i=0;
            int channel = 0;
            while(1)
            {
                if(free_channels_arr[i]==1) // channel is free
                {
                    pthread_mutex_lock(&free_channels_arr_mut);
                    free_channels_arr[i]=0; // set channel to occupied
                    pthread_mutex_unlock(&free_channels_arr_mut);
                    channel=i;
                    break;
                }
                i++;
                
                if(i==MAX_CHANNELS)
                    break;
            }
            if(i==MAX_CHANNELS)
            {
                write(curr_fd, "MessageApp: Server is Full - No channels availble",49);
                close (curr_fd);
            }
            else
            {
                usr_data[channel].connfd = curr_fd;
                printf("Server acccepted client in channel %d\n", channel);
                write(usr_data[channel].connfd, "MessageApp: Server conected",34);
                pthread_mutex_unlock(&mutex_channel[channel]); // release the communication channel
            }
                
        }
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

    free(digest);
    return digestlen;
}

int MessageApp_handshake(int channel)
{
    char buff[MAX_BUFF];
    char username[16]; // provisory buff - not attached to global data
    int username_len;
    int msg_size;
    char* tcp_msg;
    int ret_val;
    EVP_MD_CTX* md_ctx;
    
    unsigned char handshake_nonce_R1[32];
    unsigned char handshake_nonce_R2[32];
    unsigned char rand_val[32];
    
    /** RECEIVE R1 + Username */
    msg_size = read(usr_data[channel].connfd, buff, MAX_BUFF);
    if(msg_size<=32){printf("Hello from client Error - no username sent\n"); return 0;}
    username_len = msg_size-32;
    for (int i=0;i<32;i++){handshake_nonce_R1[i] = buff[i];}
    for (int i=0;i<username_len;i++){username[i] = buff[i+32];}

    /** check for potentially dangerous characters in username */
    if (check_tainted_string(username, username_len)!=0){ 
        printf("Username Contains Unsafe Characters!\n"); return 0; 
        write(usr_data[channel].connfd, "MessageApp: INVALID USERNAME", 28);
        close (usr_data[channel].connfd);
    }
    /** check if username is already logged*/
    printf("User Trying to Login: %s\n", username);
    for(int n=0;n<MAX_CHANNELS;n++){
        if((strncmp(username, usr_data[n].username, username_len)==0)&&(username_len==usr_data[n].username_len)){ // user already logged in
            printf("USER ALREADY LOGGED!\n");
            write(usr_data[channel].connfd, "MessageApp: USER ALREADY LOGGED", 31);
            close (usr_data[channel].connfd);
            return 0;
        }
    }
    /** BEGIN GENERATE TEMPORARY RSA 2048 KEY PAIR **/
    char *TempPubkey_txt;
    int TempPubkey_txt_len;
    
    BIO *bp_TempPubkey = NULL;
    BIO *bp_TempPrivkey = NULL;
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
    printf("Generated TEMP PUBKEY (%d): %s",TempPubkey_txt_len, TempPubkey_txt);
    /** END GENERATE TEMPORARY RSA 2048 KEY PAIR **/
    
    /** BEGIN GENERATE SIGNATURE FOR  R1 + TEMP PUBKEY + R2 **/
    RAND_poll();
    RAND_bytes(rand_val, 32);
    hash_256_bits(rand_val, 32, handshake_nonce_R2);
    
    char nonce_buff[TempPubkey_txt_len+64]; // R1 + TEMP PUBKEY + R2
    for (int i=0;i<32;i++){nonce_buff[i] = handshake_nonce_R1[i];}
    for (int i=0;i<TempPubkey_txt_len;i++){nonce_buff[i+32] = TempPubkey_txt[i];}
    for (int i=0;i<32;i++){nonce_buff[i+TempPubkey_txt_len+32] = handshake_nonce_R2[i];}
    
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
    
    /** get certificate */
    unsigned char* cert;
    int cert_len;
    FILE * f = fopen ("MessageApp_cert.pem", "r");
    if (f)
    {
        fseek (f, 0, SEEK_END);
        cert_len = ftell (f);
        fseek (f, 0, SEEK_SET);
        cert = malloc (cert_len);
        if (cert)
        {
            fread (cert, 1, cert_len, f);
        }
        else {printf("certificate malloc failed\n"); return 0;}
        fclose (f);
    }
    else {printf("opening certificate file failed\n"); return 0;}
    printf ("Copied Certificate (%d)\n", cert_len);
    
    // build message TempPubk + R2 + {R1 + TempPubk + R2}signed + Certificate
    for (int i=0;i<TempPubkey_txt_len;i++){buff[i] = TempPubkey_txt[i];}
    for (int i=0;i<32;i++){buff[i+TempPubkey_txt_len] = handshake_nonce_R2[i];}
    for (int i=0;i<256;i++){buff[i+TempPubkey_txt_len+32] = sgnt_buff[i];}
    for (int i=0;i<cert_len;i++){buff[i+TempPubkey_txt_len+32+256] = cert[i];}
    
    /** SEND TempPubk + R2 + {R1 + TempPubk + R2}signed + Certificate */
    write(usr_data[channel].connfd, buff, TempPubkey_txt_len+32+sgnt_size+cert_len);    
    printf("Sent Temporary Pubkey and Server Signature (%d)\n", TempPubkey_txt_len+32+sgnt_size+cert_len);
    
    /** RECEIVE {R2 + {K}TempPubk}signed + {K}TempPubk */
    msg_size = read(usr_data[channel].connfd, buff, MAX_BUFF);
    printf("Received User authentication and Encrypted Key (%d)\n", msg_size );
    if(msg_size<=256){printf("Signature from client Error - no key sent\n"); return 0;}
    unsigned char client_signature[256];
    int enc_k_len = msg_size-256;
    unsigned char * enc_k = malloc(enc_k_len);
    unsigned char * cmp_buff = malloc(enc_k_len+32);
    for (int i=0;i<32;i++){cmp_buff[i] = handshake_nonce_R2[i];}
    for (int i=0;i<256;i++){client_signature[i] = buff[i];}
    for (int i=0;i<enc_k_len;i++){enc_k[i] = buff[i+256]; cmp_buff[i+32] = buff[i+256];}
    
    /** BEGIN AUTHENTICATE USER BY PUBKEY **/
    char *pubkey_extension = "key.pem";
    char *filename = malloc(username_len+7);
    if(filename==NULL){printf("filename malloc failed\n"); return 0;}
    for (int i=0;i<username_len;i++){filename[i] = username[i];}
    for (int i=0;i<7;i++){filename[i+username_len] = pubkey_extension[i];}
    
    printf("Trying to open: <%s> \n", filename);
    FILE* clientpubkey_file = fopen(filename, "r");
    if(clientpubkey_file==NULL)
    {printf("USERNAME NOT REGISTERED\n"); write(usr_data[channel].connfd, "USERNAME NOT REGISTERED", 23); return 0;}
    
    EVP_PKEY* clientpubkey = PEM_read_PUBKEY(clientpubkey_file, NULL, NULL, NULL);
    fclose(clientpubkey_file);
    if(clientpubkey==NULL){printf("Error: PEM_read_PUBKEY returned NULL\n"); return 0;}
    
    // create the signature context:
    md_ctx = EVP_MD_CTX_new();
    if(md_ctx==NULL){printf("Error: EVP_MD_CTX_new returned NULL\n"); return 0;}
    
    ret_val = EVP_VerifyInit(md_ctx, EVP_sha256());
    if(ret_val == 0){printf("Error: EVP_VerifyInit returned NULL\n"); return 0;}
    ret_val = EVP_VerifyUpdate(md_ctx, cmp_buff, 32+enc_k_len);  
    if(ret_val == 0){printf("Error: EVP_VerifyUpdate returned NULL\n"); return 0;}
    ret_val = EVP_VerifyFinal(md_ctx, client_signature, 256, clientpubkey);
    if(ret_val==1)
        printf("Client Authenticated! Username(%d): <%s>\n",username_len, username);
    else{printf("Client Authentication FAILED (%d)\n", ret_val); 
        write(usr_data[channel].connfd, "USER NOT AUTHENTICATED", 22);
        return 0;}
        
    for(int i=0;i<username_len;i++){usr_data[channel].username[i] = username[i];}
    usr_data[channel].username_len = username_len;
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(clientpubkey);
    /** END AUTHENTICATE USER BY PUBKEY **/
    
    /** BEGIN DECRYPT Session KEY using TEMP PRIVKEY **/
    unsigned char *secret;
    size_t outlen;
    // Decrypt Received Message using privkey
    EVP_PKEY_CTX* ctx_p = EVP_PKEY_CTX_new(TempPrivkey, NULL);
    if (ctx_p==NULL){printf("Error: EVP_PKEY_CTX_new returned NULL\n"); return 0;}
    if (EVP_PKEY_decrypt_init(ctx_p) <= 0){printf("Error: EVP_PKEY_decrypt_init returned NULL\n"); return 0;}
    if (EVP_PKEY_CTX_set_rsa_padding(ctx_p, RSA_PKCS1_OAEP_PADDING) <= 0){printf("Error: EVP_PKEY_CTX_set_rsa_padding returned NULL\n"); return 0;}
    /* Determine buffer length */
    if (EVP_PKEY_decrypt(ctx_p, NULL, &outlen, enc_k, enc_k_len) <= 0){printf("Error: EVP_PKEY_decrypt returned NULL\n"); return 0;}
    
    secret = OPENSSL_malloc(outlen);
    if (!secret){printf("Malloc Failed for decrypted message\n"); return 0;}
        
    ret_val = EVP_PKEY_decrypt(ctx_p, secret, &outlen, enc_k, enc_k_len);
    if (ret_val<=0){printf("DECRYPTION Error: EVP_PKEY_decrypt\n"); return 0;}
    
    EVP_PKEY_free(TempPrivkey);
    EVP_PKEY_CTX_free(ctx_p);
    /** END DECRYPT Session KEY using TEMP PRIVKEY **/
    
    for (int i=0;i<32;i++){usr_data[channel].key[i] = secret[i];}
    printf("\nCHANNEL (%d) SESSION KEY: ", channel);
    for (int k=0;k<6;k++){
        printf("%02x ", usr_data[channel].key[k]);
    }
    
    free(secret);
    free(enc_k);
    free(cmp_buff);
    
    printf("\nFinished Handshake\n");
    
    channel_secure_send(channel, "User Login Complete!", 20);
    
    return 1;
}



// Function designed for chat between client and server.
void* MessageApp_channel_Task(void *vargp)
{
    for (;;)
    {
        int *ptr_channel;
        ptr_channel = (int *) vargp;
        int channel = *ptr_channel;
        char client_msg[MAX_BUFF];
        int client_msg_len;
        int outlen = 0;
        char rec_cmd[4] = {0};
        char data[MAX_BUFF];
        char msg_to_send[MAX_BUFF];
        int friend_channel = 0;
        int user_pubkey_len;
        char user_pubkey[600];
        //int in_chat_flag = 0;
        char *cmd_chat ="chat";
        char *cmd_reqt ="reqt";
        char *cmd_pubk ="pubk";
        char *cmd_acpt ="acpt";
        char *cmd_refu ="refu";
        char *cmd_frwd = "frwd";
        char *cmd_list = "list";
        char *cmd_exit ="exit";
        char *cmd_help ="help";
        char *in_chat_str="[IN CHAT]";
        char *help_string = "helpMessageApp Interface Commands\n \
                            Server commands:\n \
                            [SERVER-COMMAND]->listx (list online users)\n \
                            [SERVER-COMMAND]->exitx (logoff the server - close connection)\n \
                            [SERVER-COMMAND]->helpx (retrieve the help string)\n \
                            [SERVER-COMMAND]->chat'username' (call a user - no spaces and no quotes in the command)\n \
                            example: chatalice\n\n \
                            When Received a Chat Request:\n \
                            [SERVER-COMMAND]->acptx (to acept the call)\n \
                            [SERVER-COMMAND]->refux (to refuse the call)\n\n \
                            When Calling a friend you can also cancel the Call using the following cmd:\n \
                            [SERVER-COMMAND]->cachx\n\n \
                            To exit the Chat use:\n \
                            [CHAT]->/exit\n";

        
        pthread_mutex_lock(&free_channels_arr_mut);
        free_channels_arr[channel]=1;
        printf("Channel (%d) is FREE\n", channel);
        pthread_mutex_unlock(&free_channels_arr_mut);

        pthread_mutex_lock(&mutex_channel[channel]); // Task waiting for connection
        printf("Channel (%d) is TAKEN\n", channel);
        printf("Channel (%d) Connected (Non-Secure)\nBegin Handshake...\n", channel);
        for(int i=0;i<16;i++){usr_data[channel].counter_client_server[i]='\0';}
        for(int i=0;i<16;i++){usr_data[channel].counter_server_client[i]='\0';}
        // begin HANDSHAKE protocol - it returns the session key and will set the username and username_len for this channel
        if (MessageApp_handshake(channel) !=1) 
        {
            printf("Handshake FAILED\n");
            close(usr_data[channel].connfd);
            for (int i=0;i<16;i++){usr_data[channel].username[i] = '\0';}
            usr_data[channel].username_len = 0;
        }
        else
        {
            printf("Handshake SUCCESS at Channel (%d) Connected (Secure) User: <%s>\n", channel, usr_data[channel].username);
            usr_data[channel].pending = 0; // start with no pendencies
            for (;;)
            {
                /** Receive messages from logged Users */
                client_msg_len = channel_secure_receive(channel, client_msg);
                
                if (client_msg_len > 4){
                    for (int i=0;i<4;i++){rec_cmd[i]=client_msg[i];} // Save received COMMAND
                    for (int i=0;i<client_msg_len-4;i++){data[i]=client_msg[i+4];} // Save received DATA
                    printf("SERVER Ch (%d) Pd (%d) Received (%d) cmd: %s\n",channel, usr_data[channel].pending, client_msg_len ,rec_cmd);
                    /** process Command from client */
                    if ((strncmp("chat", rec_cmd, 4) == 0)&&(usr_data[channel].pending == 0)){ // Request to chat with another user
                        friend_channel = 0;
                        if((client_msg_len-4)<=16){
                            if (check_tainted_string(data, client_msg_len-4)!=0){
                                printf("Chat cmd received - Data contains unsafe chars\n");
                                channel_secure_send(channel, "erroUsername Contains Invalid Chars!", 34);
                            }
                            else{
                                for(int n=0;n<MAX_CHANNELS;n++){ // search the friend username on the channels
                                    if ((strncmp(data, usr_data[friend_channel].username, strlen(data)) == 0)&&(usr_data[friend_channel].username_len == strlen(data))){
                                        printf("Called friend found: %s - <%s>\n", data, usr_data[friend_channel].username);
                                        if((strncmp(data, usr_data[channel].username, strlen(data)) == 0) && (usr_data[channel].username_len == strlen(data))){
                                            channel_secure_send(channel, "erroCannot Request Chat to itself!", 34);
                                            break;
                                        }    
                                        else{    
                                            if(usr_data[friend_channel].pending == 0){ // check if friend is already in chat
                                                for(int i=0;i<4;i++){msg_to_send[i] = cmd_reqt[i];}
                                                for(int i=0;i<usr_data[channel].username_len;i++){msg_to_send[i+4] = usr_data[channel].username[i];}
                                                printf("Received Chat Request - Calling <%s> Ch (%d) From <%s> Ch (%d)\n", usr_data[friend_channel].username, friend_channel, usr_data[channel].username, channel);
                                                
                                                channel_secure_send(friend_channel, msg_to_send, 4+usr_data[channel].username_len);
                                                channel_secure_send(channel, "reqtRequest Sent to Friend!", 27);
                                                usr_data[channel].pending = 4; // pending 4 is calling...
                                                usr_data[friend_channel].pending = 1; // pending 1 is received request...
                                                usr_data[friend_channel].caller_ch = channel;
                                            }
                                            else{channel_secure_send(channel, "erroUser Unavailable!", 21);}
                                        }
                                        break;
                                    } 
                                    else {
                                        friend_channel++;
                                    }
                                }
                            }
                            if (friend_channel==MAX_CHANNELS){channel_secure_send(channel, "erroUser not Online/Not Registered", 34);}
                        }
                        else {channel_secure_send(channel, "erroUsername Size incorrect", 27);}
                    }
                    else if ((strncmp("acpt", rec_cmd, 4) == 0)&&(usr_data[channel].pending == 1)){ // User accepted connexion from friend - send each other public keys
                        //in_chat_flag = 1;
                        //if((client_msg_len-4)<16){
                        friend_channel = usr_data[channel].caller_ch;
                        //friend_channel = 0;
                        //for(int n=0;n<MAX_CHANNELS;n++){ // search the friend username on the channels
                        //    if ((strncmp(data, usr_data[friend_channel].username, strlen(data)) == 0)&&(usr_data[friend_channel].username_len == strlen(data))){
                        user_pubkey_len = get_user_pubkey_text(usr_data[channel].username, usr_data[channel].username_len, user_pubkey);                            
                        if(user_pubkey_len>0){
                            for(int i=0;i<4;i++){msg_to_send[i] = cmd_pubk[i];}
                            for(int i=0;i<user_pubkey_len;i++){msg_to_send[i+4] = user_pubkey[i];}
                            channel_secure_send(friend_channel, msg_to_send, 4+user_pubkey_len);
                            printf("Received acpt - Send Caller Ch (%d) friend pubkey\n", friend_channel);
                            usr_data[channel].pending = 2; // reciever connected
                            for (int i=0;i<2048;i++){user_pubkey[i]='\0';}
                            
                            user_pubkey_len = get_user_pubkey_text(usr_data[friend_channel].username, usr_data[friend_channel].username_len, user_pubkey);
                            if(user_pubkey_len>0){
                                for(int i=0;i<user_pubkey_len;i++){msg_to_send[i+4] = user_pubkey[i];}
                                channel_secure_send(channel, msg_to_send, 4+user_pubkey_len);
                                printf("Received acpt - Send Receiver Ch (%d) friend pubkey\n", channel);
                                usr_data[friend_channel].pending = 2; // caller conected
                                for (int i=0;i<2048;i++){user_pubkey[i]='\0';}
                            }
                            else {
                                channel_secure_send(channel, "erroFail to get Pubkeys", 22); 
                                usr_data[channel].pending = 0;
                                channel_secure_send(friend_channel, "erroFail to get Pubkeys", 22);
                                usr_data[friend_channel].pending = 0;
                            }
                        }
                        else{
                            channel_secure_send(channel, "erroFail to get Pubkeys", 22);
                            usr_data[channel].pending = 0;
                            channel_secure_send(friend_channel, "erroFail to get Pubkeys", 22);
                            usr_data[friend_channel].pending = 0;    
                        }
                        //for (int i=0;i<2048;i++){user_pubkey[i]='\0';}
                        //user_pubkey_len = get_user_pubkey_text(usr_data[friend_channel].username, usr_data[friend_channel].username_len, user_pubkey);                            
                        //if(user_pubkey_len>0){
                        //    for(int i=0;i<user_pubkey_len;i++){msg_to_send[i+4] = user_pubkey[i];}
                        //    channel_secure_send(channel, msg_to_send, 4+user_pubkey_len);
                        //    printf("received acpt Send Ch (%d) - (%d): %s\n", channel, 4+user_pubkey_len, user_pubkey);
                        //    usr_data[friend_channel].pending = 2; // conected
                        //}
                        //else {
                        //    channel_secure_send(channel, "erroFail to get Pubkeys", 22);usr_data[channel].pending = 0;
                        //    channel_secure_send(channel, "erroFail to get Pubkeys", 22);usr_data[friend_channel].pending = 0;    
                        //    break;}
                        //break;
                        //    //} 
                        //    //else {friend_channel++;}
                        ////}
                        //printf("friend channel %d\n", friend_channel);
                        //if (friend_channel==MAX_CHANNELS){channel_secure_send(channel, usr_data[channel].iv, usr_data[channel].key, "erroUsername not found", 22);}
                        //}
                        //else {channel_secure_send(channel, "erroUsername incorrect", 22);}                    
                    }
                    else if ((strncmp("refu", rec_cmd, 4) == 0)&&(usr_data[channel].pending == 1)){
                        friend_channel = usr_data[channel].caller_ch;
                        //for(int n=0;n<MAX_CHANNELS;n++){ // search the friend username on the channels
                        //    if ((strncmp(data, usr_data[friend_channel].username, strlen(data)) == 0)&&(usr_data[friend_channel].username_len == strlen(data))){
                        //        break;}
                        //    else {friend_channel++;}
                        //}
                        usr_data[channel].pending = 0;
                        usr_data[friend_channel].pending = 0;
                        for(int i=0;i<4;i++){msg_to_send[i] = cmd_refu[i];}
                        for(int i=0;i<usr_data[channel].username_len;i++){msg_to_send[i+4] = usr_data[channel].username[i];}
                        channel_secure_send(friend_channel, msg_to_send, 4+usr_data[channel].username_len);
                    }
                    else if ((strncmp("cach", rec_cmd, 4) == 0)&&(usr_data[channel].pending == 4)){
                        usr_data[channel].pending = 0;
                        usr_data[friend_channel].pending = 0;
                        channel_secure_send(channel, "erroChat Canceled", 17);
                        channel_secure_send(friend_channel, "erroChat Canceled", 17);
                    }
                    else if ((strncmp("frwd", rec_cmd, 4) == 0)&&(usr_data[channel].pending == 2)){
                        for(int i=0;i<4;i++){msg_to_send[i] = cmd_frwd[i];}
                        for(int i=0;i<client_msg_len-4;i++){msg_to_send[i+4] = data[i];}
                        if (usr_data[friend_channel].pending == 2){
                            channel_secure_send(friend_channel, msg_to_send, client_msg_len);
                            printf("received frwd Send Ch (%d) To Ch (%d) - (%ld)\n", channel, friend_channel, 4+usr_data[channel].username_len);
                        }
                        else {channel_secure_send(channel, "erroFriend Disconected from Chat", 32);}
                    }
                    else if (strncmp("list", rec_cmd, 4) == 0){
                        for(int i=0;i<4;i++){msg_to_send[i] = cmd_list[i];}
                        outlen = 4;
                        for(int n=0;n<MAX_CHANNELS;n++){
                            if((usr_data[n].username_len>0)&&(usr_data[n].pending !=2)){
                                for(int i=0;i<usr_data[n].username_len;i++){
                                    msg_to_send[outlen]=usr_data[n].username[i];
                                    outlen++;
                                }
                                msg_to_send[outlen]='\n';
                                outlen++;
                            }
                            else if ((usr_data[n].username_len>0)&&(usr_data[n].pending ==2)){
                                for(int i=0;i<usr_data[n].username_len;i++){
                                    msg_to_send[outlen]=usr_data[n].username[i];
                                    outlen++;
                                }
                                for(int i=0;i<9;i++){
                                    msg_to_send[outlen]=in_chat_str[i];
                                    outlen++;
                                }
                                msg_to_send[outlen]='\n';
                                outlen++;
                            }
                                
                        }
                        channel_secure_send(channel, msg_to_send, outlen+1);
                        printf("received list cmd \n");
                    }  
                    else if (strncmp("exit", rec_cmd, 4) == 0){
                        printf("User Disconnected from Channel (%d)\n", channel);
                        if ((usr_data[channel].pending == 2)||(usr_data[channel].pending == 4)||(usr_data[channel].pending == 1)){
                            friend_channel = usr_data[channel].caller_ch;
                            usr_data[friend_channel].pending=0;
                            channel_secure_send(friend_channel, "erroFriend Disconnected", 23);
                        } // disconect friend from chat
                        for (int i=0;i<16;i++){usr_data[channel].username[i] = '\0';} // remove user
                        close (usr_data[channel].connfd);
                        usr_data[channel].username_len = 0;
                        usr_data[channel].pending =0;
                        break;
                    }
                    else if ((strncmp("exch", rec_cmd, 4) == 0)&&(usr_data[channel].pending == 2)){
                        usr_data[channel].pending = 0;
                        usr_data[friend_channel].pending = 0;
                        channel_secure_send(friend_channel, "erroFriend Disconnected from Chat", 33);
                    }
                    else if (strncmp("help", rec_cmd, 4) == 0){
                        channel_secure_send(friend_channel, help_string, strlen(help_string));
                    }
                }
                else if (client_msg_len>0){
                    printf("Received Command Error (%d) Ch (%d)\n",client_msg_len, channel);
                    channel_secure_send(channel, "erroWrong Command Received", 26);
                }
                else {
                    printf("DISCONNECTION in Channel (%d)\n", channel);
                    if ((usr_data[channel].pending == 2)||(usr_data[channel].pending == 4)||(usr_data[channel].pending == 1)){
                        friend_channel = usr_data[channel].caller_ch;
                        usr_data[friend_channel].pending=0;
                        printf("Released friend in Channel (%d)\n", friend_channel);
                        channel_secure_send(friend_channel, "erroFriend Disconnected", 23);
                    } // disconect friend from chat
                    for (int i=0;i<16;i++){usr_data[channel].username[i] = '\0';}
                    usr_data[channel].username_len = 0;
                    usr_data[channel].pending = 0;
                    close (usr_data[channel].connfd); 
                    break;
                }
                printf("Cleanup\n");
                for (int i=0;i<MAX_BUFF;i++){data[i]='\0';}
                for (int i=0;i<MAX_BUFF;i++){msg_to_send[i]='\0';}
                for (int i=0;i<2048;i++){user_pubkey[i]='\0';}
            }
        }
        printf("Client Exited Channel (%d)\n", channel);
    }
}
/*
struct channel_descriptor_t
{
    bool in_use;
    
}
*/

// Driver function
int main(int n_input, char *input_args[])
{
    pthread_t thread_id[MAX_CHANNELS+1];
    int ch = 0;
    int ch_array[MAX_CHANNELS];
    
    int const port = MessageApp_launch_param_check(n_input, input_args);
    if ( port>0)
        printf("MessageApp Server launched !! connection port: %d\n\n", port);
    else
    {
        printf("MessageApp launch FAILED\n");
        exit(0);
    }
    server_sockfd = MessageApp_OpenListener(port);

    pthread_create(&thread_id[0], NULL, MessageApp_client_connect, NULL);
    for (int i=0;i<MAX_CHANNELS;i++){
        ch_array[i] = ch;
        pthread_create(&thread_id[i+1], NULL, MessageApp_channel_Task, &ch_array[i]);
        ch++;
    }
    for (int i=0;i<MAX_CHANNELS+1;i++)
        pthread_join(thread_id[i], NULL);

    printf("Returned\n");
    for (;;);
    //close(server_sockfd);
} 

