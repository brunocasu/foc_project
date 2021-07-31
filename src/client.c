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
unsigned char session_key[32];
unsigned char session_counter_client_server[16] = {0};
unsigned char session_counter_server_client[16] = {0};
int sockfd;
int caller=0; // caller is 1 if you is the one who started the chat
int chat_with_friend_flag = 0; // flag is set to one to add the chat session key in the encryption
//unsigned char chat_iv[12];
unsigned char chat_session_key[32];
unsigned char chat_counter_myself_to_friend[16] = {0};
unsigned char chat_counter_friend_to_myself[16] = {0};
pthread_mutex_t mutex_print;
EVP_PKEY* privkey;
int acpt_flag = 0;

int chat_encrypt(char* encrypted_txt, char* in ,int inlen);
int chat_decrypt(char* clear_txt, char* in, int inlen);
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
int server_secure_send(int sockfd, unsigned char* key, unsigned char* send_text, int text_len)
{
    unsigned char *aad;
    int aad_len = 16+strlen(Username);
    unsigned char tag[16];
    unsigned char out[MAX_BUFF];
    unsigned char iv[12];
    int carry=0;

    aad = malloc(aad_len);
    for (int i=0;i<strlen(Username);i++){aad[i] = Username[i];}
    for (int i=0;i<16;i++){aad[i+strlen(Username)] = session_counter_client_server[i];}
    for (int i=0;i<12;i++){iv[i] = session_counter_client_server[i];}
    // increment 16 byte counter
    session_counter_client_server[0] = session_counter_client_server[0]+1; 
    if (session_counter_client_server[0]==0){carry=1;}
    for (int n=0;n<15;n++){    
        if (session_counter_client_server[n]==0 && carry==1){
            session_counter_client_server[n+1] = session_counter_client_server[n+1]+1;
            if (session_counter_client_server[n+1]==0)
                carry=1;
            else
                carry=0;
        }
    }
    
    int outlen = EncryptAES_256_GCM(out, send_text, text_len, aad, aad_len, iv, key, tag); // return out and tag    
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
    
    
    //printf("\nSent (%d) AAD (%d): ",outlen+aad_len+16, aad_len);
    //for (int i=0;i<aad_len;i++)
    //    printf("%02x ", aad[i]);
    //printf("\n");

    int ret_val = write(sockfd, auth_msg, outlen+aad_len+16);
    return ret_val;
}


// retuns received text length
int server_secure_receive(int sockfd, unsigned char* key, unsigned char* clear_text)
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
    FD_SET(sockfd, &read_set);

    int r=select(sockfd+1, &read_set, NULL, NULL, &timeout);

    if( r<=0 ) {return 0;}
    
    msg_size = read(sockfd, buff, MAX_BUFF);
    
    if ((msg_size<32+strlen(Username))||(msg_size>MAX_BUFF)) {printf("AES Received wrong message length\n"); return 0;}
    // printf("AES Received (%d)\n", msg_size);

    
    aad_len = 16+strlen(Username);
    unsigned char *rec_aad = malloc(aad_len);
    for(int i=0;i<aad_len;i++){rec_aad[i] = buff[i];}
    //printf("AAD: ");
    //for (int i=0;i<aad_len;i++)
    //    printf("%02x ", rec_aad[i]);
    //printf("\n");
    
    for(int i=0;i<strlen(Username);i++){rec_username[i] = buff[i];}
    for(int i=0;i<16;i++){rec_counter_val[i] = buff[i+strlen(Username)];}
    
    for(int i=0;i<16;i++){rec_tag[i] = buff[i+aad_len];}
    for(int i=0;i<msg_size;i++){tcp_msg[i]=buff[i+32+strlen(Username)];}            
    
    //printf("rec_username (%ld) <%s>\n",strlen(rec_username), rec_username );
    //printf("username (%ld) <%s>\n",strlen(Username), Username );
    
    if(strncmp(rec_username, Username, strlen(Username)) != 0){printf("AES WRONG Usrname at Server comm\n"); return 0;}
    if(strncmp(rec_counter_val, session_counter_server_client, 16) != 0){printf("AES WRONG Counter value at Server comm\n"); return 0;}
    
    for (int i=0;i<12;i++){iv[i] = rec_counter_val[i];}
    
    unsigned char decrypt_buff[MAX_BUFF];
    int clear_len = DecryptAES_256_GCM(decrypt_buff, tcp_msg, msg_size-(16+aad_len), rec_aad, aad_len, iv, key, rec_tag);
    if (clear_len<0){printf("AES DECRYPTION FAILED at at Server comm\n"); return 0;}

    for (int i=0;i<clear_len;i++)
        clear_text[i] = decrypt_buff[i];
    
    // increment 16 byte counter
    session_counter_server_client[0] = session_counter_server_client[0]+1; 
    if (session_counter_server_client[0]==0){carry=1;}
    for (int n=0;n<15;n++){    
        if (session_counter_server_client[n]==0 && carry==1){
            session_counter_server_client[n+1] = session_counter_server_client[n+1]+1;
            if (session_counter_server_client[n+1]==0)
                carry=1;
            else
                carry=0;
        }
    }
    //printf("\nsession counter: ");
    //for (int i=0;i<16;i++)
    //    printf("%02x ", session_counter[i]);
    //printf("\n");
    
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



int ClientHandshake()
{
    char buff[MAX_BUFF];
    char username[16];
    int msg_size;
    char* tcp_msg;
    int ret_val;
    EVP_MD_CTX* md_ctx;
    
    unsigned char handshake_nonce_R1[32];
    unsigned char handshake_nonce_R2[32];
    unsigned char rand_val[32];
    /** get username */
    printf("Begin Handshake\nUsername :"); // (MAX 16 chars - No spaces or Special characters)
    fgets(username, 16, stdin);
    if ((strlen(username) > 0) && (username[strlen (username) - 1] == '\n'))
        username[strlen (username) - 1] = '\0';
    else {return 0;}
    if (check_tainted_string(username, strlen(username)) != 0){ printf("Username contains invalid characters"); return 0;}   
    Username = malloc(strlen(username));
    for (int i=0;i<strlen(username);i++){Username[i] = username[i];} // save username
    /** get privkey */
    FILE* privkey_file = fopen("privkey.pem", "r");
    if(privkey_file==NULL){printf("Privkey File Open Error\n"); return 0;}
    privkey = PEM_read_PrivateKey(privkey_file, NULL, NULL, NULL);
    fclose(privkey_file);
    if(privkey==NULL){printf("Error: PEM_read_PrivateKey returned NULL\n"); return 0; }
    /** generate nonce R1 */
    RAND_poll();
    RAND_bytes(rand_val, 32);
    hash_256_bits(rand_val, 32, handshake_nonce_R1);
    for (int i=0;i<32;i++){buff[i] = handshake_nonce_R1[i];}
    for (int i=0;i<strlen(username);i++){buff[i+32] = username[i];}
    
    /** SEND R1 + Username */
    printf("\nSend Hello to Server\n");
    write(sockfd, buff, 32+strlen(username)); // Send R1
    
    /** RECEIVE R2 + TempPubkey + {R1+TempPubkey+R2}signed + CertS */
    msg_size = read(sockfd, buff, MAX_BUFF);
    printf("Received Server authentication and Certificate (%d)\n", msg_size);
    if(msg_size<=426+32+256){printf("Signature from server Error - no certificate sent\n"); return 0;}
    char server_authentication_str[490]; // R1+TempPubkey+R2 -> 32+426+32 
    for (int i=0;i<32;i++){server_authentication_str[i]=handshake_nonce_R1[i];}
    char TempPubkey_txt[426]; 
    int TempPubkey_txt_len=426;
    for (int i=0;i<426;i++){server_authentication_str[i+32]=buff[i]; TempPubkey_txt[i] = buff[i];}
    for (int i=0;i<32;i++){server_authentication_str[i+32+426]=buff[i+426]; handshake_nonce_R2[i]=buff[i+426];}
    char server_signature[256];
    for (int i=0;i<256;i++){server_signature[i]=buff[i+426+32];}
    unsigned char* server_certificate = malloc(msg_size-426-32-256);
    if(server_certificate==NULL){printf("server_certificate malloc failed\n"); return 0;}
    for (int i=0;i<msg_size-426-32-256;i++){server_certificate[i]=buff[i+426+32+256];}
    /** save server certificate */
    FILE *f = fopen ("ServerCert.pem", "ab+");
    if (f != NULL) {
        if (fputs (server_certificate, f) == EOF) {printf("\n\Error Writing Certificate\n"); return 0;}
        fclose (f); 
    }
    
    // printf("signature: (%s)\n", server_authentication_str);
    
    /** get certificate authority */
    FILE* CA_file = fopen("TrustedCA_cert.pem", "r");
    if(CA_file==NULL){printf("CA File Open Error\n"); return 0;}
    X509* CAcert = PEM_read_X509(CA_file, NULL, NULL, NULL);
    fclose(CA_file);
    if(CAcert==NULL){printf("Error CA: PEM_read_X509 returned NULL\n"); return 0;}   
    /** build the certificate store */
    X509_STORE* store = X509_STORE_new();
    if(store==NULL){printf("Error CA: X509_STORE_new() returned NULL\n"); return 0;}
    ret_val = X509_STORE_add_cert(store, CAcert);
    if(ret_val == 0){printf("Error: X509_STORE_add_cert\n"); return 0;}
    ret_val = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    if(ret_val == 0){printf("Error: X509_STORE_set_flags\n"); return 0;}
    /** get peer certificate*/
    FILE* cert_file = fopen("ServerCert.pem", "r");
    if(cert_file==NULL){printf("Certificate File Open Error\n"); return 0;}
    X509* cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    fclose(cert_file);
    if(cert==NULL){printf("Error: PEM_read_X509 returned NULL\n"); return 0;}
    /** print certificate parameters */
    char* tmp = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    char* tmp2 = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
    printf("\nCertificate of %s\n issued by %s\n",tmp, tmp2);
    free(tmp);
    free(tmp2);
    /** authenticate peer using its certificate */
    md_ctx = EVP_MD_CTX_new();
    if(md_ctx==NULL){printf("Error: EVP_MD_CTX_new returned NULL\n"); return 0;}
    
    ret_val = EVP_VerifyInit(md_ctx, EVP_sha256());
    if(ret_val == 0){printf("Error: EVP_VerifyInit returned NULL\n"); return 0;}
    ret_val = EVP_VerifyUpdate(md_ctx, server_authentication_str, 490);  
    if(ret_val == 0){printf("Error: EVP_VerifyUpdate returned NULL\n"); return 0;}
    ret_val = EVP_VerifyFinal(md_ctx, server_signature, 256, X509_get_pubkey(cert));

    if(ret_val==1)
        printf("Server Authenticated!\n");
    else{
        printf("Server Authentication FAILED (%d)\n", ret_val);
        return 0;}
  
    EVP_MD_CTX_free(md_ctx);
    
    /** SEND {R2 + {K}TempPubk }SigA + IV + {K}TempPubk */
    RAND_poll();
    RAND_bytes(rand_val, 32);
    hash_256_bits(rand_val, 32, session_key);
    /** retrieve temporary pubkey from txt */
    EVP_PKEY* TempPubkey = EVP_PKEY_new();
    RSA *temp_rsa = NULL;
    BIO* pb_TempPubkey = BIO_new_mem_buf((void*) TempPubkey_txt, TempPubkey_txt_len);
    if (pb_TempPubkey==NULL){printf("BIO_new_mem_buf returned NULL\n");}
    printf("TEMP PUBKEY (%d): (%s)",TempPubkey_txt_len, TempPubkey_txt);
    temp_rsa = PEM_read_bio_RSAPublicKey(pb_TempPubkey, &temp_rsa, NULL, NULL);
    if (temp_rsa == NULL) {printf("PEM_read_bio_RSAPublicKey returned NULL\n"); return 0;}
    
    EVP_PKEY_assign_RSA(TempPubkey, temp_rsa); // set TempPubkey to correct format
    
    unsigned char *enc_k; // encrypted Session Key 'K' with Temporary Public Key
    size_t outlen;
    
    /** encrypt session key using temporary pubkey */
    EVP_PKEY_CTX* ctx_p = EVP_PKEY_CTX_new(TempPubkey, NULL);
    if (ctx_p==NULL){printf("Error: EVP_PKEY_CTX_new returned NULL\n"); return 0;}
    ret_val = EVP_PKEY_encrypt_init(ctx_p);
    if(ret_val <= 0){printf("Error: EVP_PKEY_encrypt_init\n"); return 0;}
    ret_val = EVP_PKEY_CTX_set_rsa_padding(ctx_p, RSA_PKCS1_OAEP_PADDING);
    if(ret_val <= 0){printf("Error: EVP_PKEY_CTX_set_rsa_padding\n"); return 0;}
    // Determine buffer size for encrypted length
    if (EVP_PKEY_encrypt(ctx_p, NULL, &outlen, session_key, 32) <= 0)
    {printf("Error: EVP_PKEY_encrypt\n"); return 0;}
    
    enc_k = OPENSSL_malloc(outlen);
    if (enc_k==NULL){printf("Malloc failed for username encryption\n"); return 0;}

    ret_val = EVP_PKEY_encrypt(ctx_p, enc_k, &outlen, session_key, 32);
    if (ret_val<=0){printf("ENCRYPTION Error: EVP_PKEY_encrypt\n"); return 0;}
        
    EVP_PKEY_CTX_free(ctx_p);
    EVP_PKEY_free(TempPubkey);
    
    /** sign R2 + encrypted session key using privkey */
    char *sign_buff = malloc(32+outlen);
    if (sign_buff==NULL){printf("Malloc failed for username encryption\n"); return 0;}
    for (int i=0;i<32;i++){sign_buff[i]=handshake_nonce_R2[i];}
    for (int i=0;i<outlen;i++){sign_buff[i+32]=enc_k[i];}
    
    md_ctx = EVP_MD_CTX_new();
    if(md_ctx==NULL){printf("Error: EVP_MD_CTX_new returned NULL\n"); return 0;}
    
    unsigned char* signature = (unsigned char*)malloc(EVP_PKEY_size(privkey));
    if(signature==NULL) {printf("Error: malloc returned NULL\n"); return 0;}
    
    ret_val = EVP_SignInit(md_ctx, EVP_sha256());
    if(ret_val == 0){printf("Error: EVP_SignInit returned %d\n",ret_val); return 0;}
    ret_val = EVP_SignUpdate(md_ctx, sign_buff, 32+outlen);
    if(ret_val == 0){printf("Error: EVP_SignUpdate returned %d\n",ret_val); return 0;}
    unsigned int sign_size;
    ret_val = EVP_SignFinal(md_ctx, signature, &sign_size, privkey); // return the signed message
    if(ret_val == 0){printf("Error: EVP_SignFinal returned %d\n",ret_val); return 0;}

    EVP_MD_CTX_free(md_ctx);
    /** SEND {R2 + {K}TempPubk}Signature + {K}TempPubk */
    //RAND_poll();
    //RAND_bytes(iv, 12);
    for (int i=0;i<256;i++) {buff[i] = signature[i];}
    //for (int i=0;i<12;i++) {buff[i+256] = iv[i];}
    for (int i=0;i<outlen;i++) {buff[i+256] = enc_k[i];}
    printf("\nSend Signature to Server \n");
    write(sockfd, buff, 256+outlen); 
    
    printf("\nSESSION KEY: ");
    for (int k=0;k<32;k++){
        printf("%02x ", session_key[k]);
    }
    
    printf("\nFinished Handshake\n");
    
    msg_size = server_secure_receive(sockfd, session_key, buff);
    char *rcv_msg = malloc(msg_size);
    for (int i=0;i<msg_size;i++){rcv_msg[i] = buff[i];}
    printf("From Server: %s\n", rcv_msg);
    free(rcv_msg);
    
    return 1;
}



int friend_begin_negotiation()
{
    unsigned char rand_val[32];
    unsigned char chat_nonce_R1[32];
    unsigned char chat_nonce_R2[32];
    EVP_MD_CTX* md_ctx;
    char buff[MAX_BUFF];
    int msg_len;
    int ret_val;
    char *cmd_frwd = "frwd";
    
    printf("\nBegin Negotiation\n");
    
    RAND_poll();
    RAND_bytes(rand_val, 32);
    hash_256_bits(rand_val, 32, chat_nonce_R1);
    
    for(int i=0;i<4;i++){buff[i]=cmd_frwd[i];}
    for(int i=0;i<32;i++){buff[i+4]=chat_nonce_R1[i];}
    /** SEND Nonce R1 */
    sleep(1);
    server_secure_send(sockfd, session_key, buff, 36); // must add "frwd" cmd before string
    printf("Sent R1\n");
    
    /** RECEIVE TempPubk + R2 + {R1+TempPubk+R2}Signed */
    msg_len = server_secure_receive(sockfd, session_key, buff);
    printf("Received Friend Signature\n");
    char rec_cmd[4];
    for (int i=0;i<4;i++){rec_cmd[i] = buff[i];}
    if (strncmp(cmd_frwd, rec_cmd, 4)!=0){printf("Message Command ERROR\n"); return 0;}
    
    if(msg_len<4+426+32+256){printf("Signature size from friend ERROR\n"); return 0;}
    char friend_authentication_str[490]; // R1+TempPubkey+R2 -> 32+426+32 
    for (int i=0;i<32;i++){friend_authentication_str[i]=chat_nonce_R1[i];}
    char TempPubkey_txt[426]; 
    int TempPubkey_txt_len=426;
    for (int i=0;i<426;i++){friend_authentication_str[i+32]=buff[i+4]; TempPubkey_txt[i] = buff[i+4];} // first 4 bytes from buff are protocol control
    for (int i=0;i<32;i++){friend_authentication_str[i+32+426]=buff[i+4+426]; chat_nonce_R2[i]=buff[i+4+426];}
    char friend_signature[256];
    for (int i=0;i<256;i++){friend_signature[i]=buff[i+4+426+32];}
    
    /** BEGIN AUTHENTICATE FRIEND BY PUBKEY */
    FILE* clientpubkey_file = fopen("friendPubkey.pem", "r");
    if(clientpubkey_file==NULL)
    {printf("Fail to Open Pubkey File\n"); return 0;}
    
    EVP_PKEY* friend_pubkey = PEM_read_PUBKEY(clientpubkey_file, NULL, NULL, NULL);
    fclose(clientpubkey_file);
    if(friend_pubkey==NULL){printf("Error: PEM_read_PUBKEY returned NULL\n"); return 0;}
    
    // create the signature context:
    md_ctx = EVP_MD_CTX_new();
    if(md_ctx==NULL){printf("Error: EVP_MD_CTX_new returned NULL\n"); return 0;}
    
    ret_val = EVP_VerifyInit(md_ctx, EVP_sha256());
    if(ret_val == 0){printf("Error: EVP_VerifyInit returned NULL\n"); return 0;}
    ret_val = EVP_VerifyUpdate(md_ctx, friend_authentication_str, 490);  
    if(ret_val == 0){printf("Error: EVP_VerifyUpdate returned NULL\n"); return 0;}
    ret_val = EVP_VerifyFinal(md_ctx, friend_signature, 256, friend_pubkey);
    if(ret_val==1)
        printf("Friend Authenticated! \n");
    else{printf("Friend Authentication FAILED (%d)\n", ret_val); return 0;}
    /** END AUTHENTICATE FRIEND BY PUBKEY */
    
    RAND_poll();
    RAND_bytes(rand_val, 32);
    hash_256_bits(rand_val, 32, chat_session_key);
    //RAND_poll();
    //RAND_bytes(chat_iv, 12);
    
    /** BEGIN ENCRYPT CHAT SESSION KEY BY TEMPORARY PUBKEY */
    EVP_PKEY* TempPubkey = EVP_PKEY_new();
    RSA *temp_rsa = NULL;
    BIO* pb_TempPubkey = BIO_new_mem_buf((void*) TempPubkey_txt, TempPubkey_txt_len);
    if (pb_TempPubkey==NULL){printf("BIO_new_mem_buf returned NULL\n");}
    printf("TEMP PUBKEY (%d): %s\n",TempPubkey_txt_len, TempPubkey_txt);
    temp_rsa = PEM_read_bio_RSAPublicKey(pb_TempPubkey, &temp_rsa, NULL, NULL);
    if (temp_rsa == NULL) {printf("PEM_read_bio_RSAPublicKey returned NULL\n"); return 0;}
    
    EVP_PKEY_assign_RSA(TempPubkey, temp_rsa); // set TempPubkey to correct format
    
    unsigned char *enc_k; // encrypted Session Key 'K' with Temporary Public Key
    size_t outlen;
    
    EVP_PKEY_CTX* ctx_p = EVP_PKEY_CTX_new(TempPubkey, NULL);
    if (ctx_p==NULL){printf("Error: EVP_PKEY_CTX_new returned NULL\n"); return 0;}
    ret_val = EVP_PKEY_encrypt_init(ctx_p);
    if(ret_val <= 0){printf("Error: EVP_PKEY_encrypt_init\n"); return 0;}
    ret_val = EVP_PKEY_CTX_set_rsa_padding(ctx_p, RSA_PKCS1_OAEP_PADDING);
    if(ret_val <= 0){printf("Error: EVP_PKEY_CTX_set_rsa_padding\n"); return 0;}
    // Determine buffer size for encrypted length
    if (EVP_PKEY_encrypt(ctx_p, NULL, &outlen, chat_session_key, 32) <= 0)
    {printf("Error: EVP_PKEY_encrypt\n"); return 0;}
    printf("encrypted key length (%ld)",outlen);
    enc_k = OPENSSL_malloc(outlen);
    if (enc_k==NULL){printf("Malloc failed for username encryption\n"); return 0;}

    ret_val = EVP_PKEY_encrypt(ctx_p, enc_k, &outlen, chat_session_key, 32);
    if (ret_val<=0){printf("ENCRYPTION Error: EVP_PKEY_encrypt\n"); return 0;}
        
    EVP_PKEY_CTX_free(ctx_p);
    EVP_PKEY_free(TempPubkey);
    
    /** sign R2 + encrypted session key using privkey */
    char *sign_buff = malloc(32+outlen);
    if (sign_buff==NULL){printf("Malloc failed for username encryption\n"); return 0;}
    for (int i=0;i<32;i++){sign_buff[i]=chat_nonce_R2[i];}
    printf("encrypted key length (%ld)",outlen);
    for (int i=0;i<outlen;i++){sign_buff[i+32]=enc_k[i];}
    
    md_ctx = EVP_MD_CTX_new();
    if(md_ctx==NULL){printf("Error: EVP_MD_CTX_new returned NULL\n"); return 0;}
    
    unsigned char* signature = (unsigned char*)malloc(EVP_PKEY_size(privkey));
    if(signature==NULL) {printf("Error: malloc returned NULL\n"); return 0;}
    
    ret_val = EVP_SignInit(md_ctx, EVP_sha256());
    if(ret_val == 0){printf("Error: EVP_SignInit returned %d\n",ret_val); return 0;}
    ret_val = EVP_SignUpdate(md_ctx, sign_buff, 32+outlen);
    if(ret_val == 0){printf("Error: EVP_SignUpdate returned %d\n",ret_val); return 0;}
    unsigned int sign_size;
    ret_val = EVP_SignFinal(md_ctx, signature, &sign_size, privkey); // return the signed message
    if(ret_val == 0){printf("Error: EVP_SignFinal returned %d\n",ret_val); return 0;}

    EVP_MD_CTX_free(md_ctx);
    //EVP_PKEY_free(privkey);
    printf("signature length (%d)",sign_size);
    for(int i=0;i<4;i++){buff[i]=cmd_frwd[i];} // add protcol cmd
    for (int i=0;i<sign_size;i++) {buff[i+4] = signature[i];}
    //for (int i=0;i<12;i++) {buff[i+4+256] = chat_iv[i];}
    for (int i=0;i<outlen;i++) {buff[i+4+sign_size] = enc_k[i];}


    /** SEND Encrypted Key and signature */
    server_secure_send(sockfd, session_key, buff, 4+256+outlen); // must add "frwd" cmd before string
    printf("\nSent Signature to friend (%ld)\n", 4+256+outlen);
    
    printf("\nCHAT SESSION KEY: ");
    for (int k=0;k<32;k++){
        printf("%02x ", chat_session_key[k]);
    }
    for (int i=0;i<16;i++){chat_counter_myself_to_friend[i] = '\0';}
    for (int i=0;i<16;i++){chat_counter_friend_to_myself[i] = '\0';}
    
    // receive confirmation message
    msg_len = server_secure_receive(sockfd, session_key, buff);
    if (msg_len<4){return 0;}
    char clear_txt[500];
    unsigned char *msg = malloc(msg_len-4); // not considering the cmd sent
    for (int i=0;i<msg_len-4;i++){msg[i] = buff[i+4];};
    
    chat_decrypt(clear_txt, msg, msg_len-4);
    printf("\nFrom <%s>: %s\n", friendname, clear_txt);
    printf("\nFriend Key Exchange Completed\n");
    return 1;
}


int friend_wait_negotiation()
{
    unsigned char rand_val[32];
    unsigned char chat_nonce_R1[32];
    unsigned char chat_nonce_R2[32];
    EVP_MD_CTX* md_ctx;
    char buff[MAX_BUFF];
    int msg_len;
    int ret_val;
    char *cmd_frwd = "frwd";
    
    /** RECEIVE R1 */
    printf("Waiting for Caller Negotiation...\n");
    msg_len = server_secure_receive(sockfd, session_key, buff);
    printf("Received R1(%d)\n", msg_len);
    char rec_cmd[4];
    for (int i=0;i<4;i++){rec_cmd[i] = buff[i];}
    if (strncmp(cmd_frwd, rec_cmd, 4)!=0){printf("Message Command ERROR\n"); return 0;}
    for (int i=0;i<32;i++){chat_nonce_R1[i] = buff[i+4];}
    
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
    printf("Generated TEMP PUBKEY (%d): %s\n",TempPubkey_txt_len, TempPubkey_txt);    
    /** END GENERATE TEMPORARY RSA 2048 KEY PAIR **/
    
    /** BEGIN GENERATE SIGNATURE FOR  R1 + TEMP PUBKEY + R2 **/
    RAND_poll();
    RAND_bytes(rand_val, 32);
    hash_256_bits(rand_val, 32, chat_nonce_R2);
    
    char nonce_buff[TempPubkey_txt_len+64]; // R1 + TEMP PUBKEY + R2
    for (int i=0;i<32;i++){nonce_buff[i] = chat_nonce_R1[i];}
    for (int i=0;i<TempPubkey_txt_len;i++){nonce_buff[i+32] = TempPubkey_txt[i];}
    for (int i=0;i<32;i++){nonce_buff[i+TempPubkey_txt_len+32] = chat_nonce_R2[i];}
    
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
    
    EVP_MD_CTX_free(md_ctx);
    //EVP_PKEY_free(privkey);
    /** END GENERATE SIGNATURE FOR  R1 + TEMP PUBKEY + R2 **/
    
    // build message TempPubk + R2 + {R1+TempPubk+R2}signed
    for(int i=0;i<4;i++){buff[i]=cmd_frwd[i];} // add protcol cmd
    for (int i=0;i<TempPubkey_txt_len;i++){buff[i+4] = TempPubkey_txt[i];}
    for (int i=0;i<32;i++){buff[i+4+TempPubkey_txt_len] = chat_nonce_R2[i];}
    for (int i=0;i<256;i++){buff[i+4+TempPubkey_txt_len+32] = sgnt_buff[i];}

    server_secure_send(sockfd, session_key, buff, 4+TempPubkey_txt_len+32+sgnt_size);
    printf("Sent Signature\n");
    
    /** RECEIVE Friend signature + Enc(K) */
    msg_len = server_secure_receive(sockfd, session_key, buff);
    printf("Received Friend Signature(%d)\n", msg_len);
    for (int i=0;i<4;i++){rec_cmd[i] = buff[i];}
    if (strncmp(cmd_frwd, rec_cmd, 4)!=0){printf("Sign Message Command ERROR\n"); return 0;}
    
    unsigned char friend_signature[256];
    int enc_k_len = msg_len-4-256;
    unsigned char * enc_k = malloc(enc_k_len);
    unsigned char * cmp_buff = malloc(enc_k_len+32);
    for (int i=0;i<32;i++){cmp_buff[i] = chat_nonce_R2[i];}
    for (int i=0;i<256;i++){friend_signature[i] = buff[i+4];}
    for (int i=0;i<enc_k_len;i++){enc_k[i] = buff[i+4+256]; cmp_buff[i+32] = buff[i+4+256];}
    
    /** BEGIN AUTHENTICATE FRIEND BY PUBKEY **/
    FILE* clientpubkey_file = fopen("friendPubkey.pem", "r");
    if(clientpubkey_file==NULL){printf("Fail to Open Frien Pubkey\n"); return 0;}
    
    EVP_PKEY* friend_pubkey = PEM_read_PUBKEY(clientpubkey_file, NULL, NULL, NULL);
    fclose(clientpubkey_file);
    if(friend_pubkey==NULL){printf("Error: PEM_read_PUBKEY returned NULL\n"); return 0;}
    
    // create the signature context:
    md_ctx = EVP_MD_CTX_new();
    if(md_ctx==NULL){printf("Error: EVP_MD_CTX_new returned NULL\n"); return 0;}
    
    ret_val = EVP_VerifyInit(md_ctx, EVP_sha256());
    if(ret_val == 0){printf("Error: EVP_VerifyInit returned NULL\n"); return 0;}
    ret_val = EVP_VerifyUpdate(md_ctx, cmp_buff, 32+enc_k_len);  
    if(ret_val == 0){printf("Error: EVP_VerifyUpdate returned NULL\n"); return 0;}
    ret_val = EVP_VerifyFinal(md_ctx, friend_signature, 256, friend_pubkey);
    if(ret_val==1)
        printf("Friend Authenticated!\n");
    else{printf("Friend Authentication FAILED (%d)\n", ret_val); return 0;}
        
    EVP_PKEY_free(friend_pubkey);
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
    
    //for (int i=0;i<12;i++){chat_iv[i] = buff[i+4+256];}
    for (int i=0;i<32;i++){chat_session_key[i] = secret[i];}
    printf("\nCHAT SESSION KEY: ");
    for (int k=0;k<32;k++){
        printf("%02x ", chat_session_key[k]);
    }
    
    for (int i=0;i<16;i++){chat_counter_myself_to_friend[i] = '\0';}
    for (int i=0;i<16;i++){chat_counter_friend_to_myself[i] = '\0';}
    
    free(secret);
    free(enc_k);
    free(cmp_buff);
    char enc_buff[500];
    int enc_len = chat_encrypt(enc_buff, "CHAT IS SECURE!", 15);
    for (int i=0;i<4;i++){buff[i] = cmd_frwd[i];}
    for (int i=0;i<enc_len;i++){buff[i+4] = enc_buff[i];}
    
    server_secure_send(sockfd, session_key, buff, 4+enc_len);
    printf("\nFriend Key Exchange Completed\n");
    return 1;
    
}



int chat_encrypt(char* encrypted_txt, char* in ,int inlen)
{
    unsigned char out[MAX_BUFF];
    unsigned char *auth_string = "MessageAppV1";
    unsigned char aad[28];
    unsigned char tag[16];
    unsigned char iv[12];
    int carry = 0;
    
    for (int i=0;i<12;i++){aad[i] = auth_string[i];}
    for (int i=0;i<16;i++){aad[i+12] = chat_counter_myself_to_friend[i];}
    for (int i=0;i<12;i++){iv[i] = chat_counter_myself_to_friend[i];}
    // increment 16 byte counter
    chat_counter_myself_to_friend[0] = chat_counter_myself_to_friend[0]+1; 
    if (chat_counter_myself_to_friend[0]==0){carry=1;}
    for (int n=0;n<15;n++){    
        if (chat_counter_myself_to_friend[n]==0 && carry==1){
            chat_counter_myself_to_friend[n+1] = chat_counter_myself_to_friend[n+1]+1;
            if (chat_counter_myself_to_friend[n+1]==0)
                carry=1;
            else
                carry=0;
        }
    }

    int outlen = EncryptAES_256_GCM(out, in, inlen, aad, 28, iv, chat_session_key, tag);    
    if (outlen<=0){printf("Error: Chat EncryptAES_256_GCM\n"); return 0;}
    
    for (int v=0;v<28;v++)
        encrypted_txt[v] = aad[v];
    for (int v=0;v<16;v++)
        encrypted_txt[v+28] = tag[v];
    for (int v=0;v<outlen;v++)
        encrypted_txt[v+44] = out[v];
    
    return (outlen+12+16+16);
}

    
int chat_decrypt(char* clear_txt, char* in, int inlen)
{
    unsigned char *auth_string = "MessageAppV1";
    unsigned char rec_str[12];
    unsigned char rec_counter[16];
    unsigned char rec_aad[28];
    unsigned char rec_tag[16];
    unsigned char iv[12];
    unsigned char* encrypted_data;
    int carry = 0;
    
    if ((inlen>44)&&(inlen<MAX_BUFF))
    {
        encrypted_data = malloc(inlen-44);
        for(int i=0;i<12;i++){rec_str[i] = in[i];}
        for(int i=0;i<16;i++){rec_counter[i] = in[i+12];}
        for(int i=0;i<12;i++){iv[i] = rec_counter[i];}
        for(int i=0;i<28;i++){rec_aad[i] = in[i];}
        for(int i=0;i<16;i++){rec_tag[i] = in[i+28];}
        for(int i=0;i<inlen-44;i++){encrypted_data[i]=in[i+44];}            
    }
    else {return 0;}

    if(strncmp(auth_string, rec_str, 12)!=0){printf("\nAES Decryption Chat FAILED - wrong AAD\n"); return 0;}
    if(strncmp(chat_counter_friend_to_myself, rec_counter, 16)!=0){printf("\nAES Decryption Chat FAILED - wrong counter value\n"); return 0;}
    
    // increment 16 byte counter
    chat_counter_friend_to_myself[0] = chat_counter_friend_to_myself[0]+1; 
    if (chat_counter_friend_to_myself[0]==0){carry=1;}
    for (int n=0;n<15;n++){    
        if (chat_counter_friend_to_myself[n]==0 && carry==1){
            chat_counter_friend_to_myself[n+1] = chat_counter_friend_to_myself[n+1]+1;
            if (chat_counter_friend_to_myself[n+1]==0)
                carry=1;
            else
                carry=0;
        }
    }
    
    unsigned char decrypt_buff[MAX_BUFF];
    int clear_len = DecryptAES_256_GCM(decrypt_buff, encrypted_data, inlen-44, rec_aad, 28, iv, chat_session_key, rec_tag);
    if (clear_len<0){printf("Chat AES DECRYPTION FAILED\n"); return 0;}

    for (int i=0;i<clear_len;i++)
        clear_txt[i] = decrypt_buff[i];
    
    return clear_len;    
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
    char ipt_cmd_chat[5];
    char enc_buff[MAX_BUFF];
    int outlen;
    
        
    for (;;) {
            
        //pthread_mutex_lock(&mutex_print);
        if (chat_with_friend_flag == 0){printf("\nMessasgeApp[SERVER-COMMAND]->\n");}
        else if (chat_with_friend_flag == 1){printf("\nMessasgeApp[CHAT]->\n");}
         // send command to server
        
        fgets(sbuff, MAX_BUFF, stdin);
        
        if ((strlen(sbuff) > 0) && (sbuff[strlen (sbuff) - 1] == '\n'))
            sbuff[strlen (sbuff) - 1] = '\0';
        
        if ((chat_with_friend_flag == 0)&&(acpt_flag==0))
        {            
            for(int i=0;i<4;i++){ipt_cmd[i] = sbuff[i];}
            if(strncmp(ipt_cmd, cmd_chat, 4)==0){
                caller=1;
                for (int i=0;i<strlen(sbuff)-4;i++){friendname[i] = sbuff[i+4];}
            } // lock until response
            
            if (strlen(sbuff)>0){
                server_secure_send(sockfd, session_key, sbuff, strlen(sbuff));}
            
        }
        else if (acpt_flag == 1){
            for(int i=0;i<5;i++){ipt_cmd_chat[i] = sbuff[i];}
            if((strncmp(ipt_cmd_chat, "acptx", 5)==0)||(strncmp(ipt_cmd_chat, "refux", 5)==0)){
                acpt_flag = 0; 
                for (int i=0;i<strlen(friendname);i++){sbuff[i+4]=friendname[i];}
                server_secure_send(sockfd, session_key, sbuff, 4+strlen(friendname));
            }
            else {printf("\nInput Error - Chat still Holding...\n");}
        
        }
        else if (chat_with_friend_flag == 1)
        {
            for(int i=0;i<5;i++){ipt_cmd_chat[i] = sbuff[i];}
            if(strncmp(ipt_cmd_chat, "/exit", 5)==0){
                chat_with_friend_flag = 0; //exit chat
                caller = 0;
                for(int i=0;i<16;i++){friendname[i] = '\0';}
                server_secure_send(sockfd, session_key, "exchx", 5);
                //close(sockfd); exit(0);
            }
            else if (strlen(sbuff)>0){
                outlen = chat_encrypt(enc_buff, sbuff , strlen(sbuff));
            
                for(int i=0;i<4;i++){friend_sbuff[i] = cmd_frwd[i];}
                for(int i=0;i<outlen;i++){friend_sbuff[i+4] = enc_buff[i];}
            
                // printf("Send to Server: (%d)\n", outlen+4);
                server_secure_send(sockfd, session_key, friend_sbuff, outlen+4);
            }
            
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
    char decrypt[MAX_BUFF];
    int dec_size;
    char rec_cmd[4];
    unsigned char buff[MAX_BUFF];
    char friend_name[16];
    char clear_txt[MAX_BUFF];
    int clear_len;
    unsigned char friend_pubkey_txt[451];
    int ret_val;
    FILE *f;
    char ipt_cmd_chat[5];
    char sbuff[MAX_BUFF];
    
    for (;;) {
        
        //printf("\nclient waiting...");
        
        msg_len = server_secure_receive(sockfd, session_key, buff);
        //pthread_mutex_lock(&mutex_print);
        //printf("From Server (%d)\n",msg_len);
        for (int i=0;i<MAX_BUFF;i++){data[i]='\0';} // clear data buffer
        if (msg_len > 4){
            for (int i=0;i<4;i++){rec_cmd[i]=buff[i];} // Save received COMMAND
            for (int i=0;i<msg_len-4;i++){data[i]=buff[i+4];} // Save received DATA
            if(strncmp(rec_cmd, "reqt", 4)==0){ //received a request
                if (caller==1){
                    printf("\nMessageApp: <%s>\n", data);
                }
                else{
                    for(int i=0;i<16;i++){friendname[i] = '\0';}
                    for(int i=0;i<msg_len-4;i++){friendname[i] = data[i];}
                    printf("\nMessageApp - REQUEST TO CHAT FROM: <%s> ACCEPT?\n", friendname);
                    acpt_flag = 1;
                }
            }
            else if (strncmp(rec_cmd, "pubk", 4)==0){
                if (caller==1){
                    printf("\nMessageApp Caller- Chat Accepted!\n");
                    // friend_pubkey_txt = malloc(msg_len-4);
                    for(int k=0;k<msg_len-4;k++){friend_pubkey_txt[k] = data[k];}
                        f = fopen ("friendPubkey.pem", "w");
                        if (f != NULL) {
                            if (fputs (friend_pubkey_txt, f) == EOF) {printf("\n\Error writing Pubkey\n");}
                            fclose (f); 
                        }
                    printf("\nFirend Pubk(%ld): %s \n", strlen(friend_pubkey_txt), friend_pubkey_txt); 
                    printf("Caller Handshake Begin\n");
                    ret_val = friend_begin_negotiation(); // saves the chat session key
                    if (ret_val>0)
                        chat_with_friend_flag = 1;
                    else {printf("\nChat Key exchange failed"); }
                }
                else{                    
                    printf("\nMessageApp Receiver- Chat Accepted!\n"); 
                    // friend_pubkey_txt = malloc(msg_len-4);
                    for(int k=0;k<msg_len-4;k++){friend_pubkey_txt[k] = data[k];}
                    f = fopen ("friendPubkey.pem", "w");
                    if (f != NULL) {
                        if (fputs (friend_pubkey_txt, f) == EOF) {printf("\n\Error writing Pubkey\n");}
                        fclose (f); 
                    }
                    printf("\nFirend Pubk(%ld): %s \n", strlen(friend_pubkey_txt), friend_pubkey_txt); 
                    printf("Receiver Handshake Waiting...\n");
                    ret_val = friend_wait_negotiation(); // saves the chat session key
                    if (ret_val>0)
                        chat_with_friend_flag = 1;
                    else {printf("\nChat Key exchange failed"); }
                }
            }
            else if ((strncmp(rec_cmd, "frwd", 4)==0)&&(chat_with_friend_flag == 1)){
                clear_len = chat_decrypt(clear_txt, data, msg_len-4);                
                printf("\nMessasgeApp[CHAT]<%s>: %s\n", friendname, clear_txt);
                for (int i=0;i< clear_len;i++){clear_txt[i]='\0';}
            }
            else if (strncmp(rec_cmd, "refu", 4)==0){
                printf("\nMessageApp - Chat REFUSED by <%s>\n", data);
                caller = 0;
            }
            else if (strncmp(rec_cmd, "list", 4)==0){
                printf("\nMessageApp - ONLINE USERS:\n%s", data);
                //printf("\nSERVER[cmd][param]->");
            }
            else if (strncmp(rec_cmd, "erro", 4)==0){
                printf("\nMessageApp: %s\n", data);
                caller = 0;
                acpt_flag = 0;
                chat_with_friend_flag = 0;
                //printf("\nSERVER[cmd][param]->");
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
    unsigned char tcp_msg[50]={0};
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
    int msg_size = read(sockfd, tcp_msg, 50);
    if (msg_size>0){printf("%s\n", tcp_msg);}
    
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
