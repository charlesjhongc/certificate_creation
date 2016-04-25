#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

#define KEY_LENGTH      4096
#define PUB_EXP         3
#define BUF_SIZE        4069
#define SESSIONKEY_LENG 16
#define min(a,b) (((a) < (b)) ? (a) : (b))

#define DEBUG

void printHex(unsigned char *stream, int length);
int recvMsg(int sockfd, unsigned char* buffer);

int generateNonce(char **output) {
    srand(time(NULL));
    int current_time = time(NULL);
    int random_value = rand();
    int key;
    memcpy(&key, "dsns", 4);
#ifdef DEBUG
    printf("[DEBUG] time: %x, random: %x\n", current_time, random_value);
#endif
    int xor_result = current_time ^ random_value ^ key;
    char xor_output[8];
    memcpy(xor_output, &random_value, 4);
    memcpy(xor_output+4, &xor_result, 4);

    BIO *bio, *b64;
    FILE* stream;
    int encodedSize = 12;
    *output = (char *) malloc(encodedSize+1);

    stream = fmemopen(*output, encodedSize+1, "w");
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_fp(stream, BIO_NOCLOSE);
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, xor_output, 8);
    BIO_flush(bio);
    BIO_free_all(bio);
    fclose(stream);

    (*output)[12] = '\0';

    return 0;
}

// Receive message through clientfd as RSA public key and return the RSA instance
// Please DO remember to free the RSA instance
RSA* recvPublicKey(int clientfd){
    unsigned char buffer[BUF_SIZE];
    int size = recvMsg(clientfd,buffer);
    RSA* public_key = RSA_new();
    public_key->n = BN_bin2bn(buffer, size, NULL);
#ifdef DEBUG
    printf("[recvPublicKey] get n size %d\n", size);
    printHex(buffer, size);
#endif

    size = recvMsg(clientfd,buffer);
    public_key->e = BN_bin2bn(buffer, size, NULL);  
#ifdef DEBUG
    printf("[recvPublicKey] get e size %d\n", size);
    printHex(buffer, size);
#endif
    return public_key;
}

void printHex(unsigned char *stream, int length){
    for(int i=0;i<length;i++)
    {
        printf("%x ", stream[i]);
        if(i%16 == 15)printf("\n");
    }
    printf("\n");
}

// Send message through clientfd and automatically append size in front of the message
int sendMsg(int clientfd, int size, unsigned char* msg)
{
    unsigned char buffer[BUF_SIZE];
    memcpy(buffer, &size, sizeof(int));
    memcpy(buffer+sizeof(int), msg, min(size, BUF_SIZE-sizeof(int)));
    send(clientfd, buffer, size+sizeof(int), 0);
#ifdef DEBUG
    printf("[sendMsg]\n");
    printHex(buffer, size+sizeof(int));
#endif
}

// Receive message through sockfd and automatically remove size in front of the message
int recvMsg(int sockfd,unsigned char* buffer)
{
    int size;
    recv(sockfd, (char*)&size, sizeof(int), 0);
    recv(sockfd, buffer, size, 0);
    return size; 
}

// Generate session key with random bytes
int generateSessionKey(unsigned char* sessionKey)
{
#ifdef DEBUG
    printf("Session Key %d\n", sizeof(sessionKey));
#endif
    RAND_bytes(sessionKey, sizeof(sessionKey));
#ifdef DEBUG
    printHex(sessionKey, SESSIONKEY_LENG);
#endif
}

// Encrypt the msg with sessionKey, and send it through sockfd by sendMsg()
int sendEncryptMsg(int sockfd, char* msg, unsigned char* sessionKey)
{
    unsigned char ebuffer[BUF_SIZE];
    AES_KEY aes;
    AES_set_encrypt_key(sessionKey, 128, &aes);
    int len = 0;
    if ((strlen(msg) + 1) % AES_BLOCK_SIZE == 0) {
        len = strlen(msg) + 1;
    } else {
        len = ((strlen(msg) + 1) / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
    }
    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0x00, AES_BLOCK_SIZE);
    AES_cbc_encrypt((unsigned char*)msg , ebuffer, len , &aes, iv, AES_ENCRYPT);
    sendMsg(sockfd, len, ebuffer);
}

// Recv the message through sockfd by recvMsg(), decrypt msg with sessionKey and store at buffer
int recvDecyptMsg(int sockfd, unsigned char* sessionKey, unsigned char* buffer)
{
    unsigned char ebuffer[ BUF_SIZE ];
    AES_KEY aes;
    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0x00, AES_BLOCK_SIZE);
    int len = recvMsg(sockfd, ebuffer);
    AES_set_decrypt_key(sessionKey , 128, &aes);
    AES_cbc_encrypt(ebuffer, buffer, len , &aes, iv, AES_DECRYPT);
#ifdef DEBUG
    printf("[recvDecyptMsg] %s\n", buffer);
#endif
}

// Encrypt the sessionKey with RSA publicKey, and send it through sockfd by sendMsg()
int sendRSAMsg(int sockfd, int len, unsigned char* sessionKey, RSA* publicKey)
{
    unsigned char ebuffer[ BUF_SIZE ];
    memset(ebuffer, 0x00, BUF_SIZE );
    int encryptSize = RSA_public_encrypt( len ,sessionKey , ebuffer , publicKey , RSA_PKCS1_OAEP_PADDING);  
    sendMsg(sockfd, encryptSize , ebuffer);
}

int main(int argc, char *argv[])
{
    char client_cert_pathname[] = "./server.crt";
    char server_cert_pathname[] = "./rootca.crt";

    // Deal with command line input argument
    if (argc < 3) {
        fprintf(stderr, "usage %s hostname port\n", argv[0]);
        exit(0);
    }
    int port = atoi(argv[2]);
    char *ip = argv[1];

    // Connect to server
    int sockfd;
    struct sockaddr_in dest;
    unsigned char sessionKey[SESSIONKEY_LENG];

    /* create socket */
    sockfd = socket(PF_INET, SOCK_STREAM, 0);

    /* initialize value in dest */
    bzero(&dest, sizeof(dest));
    dest.sin_family = PF_INET;
    dest.sin_port = htons(port);
    inet_aton(ip, &dest.sin_addr);

    /* Connecting to server */
    connect(sockfd, (struct sockaddr*)&dest, sizeof(dest));

    /* Step 1: Send "hello" to Server */
    char* hello = (char*)"hello";
    sendMsg(sockfd, strlen(hello)+1, (unsigned char*)hello);
    char hello_ack[BUF_SIZE];
    recvMsg(sockfd, (unsigned char*)hello_ack);
    printf("[recvMsg] %s\n", hello_ack);

    /* Step 2: Send certificate to Server */
    FILE *cert_fp = fopen(client_cert_pathname, "r");
    fseek(cert_fp, 0, SEEK_END);
    int cert_size = ftell(cert_fp);
    fseek(cert_fp, 0, SEEK_SET);
    char *cert_buf = new char[cert_size];
    fread(cert_buf, 1, cert_size, cert_fp);
    sendMsg(sockfd, cert_size, (unsigned char*)cert_buf);
    char login_ack[BUF_SIZE];
    recvMsg(sockfd, (unsigned char*)login_ack);
    printf("[recvMsg] %s\n", login_ack);

    /* Step 3: Get RSA public key from server's certificate */
    FILE *root_cert_fp = fopen(server_cert_pathname, "r");
    X509 *root_cert;
    EVP_PKEY *root_pubkey;
    root_cert = PEM_read_X509(root_cert_fp, &root_cert, NULL, NULL);
    root_pubkey = X509_get_pubkey(root_cert);
    RSA *publicKey = EVP_PKEY_get1_RSA(root_pubkey);

    /* Step 4: Generate & send session key encrypted by RSA public key */
    generateSessionKey(sessionKey);
    sendRSAMsg(sockfd, SESSIONKEY_LENG , sessionKey, publicKey);

    /* Step 5: Send Secret message encrypted by AES key */
    char* auth = (char*)"0356539 pass the NetSec test!!";
    char auth2[256];
    strcpy(auth2, auth);
    char *nonce;
    generateNonce(&nonce);
    strcat(auth2, nonce);
    sendEncryptMsg(sockfd, auth2, sessionKey);

    /* Step 6: Receive ACK msg */
    unsigned char ack_msg[BUF_SIZE];
    recvDecyptMsg(sockfd, sessionKey, ack_msg);
    printf("[ACK msg] %s\n", ack_msg);

    /* Step 7: Receive bye msg */
    unsigned char bye_msg[BUF_SIZE];
    recvDecyptMsg(sockfd, sessionKey, bye_msg);
    printf("[BYE msg] %s\n", bye_msg);
    
    /* Step 8: Close connection & clean up */
    close(sockfd);

    free(nonce);
    RSA_free(publicKey);

    return 0;
}

