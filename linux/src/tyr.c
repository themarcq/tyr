#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <pwd.h>
#include <sys/stat.h>
#include <pthread.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/sha.h>
#include <qrencode.h>
#include <png.h>
#include <libnotify/notify.h>

#define abort() exit(EXIT_FAILURE)
#define ll long long int
#define INCHES_PER_METER (100.0/2.54)

typedef struct packet_t {
    char type;
    char error;
    uint32_t length;
    unsigned char buf[1000];
} packet;

//main functions
void parse_args(int argc, char ** argv);
void load_keys();
void receive_packets();
void * send_id(void *ptr);
void show_help();
//reply functions
unsigned char* convert_packet_to_byte(packet* pkt);
packet* convert_byte_to_packet(unsigned char* byte);
void login_reply(packet * pkt);
void punch(packet * pkt);
void show_notification(packet * pkt);
void pong(struct sockaddr_in * sender_addr, packet *pkt);
char * join_char_arrays(char *a, char *b);
int  generate_qrcode();
int write_PNG(QRcode *qrcode, char *outfile);
int base64_encode(char *encoded, const char *string, int len);
int base64_encode_len(int len);

int     force_new_keys = 0;
struct  sockaddr_in self_addr;
struct  sockaddr_in serv_addr;
int     sock;
RSA   * rsa_pub;
RSA   * rsa_priv;
char  * server_address = "192.168.1.3";
int     server_port = 1222;
int     id;
int     padding = RSA_PKCS1_PADDING;
//int     padding = RSA_NO_PADDING;
pthread_mutex_t stdout_lock;

int main(int argc, char **argv)
{
    parse_args(argc, argv);
    load_keys();

    sock = socket(AF_INET, SOCK_DGRAM, 0);   
    if (sock < 0) {
        fprintf(stderr, "Can't create socket!\n");
        abort();
    }
    
    memset(&self_addr, 0, sizeof(self_addr));
    self_addr.sin_family = AF_INET;
    self_addr.sin_port = htons(7462);
    self_addr.sin_addr.s_addr = htonl(INADDR_ANY);  
    serv_addr.sin_family = AF_INET;
    
    if (inet_aton(server_address, &serv_addr.sin_addr) == 0) {
        fprintf(stderr, "can't parse tracker ip.\n");
        abort();
    }
    
    serv_addr.sin_port=htons(server_port);

    if (bind(sock, (struct sockaddr *)&self_addr, sizeof(self_addr))) {
        fprintf(stderr, "cant bind\n");
        abort();
    }
    
    pthread_t send_id_thread;
    pthread_create(&send_id_thread, NULL, send_id, NULL);
    pthread_detach(send_id_thread);

    if (!generate_qrcode()) {
            pthread_mutex_lock(&stdout_lock);
            fprintf(stderr, "Could not generate qrcode\n");
            pthread_mutex_unlock(&stdout_lock); 
    }

    receive_packets();
}

void parse_args(int argc, char ** argv)
{
    int opt;
    for(;;) {
        int option_index = 0;
        static struct option long_options[] = {
            {"force-key-change",    no_argument,        0,  'f'},
            {"server-address",      required_argument,  0,  'a'},
            {"server-port",         required_argument,  0,  'p'}
        };
        int c = getopt_long(argc, argv, "fa:p:"/*pun not intended*/,
                long_options, &option_index);
        if (c == -1)
            break;

        switch(c) {
            case 'f':
                force_new_keys = 1;
                break;
            case 'a':
                server_address = optarg;
                break;
            case 'p':
                opt = atoi(optarg);
                if ((opt < 1) || (opt > 7000)) {
                    fprintf(stderr, "Port number to large or to small\n");
                    abort();
                }
                server_port = opt;
                break;
        }
        
    }
    if (optind < argc) {
        fprintf(stderr, "Unknow option: %d %d %s\n", optind, argc, argv[optind]);
        show_help();
    }
}

void show_help()
{
    printf("\
Usage: tyr [OPTIONS]...\n\
\n\
    -f, --force-new-keys    Force cretion of new pair of keys\n\
    -a, --server-address    specify server address\n\
    -p, --server-port       specify server port\n");
abort();
}

void receive_packets()
{
    struct sockaddr_in sender_addr;
    socklen_t addrlen = 10;
    unsigned char* buf = malloc(1024);
    int status;
    for(;;){
        status = recvfrom(sock, buf, 1024, 0, (struct sockaddr *)&sender_addr, &addrlen);
        packet* pkt = convert_byte_to_packet(buf);
        if(status == -1){
            pthread_mutex_lock(&stdout_lock);
            fprintf(stderr, "error receiving a pktet\n");
            pthread_mutex_unlock(&stdout_lock);
        }
        
        switch (pkt->type) {
            case 'i':
                login_reply(pkt);
                break;
            case 'n':
                show_notification(pkt);
                break;
            case 'p':
                pong(&sender_addr, pkt);
                break;
            case 'u':
                punch(pkt);
                break;
            default:
                pthread_mutex_lock(&stdout_lock);
                fprintf(stderr, "Unknow pktet type received\n");
                pthread_mutex_unlock(&stdout_lock);
                break;
        }
    }
}

void load_keys() 
{
    struct passwd *pw      = NULL;//getpwuid(getuid());
    char *confdir          = "/home/jeremy/.tyr/";//join_char_arrays(pw->pw_dir, "/.tyr/");
    char *rsa_pub_keyfile  = "/home/jeremy/.tyr/rsa_pub";//join_char_arrays(confdir, "rsa_pub");
    char *rsa_priv_keyfile = "/home/jeremy/.tyr/rsa_priv";//join_char_arrays(confdir, "rsa_priv");
    struct stat info;
    if (stat( confdir, &info ) != 0) {
        mkdir(confdir, S_IRWXU | S_IRGRP);
        if (stat(confdir, &info) !=0) {
            fprintf(stderr, "error creating a config directory %s\n",confdir);
            abort();
        }
    } else if(!(info.st_mode & S_IFDIR)) {
        fprintf(stderr, "%s is no directory\n", confdir);
        abort();
    }
    
    FILE * rsa_pub_key_p = fopen(rsa_pub_keyfile,"rb");
    FILE * rsa_priv_key_p = fopen(rsa_priv_keyfile,"rb");


    if(force_new_keys || !rsa_pub_key_p || !rsa_priv_key_p) {
        if(force_new_keys) {
            fprintf(stderr, "Forced to create new keys\n");
        } else {
            fprintf(stderr, "Keys not found, creating new ones\n");
        }
        if(rsa_pub_key_p)
            fclose(rsa_pub_key_p);
        if(rsa_priv_key_p)
            fclose(rsa_priv_key_p);
        rsa_pub_key_p = fopen(rsa_pub_keyfile, "w");
        rsa_priv_key_p = fopen(rsa_priv_keyfile, "w");

        int status;
        BIGNUM * big_number = BN_new();

        status = BN_set_word(big_number, RSA_F4);
        if(status!=1){
           fprintf(stderr, "Can't generate big number\n");
           abort();
        }

        RSA * rsa_keys = RSA_new();
        status = RSA_generate_key_ex(rsa_keys, 1024, big_number, NULL);
        if(status!=1){
            fprintf(stderr, "CAn't generate rsa keys\n");
            abort();
        }

        status = PEM_write_RSAPublicKey(rsa_pub_key_p, rsa_keys);
        if(status!=1){
            fprintf(stderr, "Can't write to a file %s\n", rsa_pub_keyfile);
            abort();
        }
    
        status = PEM_write_RSAPrivateKey(rsa_priv_key_p, rsa_keys, NULL, NULL, 0, NULL, NULL);
        if(status==0){
            fprintf(stderr, "Can't write to a file %s\n", rsa_priv_keyfile);
            abort();
        } 

        free(rsa_keys);
        printf("Generated new keys\n");
    }
    BIO * bp_public;
    BIO * bp_private;

    if(rsa_pub_key_p)
        fclose(rsa_pub_key_p);
    if(rsa_priv_key_p)
        fclose(rsa_priv_key_p);

    bp_public = BIO_new(BIO_s_file());
    bp_private = BIO_new(BIO_s_file());

    if (BIO_read_filename(bp_public, rsa_pub_keyfile) == 0) {
        fprintf(stderr, "Can't open public keyfile \n");
        abort();
    }
    if (BIO_read_filename(bp_private, rsa_priv_keyfile) == 0) {
        fprintf(stderr, "Can't open private keyfile\n");
        abort();
    }
    rsa_pub = RSA_new();
    rsa_priv = RSA_new();
    PEM_read_bio_RSAPublicKey(bp_public,  &rsa_pub, NULL, NULL);
    PEM_read_bio_RSAPrivateKey(bp_private, &rsa_priv, NULL, NULL);

    if (!rsa_pub) {
        fprintf(stderr, "Can't load public key\n");
        abort();
    }

    if (!rsa_priv) {
        fprintf(stderr, "Can't load private key\n");
        abort();
    }

   // free(confdir);
   // free(rsa_pub_keyfile);
   // free(rsa_priv_keyfile);
   // free(bp_public);
   // free(bp_private);

    int rc = i2d_RSAPublicKey(rsa_pub, NULL);
    unsigned char* rsa_pub_pem = malloc(rc*2);
    i2d_RSAPublicKey(rsa_pub, &rsa_pub_pem);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, rsa_pub_pem, rc);
    SHA256_Final(hash, &sha256);
    unsigned int hash1 = hash[0];
    unsigned int hash2 = hash[1];
    unsigned int hash3 = hash[2];
    unsigned int hash4 = hash[3];
    hash1 <<= 24;
    hash2 <<= 16;
    hash3 <<= 8;
    id = hash1+hash2+hash3+hash4;
    if(id<0)id*=-1;
    printf("id: %d\n",id);
    
}

void * send_id(void *ptr)
{
    packet* pkt = (packet*)malloc(sizeof(packet));
    pkt->type = 'u';
    pkt->error = '\0';
    pkt->length = 4;
    int id_tt = 0;
    id_tt=id;
    for (int i=0; i<4; i++){
        pkt->buf[i] = (char)id_tt;
        id_tt = id_tt >> 8;
    }
    unsigned char * byte = convert_packet_to_byte(pkt);
    for(;;) {
       int status = sendto(sock, byte, pkt->length+6, 0, (struct sockaddr *)&serv_addr, sizeof(struct sockaddr_in));
       if(status==-1) {
            pthread_mutex_lock(&stdout_lock);
            fprintf(stderr, "Error sending id to server");
            pthread_mutex_unlock(&stdout_lock);
        } 
        sleep(2);
    }
}

void punch(packet * pkt)
{
    struct sockaddr_in * addr = malloc(sizeof(struct sockaddr_in));
    memcpy(addr,pkt->buf,sizeof(struct sockaddr_in));
    packet pkt2;
    pkt2.type = 'p';
    pkt2.error = '\0';
    pkt2.length = 0;
    unsigned char * byte = convert_packet_to_byte(&pkt2);
    int status = sendto(sock, byte, pkt2.length+6, 0, (struct sockaddr *)addr, sizeof(struct sockaddr_in));
    if(status==-1) {
        pthread_mutex_lock(&stdout_lock);
        fprintf(stderr, "Error sending id to server");
        pthread_mutex_unlock(&stdout_lock);
    } 
}

void login_reply(packet * pkt)
{
    char error = pkt->error;
    if (error != '\0') {
        pthread_mutex_lock(&stdout_lock);
        fprintf(stderr, "Server said to fuck off\n");
        pthread_mutex_unlock(&stdout_lock);
    }
}

void show_notification(packet * pkt)
{   
    unsigned char * res = malloc(1024);
    memset(res,0,1024);
    int status = RSA_private_decrypt(pkt->length, pkt->buf, res, rsa_priv, padding);
    if(status==-1) {
        pthread_mutex_lock(&stdout_lock);
        int err = ERR_peek_last_error();
        char * err_text = malloc(1024);
        ERR_load_crypto_strings();
        ERR_error_string(err,err_text);
        printf("%d %s\n",err,err_text);
        pthread_mutex_unlock(&stdout_lock);
        free(err_text);
        return;
    }
    pthread_mutex_lock(&stdout_lock);
    printf("%s\n",res);
    pthread_mutex_unlock(&stdout_lock);

	notify_init ("Notification");
	NotifyNotification * note = notify_notification_new ("Phone notification", res, "dialog-information");
	notify_notification_show (note, NULL);
	g_object_unref(G_OBJECT(note));
	notify_uninit();
    free(res);
}

void pong(struct sockaddr_in * sender_addr, packet * orig)
{
    packet pkt;
    pkt.type = 'r';
    pkt.error = '\0';
    pkt.length = 4;
    int id_tt = 0;
    id_tt=id;
    for (int i=0; i<4; i++){
        pkt.buf[i] = (char)id_tt;
        id_tt = id_tt >> 8;
    }
    unsigned char* byte = convert_packet_to_byte(&pkt); 
    if (!sendto(sock, byte, 6+pkt.length, 0, (struct sockaddr *)sender_addr, sizeof(struct sockaddr_in))) {
        pthread_mutex_lock(&stdout_lock);
        fprintf(stderr, "Error replying to ping\n");
        pthread_mutex_unlock(&stdout_lock);
    }
}

char * join_char_arrays(char *a, char *b)
{
    char *c = malloc(strlen(a) + strlen(b) + 1);
    memcpy(c, a, strlen(a));
    memcpy(c + strlen(a), b, strlen(b)+1);
    return c;
}

int generate_qrcode()
{
    unsigned char * buf = NULL;
    unsigned char * e_byte = NULL;
    unsigned char * n_byte = NULL;
    unsigned char * e_based = NULL;
    unsigned char * n_based = NULL;
    int e_byte_l = BN_num_bytes(rsa_priv->e);
    e_byte = malloc(e_byte_l+1);
    BN_bn2bin(rsa_priv->e, e_byte);
    e_based = malloc(base64_encode_len(e_byte_l)+1);
    base64_encode(e_based, e_byte, e_byte_l);

    int n_byte_l = BN_num_bytes(rsa_priv->n);
    n_byte = malloc(n_byte_l+1);
    BN_bn2bin(rsa_priv->n, n_byte);
    n_based = malloc(base64_encode_len(n_byte_l)+1);
    base64_encode(n_based, n_byte, n_byte_l);

    char * qr_text = malloc(2048);
    sprintf(qr_text, "Tyr;%d;%s;%s;%s;%d", id, n_based, e_based, server_address, server_port);

    QRcode *qrcode = QRcode_encodeString(qr_text, 0, QR_ECLEVEL_M, QR_MODE_8, 1);       
    if(qrcode == NULL) {
        pthread_mutex_lock(&stdout_lock);
        fprintf(stderr, "Could not create qrcode\n");
        pthread_mutex_unlock(&stdout_lock);
    }

    free(e_byte);
    free(e_based);
    free(n_byte);
    free(n_based);

    return write_PNG(qrcode, join_char_arrays(getpwuid(getuid())->pw_dir, "/.tyr/qrcode.png"));
}

unsigned char* convert_packet_to_byte(packet* pkt)
{
    unsigned char* byte = malloc(pkt->length + 6);
    byte[0]=pkt->type;
    byte[1]=pkt->error;
    byte[2]=(unsigned char)(pkt->length>>24);
    byte[3]=(unsigned char)(pkt->length>>16);
    byte[4]=(unsigned char)(pkt->length>>8);
    byte[5]=(unsigned char)pkt->length;
    memcpy(byte+6,pkt->buf,pkt->length);
    return byte;
}

packet* convert_byte_to_packet(unsigned char* byte)
{
    packet* pkt = malloc(sizeof(packet));
    pkt->type = byte[0];
    pkt->error = byte[1];
    pkt->length = (uint32_t)byte[2];
    pkt->length = pkt->length<<8 | (uint32_t)byte[3];
    pkt->length = pkt->length<<8 | (uint32_t)byte[4];
    pkt->length = pkt->length<<8 | (uint32_t)byte[5];
    memcpy(pkt->buf, byte+6, pkt->length);
    return pkt;
}

static const char basis_64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int base64_encode_len(int len)
{
    return ((len + 2) / 3 * 4) + 1;
}

static const unsigned char pr2six[256] =
{
    /* ASCII table */
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

int base64_encode(char *encoded, const char *string, int len)
{
    int i;
    char *p;

    p = encoded;
    for (i = 0; i < len - 2; i += 3) {
    *p++ = basis_64[(string[i] >> 2) & 0x3F];
    *p++ = basis_64[((string[i] & 0x3) << 4) |
                    ((int) (string[i + 1] & 0xF0) >> 4)];
    *p++ = basis_64[((string[i + 1] & 0xF) << 2) |
                    ((int) (string[i + 2] & 0xC0) >> 6)];
    *p++ = basis_64[string[i + 2] & 0x3F];
    }
    if (i < len) {
    *p++ = basis_64[(string[i] >> 2) & 0x3F];
    if (i == (len - 1)) {
        *p++ = basis_64[((string[i] & 0x3) << 4)];
        *p++ = '=';
    }
    else {
        *p++ = basis_64[((string[i] & 0x3) << 4) |
                        ((int) (string[i + 1] & 0xF0) >> 4)];
        *p++ = basis_64[((string[i + 1] & 0xF) << 2)];
    }
    *p++ = '=';
    }

    *p++ = '\0';
    return p - encoded;
}

int write_PNG(QRcode *qrcode, char *outfile)
{
    int margin=5;
    int size=5;
    static unsigned int fg_color[4] = {0, 0, 0, 255};
    static unsigned int bg_color[4] = {255, 255, 255, 255};
    static int dpi = 72;


	static FILE *fp;
	png_structp png_ptr;
	png_infop info_ptr;
	png_colorp palette;
	png_byte alpha_values[2];
	unsigned char *row, *p, *q;
	int x, y, xx, yy, bit;
	int realwidth;

	realwidth = (qrcode->width + margin * 2) * size;
	row = (unsigned char *)malloc((realwidth + 7) / 8);
	if(row == NULL) {
		fprintf(stderr, "Failed to allocate memory.\n");
		exit(EXIT_FAILURE);
	}

	if(outfile[0] == '-' && outfile[1] == '\0') {
		fp = stdout;
	} else {
		fp = fopen(outfile, "wb");
		if(fp == NULL) {
			fprintf(stderr, "Failed to create file: %s\n", outfile);
			perror(NULL);
			exit(EXIT_FAILURE);
		}
	}

	png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
	if(png_ptr == NULL) {
		fprintf(stderr, "Failed to initialize PNG writer.\n");
		exit(EXIT_FAILURE);
	}

	info_ptr = png_create_info_struct(png_ptr);
	if(info_ptr == NULL) {
		fprintf(stderr, "Failed to initialize PNG write.\n");
		exit(EXIT_FAILURE);
	}

	if(setjmp(png_jmpbuf(png_ptr))) {
		png_destroy_write_struct(&png_ptr, &info_ptr);
		fprintf(stderr, "Failed to write PNG image.\n");
		exit(EXIT_FAILURE);
	}

	palette = (png_colorp) malloc(sizeof(png_color) * 2);
	if(palette == NULL) {
		fprintf(stderr, "Failed to allocate memory.\n");
		exit(EXIT_FAILURE);
	}
	palette[0].red   = fg_color[0];
	palette[0].green = fg_color[1];
	palette[0].blue  = fg_color[2];
	palette[1].red   = bg_color[0];
	palette[1].green = bg_color[1];
	palette[1].blue  = bg_color[2];
	alpha_values[0] = fg_color[3];
	alpha_values[1] = bg_color[3];
	png_set_PLTE(png_ptr, info_ptr, palette, 2);
	png_set_tRNS(png_ptr, info_ptr, alpha_values, 2, NULL);

	png_init_io(png_ptr, fp);
	png_set_IHDR(png_ptr, info_ptr,
			realwidth, realwidth,
			1,
			PNG_COLOR_TYPE_PALETTE,
			PNG_INTERLACE_NONE,
			PNG_COMPRESSION_TYPE_DEFAULT,
			PNG_FILTER_TYPE_DEFAULT);
	png_set_pHYs(png_ptr, info_ptr,
			dpi * INCHES_PER_METER,
			dpi * INCHES_PER_METER,
			PNG_RESOLUTION_METER);
	png_write_info(png_ptr, info_ptr);

	/* top margin */
	memset(row, 0xff, (realwidth + 7) / 8);
	for(y=0; y<margin * size; y++) {
		png_write_row(png_ptr, row);
	}

	/* data */
	p = qrcode->data;
	for(y=0; y<qrcode->width; y++) {
		bit = 7;
		memset(row, 0xff, (realwidth + 7) / 8);
		q = row;
		q += margin * size / 8;
		bit = 7 - (margin * size % 8);
		for(x=0; x<qrcode->width; x++) {
			for(xx=0; xx<size; xx++) {
				*q ^= (*p & 1) << bit;
				bit--;
				if(bit < 0) {
					q++;
					bit = 7;
				}
			}
			p++;
		}
		for(yy=0; yy<size; yy++) {
			png_write_row(png_ptr, row);
		}
	}
	/* bottom margin */
	memset(row, 0xff, (realwidth + 7) / 8);
	for(y=0; y<margin * size; y++) {
		png_write_row(png_ptr, row);
	}

	png_write_end(png_ptr, info_ptr);
	png_destroy_write_struct(&png_ptr, &info_ptr);

	fclose(fp);
	free(row);
	free(palette);

	return 1;
}

