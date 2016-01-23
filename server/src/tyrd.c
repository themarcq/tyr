#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>

typedef struct node node;
struct node {
    node * left;
    node * right;
    unsigned char * id;
    struct sockaddr_in * info;
};

typedef struct packet_t {
    char type;
    char error;
    uint32_t length;
    unsigned char buf[1024];
} packet;

int port = 1222;

int byte_on_index(unsigned char * id, int index); 
int put_info(node * n, unsigned char * id, struct sockaddr_in * info, int depth);
struct sockaddr_in * fetch_info(node * n, unsigned char * id, int depth);
void show_help();
void parse_args(int argc, char ** argv);
void receive_packets();
void id_update_reply(packet * pkt, struct sockaddr_in * sender_addr);
void ip_request_reply(packet * pkt, struct sockaddr_in *  sender_addr);
int idcmp(unsigned char * a, unsigned char *b);
unsigned char* convert_packet_to_byte(packet* pkt);
packet* convert_byte_to_packet(unsigned char* byte);
int  sock;
struct sockaddr_in self_addr;
node * top;

int main(int argc, char ** argv) {
    parse_args(argc, argv);

    top = malloc(sizeof(node));

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        fprintf(stderr, "Can't create socket\n");
        abort();
    }

    self_addr.sin_family = AF_INET;
    self_addr.sin_port = htons(port);
    self_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (struct sockaddr *)&self_addr, sizeof(self_addr))) {
        fprintf(stderr, "Error binding socket\n");
        abort();
    }

    receive_packets();
}

void show_help()
{
    printf("\
Usage: tyrd [OPTIONS]...\n\
\n\
    -p, --port       specify server port\n");
abort();
}

void parse_args(int argc, char ** argv) 
{
    for(;;) {
        static struct option long_options[] = {
            {"port",         required_argument,  0,  'p'}
        };
        int option_index = 0;
        int this_option_optind = optind ? optind : 1;

        int c = getopt_long(argc, argv, "p:",
                long_options, &option_index);
        if (c == -1)
            break;
        switch(c) {
            case 'p':
                port = atoi(optarg);
                break;
        }
    }
    if (optind < argc) {
        fprintf(stderr, "Unknow option: %s\n", argv[optind++]);
        show_help();
    }
}

void receive_packets()
{
    unsigned char* buf = malloc(1024);
    for(;;){
        socklen_t addrlen = 10;
        int status;
        struct sockaddr_in sender_addr;
        status = recvfrom(sock, buf, 1024, 0, (struct sockaddr *)&sender_addr, &addrlen);
        if(status == -1){
            fprintf(stderr, "error receiving a pktet\n");
        }
        packet* pkt = convert_byte_to_packet(buf);
        switch (pkt->type) {
            case 'u':
                id_update_reply(pkt, &sender_addr);
                break;
            case 'i':
                ip_request_reply(pkt, &sender_addr);
                break;
            default:
                fprintf(stderr, "Unknow pktet type received\n");
                break;
        }
    }
}

void id_update_reply(packet * pkt, struct sockaddr_in * sender_addr)
{
    unsigned char * id = malloc(pkt->length);
    memcpy(id, pkt->buf, pkt->length);
    put_info(top, id, sender_addr, 0);
    packet response;
    response.type = 'i';
    response.error = '\0';
    response.length = 0;
    unsigned char* byte = convert_packet_to_byte(&response);
    int status = sendto(sock, byte, 6, 0, (struct sockaddr *)sender_addr, sizeof(struct sockaddr_in));
    if(status<0)
        fprintf(stderr, "Packet Sending errno: %d\n",errno);
}

void ip_request_reply(packet * pkt, struct sockaddr_in *  sender_addr)
{
    unsigned char * id = malloc(pkt->length);
    memcpy(id, pkt->buf, pkt->length);
    struct sockaddr_in * info = fetch_info(top, id, 0);

    if (info == NULL) {
        //send error message
        packet response;
        response.type = 'i';
        response.error = 'p';
        response.length = 0;
        unsigned char* byte = convert_packet_to_byte(&response);
        int status = sendto(sock, byte, 6, 0, (struct sockaddr *)sender_addr, sizeof(struct sockaddr_in));
        if(status<0)
            fprintf(stderr, "Packet Sending errno: %d\n",errno);
    } else {
        //send ip and port
        packet response;
        response.type = 'i';
        response.error = '\0';
        response.length = 10;
        memcpy(response.buf, id, 4);
        memcpy(response.buf+4, &info->sin_addr.s_addr, 4);
        memcpy(response.buf+8, &info->sin_port, 2);
        unsigned char* byte = convert_packet_to_byte(&response);
        int status = sendto(sock, byte, 6+response.length, 0, (struct sockaddr *)sender_addr, sizeof(struct sockaddr_in));
        if(status<0)
            fprintf(stderr, "Packet Sending errno: %d\n",errno);
        else {
            free(byte);
            packet pkt;
            pkt.type = 'u';
            pkt.error = '\0';
            pkt.length = sizeof(struct sockaddr_in);
            memcpy(pkt.buf, sender_addr, sizeof(struct sockaddr_in));
            byte = convert_packet_to_byte(&pkt);
            int status = sendto(sock, byte, 6+response.length, 0, (struct sockaddr *)info, sizeof(struct sockaddr_in));
            if (status == -1)
                printf("lol\n");
        }
    }
}

int byte_on_index(unsigned char * id, int index) 
{
    return (id[index/8] >> (7 - (index % 8)) & 1);
}

int put_info(node * n, unsigned char * id, struct sockaddr_in * info, int depth) 
{
    if (n->left == NULL) {
        if (n->id == NULL) {
            n->id = malloc(4);
            memcpy(n->id,id,4);
            n->info = malloc(sizeof(struct sockaddr_in));
            memcpy(n->info,info,sizeof(struct sockaddr_in));
        } else {
            if (idcmp(n->id, id)) {
                n->info = malloc(sizeof(struct sockaddr_in));
                memcpy(n->info,info,sizeof(struct sockaddr_in));
            } else {
                node nl = {NULL, NULL, NULL, NULL};
                node np = {NULL, NULL, NULL, NULL};
                put_info((byte_on_index(n->id, depth) ? &nl : &np),
                         n->id, n->info, depth + 1);
                
                put_info((byte_on_index(id, depth) ? & nl : & np),
                         id, info, depth + 1);
                if(n->id != NULL)
                    free(n->id);
                if(n->info != NULL)
                    free(n->info);
            }
        }
    } else {
        put_info((byte_on_index(id, depth) ? n->left : n->right),
                 id, info, depth + 1);
    }
}

int idcmp(unsigned char * a, unsigned char *b)
{
    for(int i=0;i<4;i++)
        if(a[i]!=b[i])
            return 0;
    return 1;
}

struct sockaddr_in * fetch_info(node * n, unsigned char * id, int depth) 
{
    if (n->left == NULL) {
        if(n->id == NULL)
            return NULL;
        if (idcmp(id, n->id)) {
            return n->info;
        } else {
            return NULL;
        }
    } else {
        return(fetch_info((byte_on_index(id, depth) ? n->left : n->right), id, depth+1));
    }
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

