#ifndef _NATPOKER_STUN_H_
#define _NATPOKER_STUN_H_

#define STUN_COOKIE 0x2112a442

#define STUN_MSG_BINDING_REQ 0x0001
#define STUN_MSG_BINDING_RESP 0x0101

#define STUN_MAPPED_ADDRESS    0x0001
#define STUN_XORMAPPED_ADDRESS 0x0020
#define STUN_SOFTWARE          0x8022
#define STUN_RESPONSE_ORIGIN   0x802b

#define NP_NAME "NatPoker"
#define NP_VERSION "0.1"
#define NP_URL "https://github.com/sdstrowes/natpoker-srv"

#define BUFFER_SIZE 1280

struct stun_msgid
{
	uint8_t b[12];
} __attribute__((packed));

struct stun_hdr
{
	uint16_t msg_type;
	uint16_t msg_len;
	uint32_t msg_cookie;
	struct stun_msgid msg_id;
} __attribute__((packed));

struct stun_attr
{
	uint16_t type;
	uint16_t len;
	uint8_t  reserved;
	uint8_t  pf;
	uint16_t port;
	uint32_t ip;
} __attribute__((packed));


struct stun_attr_sw
{
	uint16_t type;
	uint16_t len;
	char     str[0];
} __attribute__((packed));

void stun_set_msg_type(struct stun_hdr *msg, uint16_t type);

void stun_set_msg_len(struct stun_hdr *msg, uint16_t len);

void stun_set_msg_cookie(struct stun_hdr *msg);

void stun_copy_msg_id(struct stun_hdr *a, struct stun_hdr *b);

int stun_validate(struct stun_hdr *msg);

int stun_add_mapped_addr(char* buffer, int* len, struct sockaddr* addr);

int stun_add_xormapped_addr(char* buffer, int* len, struct sockaddr* addr);

int stun_add_software(char* buffer, int* len);

int stun_send_response(int sd, struct stun_hdr* stun_cli, struct sockaddr* addr, socklen_t peer_len);

#endif

