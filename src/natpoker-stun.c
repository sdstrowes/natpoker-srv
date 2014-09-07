#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

#include "natpoker-log.h"
#include "natpoker-stun.h"

void stun_set_msg_type(struct stun_hdr *msg, uint16_t type)
{
	msg->msg_type = htons(type);
}

void stun_set_msg_len(struct stun_hdr *msg, uint16_t len)
{
	msg->msg_len = htons(len);
}

void stun_set_msg_cookie(struct stun_hdr *msg)
{
	msg->msg_cookie = htonl(STUN_COOKIE);
}

void stun_copy_msg_id(struct stun_hdr *a, struct stun_hdr *b)
{
	memcpy(&b->msg_id, &a->msg_id, sizeof(a->msg_id));
}

int stun_validate(struct stun_hdr *msg)
{
	switch (ntohs(msg->msg_type)) {
	case 0x0001: {
		break;
	}
	default: {
		log_msg("Unknown packet type");
		return 0;
	}
	}

	if (ntohl(msg->msg_cookie) != STUN_COOKIE) {
		return 0;
	}

	return 1;
}

int stun_add_mapped_addr(char* buffer, int* len, struct sockaddr* addr)
{
	struct stun_attr attr = { 0 };
	attr.type = htons(STUN_MAPPED_ADDRESS);
	attr.len = htons(8);
	switch(addr->sa_family) {
	case AF_INET: {
		struct sockaddr_in *addr4 = (struct sockaddr_in*)addr;
		attr.pf = 0x01;
		attr.port = addr4->sin_port;
		attr.ip = addr4->sin_addr.s_addr;
		break;
	}
	case AF_INET6: {
		return 0;
//		struct sockaddr_in6 *addr6 = (struct sockaddr_in6*)addr;
//		attr.pf = 0x02;
//		attr.port = addr6->sin6_port;
//		memcpy(&attr.ip, &addr6->sin6_addr, sizeof(attr.ip));
//		break;
	}
	default: {
		return 0;
	}
	}

	memcpy(buffer, &attr, sizeof(attr));
	*len = sizeof(attr);

	return 1;
}

int stun_add_xormapped_addr(char* buffer, int* len, struct sockaddr* addr)
{
	struct stun_attr attr = { 0 };
	attr.type = htons(STUN_XORMAPPED_ADDRESS);
	attr.len = htons(8);
	switch(addr->sa_family) {
	case AF_INET: {
		struct sockaddr_in *addr4 = (struct sockaddr_in*)addr;
		attr.pf = 0x01;
		uint32_t xorip   = ntohl(addr4->sin_addr.s_addr) ^ STUN_COOKIE;
		uint16_t magic16 = STUN_COOKIE >> 16;
		uint16_t xorport = ntohs(addr4->sin_port) ^ magic16;

		attr.port = htons(xorport);
		attr.ip   = htonl(xorip);
		break;
	}
	case AF_INET6: {
		return 0;
//		struct sockaddr_in6 *addr6 = (struct sockaddr_in6*)addr;
//		attr.pf = 0x02;
//		attr.port = addr6->sin6_port;
//		memcpy(&attr.ip, &addr6->sin6_addr, sizeof(attr.ip));
//		break;
	}
	default: {
		return 0;
	}
	}

	memcpy(buffer, &attr, sizeof(attr));
	*len = sizeof(attr);

	return 1;
}

int stun_add_software(char* buffer, int* len)
{
	struct stun_attr_sw *attr = calloc(sizeof(struct stun_attr) + 762, 1);

	char string[763]; // rfc5389, s.15.10
	int length = sizeof(string);
	char* pos = string;
	memset(string, '\0', length);

	strncpy(pos, NP_NAME, length);
	length -= strlen(NP_NAME);
	pos += strlen(NP_NAME);

	pos = strncpy(pos, " ", length);
	length -= strlen(" ");
	pos += strlen(" ");

	pos = strncpy(pos, NP_VERSION, length);
	length -= strlen(NP_VERSION);
	pos += strlen(NP_VERSION);

	pos = strncpy(pos, ", ", length);
	length -= strlen(", ");
	pos += strlen(", ");

	pos = strncpy(pos, NP_URL, length);
	length -= strlen(NP_URL);
	pos += strlen(NP_URL);

	attr->type = htons(STUN_SOFTWARE);

	// Figure out padding
	int real_len = strlen(string);
	int padded_len = (real_len % 4) ? real_len + (4 - (real_len % 4)) : real_len;
	attr->len = htons(real_len);

	memcpy(attr->str, string, strlen(string));
	memcpy(buffer, attr, sizeof(*attr)+strlen(string));

	*len = sizeof(*attr) + padded_len;
	free(attr);
	return 1;
}

int stun_send_response(int sd, struct stun_hdr* stun_cli, struct sockaddr* addr, socklen_t peer_len)
{
	int rc;
	char *buffer = calloc(BUFFER_SIZE, 1);
	int msg_len = 0;
	struct stun_hdr stun_srv;

	stun_set_msg_type(&stun_srv, STUN_MSG_BINDING_RESP);
	stun_set_msg_cookie(&stun_srv);
	stun_copy_msg_id(stun_cli, &stun_srv);

	msg_len = sizeof(struct stun_hdr);

	int attr_len = 0;
	stun_add_mapped_addr(buffer+msg_len, &attr_len, addr);
	msg_len += attr_len;

	stun_add_xormapped_addr(buffer+msg_len, &attr_len, addr);
	msg_len += attr_len;

	stun_add_software(buffer+msg_len, &attr_len);
	msg_len += attr_len;

	stun_set_msg_len(&stun_srv, msg_len - sizeof(struct stun_hdr));

	memcpy(buffer, &stun_srv, sizeof(stun_srv));

	rc = sendto(sd, buffer, msg_len, 0, addr, peer_len);
	if (rc == -1) {
		log_err("error sending: %s", strerror(errno));
	}

	free(buffer);
	return rc;
}


