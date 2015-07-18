#include <arpa/inet.h>
#include <errno.h>
#include <ev.h>
#include <string.h>
#include <unistd.h>

#include <stdio.h>

#include "natpoker-stun.h"
#include "natpoker-log.h"

#define BUFFER_SIZE 1280
#define DEFAULT_PORT 3478

struct tcp_buffer
{
	char buffer[BUFFER_SIZE];
	uint16_t idx;
};


char* inet_pton64(const struct sockaddr_storage *addr, char *s, size_t maxlen)
{
	switch(addr->ss_family) {
	case AF_INET: {
		inet_ntop(AF_INET, &(((struct sockaddr_in *)addr)->sin_addr), s, maxlen);
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6*)addr;
		if (IN6_IS_ADDR_V4MAPPED(&addr6->sin6_addr)) {
			struct in_addr v4_tmp;
			memcpy(&v4_tmp.s_addr, addr6->sin6_addr.s6_addr+12, sizeof(v4_tmp.s_addr));
			inet_ntop(AF_INET, &v4_tmp, s, maxlen);
		}
		else {
			inet_ntop(AF_INET6, &addr6->sin6_addr, s, maxlen);
		}
		break;
	}
	}
	return s;
}

uint16_t inet_port64(struct sockaddr_storage *addr)
{
	switch(addr->ss_family) {
	case AF_INET: {
		return ntohs(((struct sockaddr_in*)addr)->sin_port);
	}
	case AF_INET6: {
		return ntohs(((struct sockaddr_in6*)addr)->sin6_port);
	}
	}
	return -1;
}

static void tcp_recv_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	if (EV_ERROR & revents) {
		log_err("received invalid event in %s", __func__);
		return;
	}

	int rc;

	struct tcp_buffer *tcp_buffer = watcher->data;

	rc = recv(watcher->fd, &tcp_buffer->buffer[tcp_buffer->idx], BUFFER_SIZE, 0);
	if (rc == -1) {
		log_err("error on recv: %s", strerror(errno));
		goto bail;
	}
	if (rc == 0) {
		log_msg("client is leaving");
		goto bail;
	}

	tcp_buffer->idx += rc;

	if (tcp_buffer->idx < 20) {
		return;
	}

	struct stun_hdr *stun = (struct stun_hdr*)tcp_buffer->buffer;
	if (stun_validate(stun)) {
		struct sockaddr_storage peer;
		socklen_t       peer_len = sizeof(peer);
		char            ip_str[INET6_ADDRSTRLEN];

		memset(ip_str, '\0', INET6_ADDRSTRLEN);
		getpeername(watcher->fd, (struct sockaddr*)&peer, &peer_len);
		log_msg("Received STUN TCP binding request from %s:%u",
			inet_pton64(&peer, ip_str, INET6_ADDRSTRLEN), inet_port64(&peer));
	}
	else {
		goto bail;
	}

	if (tcp_buffer->idx < 20 + stun->msg_len) {
		return;
	}

	rc = stun_send_tcp_response(watcher->fd, stun);
	if (rc == -1) {
		goto bail;
	}

	memset(tcp_buffer->buffer, 0, BUFFER_SIZE);
	tcp_buffer->idx = 0;

	return;

bail:
	ev_io_stop(loop, watcher);
	close(watcher->fd);
	free(watcher->data);
	free(watcher);
}

static void tcp_accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	if (EV_ERROR & revents) {
		log_err("received invalid event");
		return;
	}

	int sd;
	struct sockaddr_storage peer;
	socklen_t peer_len = sizeof(peer);

	sd = accept(watcher->fd, (struct sockaddr*)&peer, &peer_len);
	if (sd == -1) {
		log_err("TCP accept failed: %s", strerror(errno));
		return;
	}

	struct ev_io* w_client = (struct ev_io*)malloc(sizeof(struct ev_io));
	if (w_client == NULL) {
		log_err("malloc() failed: %s", strerror(errno));
		close(sd);
		return;
	}

	struct tcp_buffer *buffer = (struct tcp_buffer*)malloc(sizeof(struct tcp_buffer));
	if (buffer == NULL) {
		log_err("malloc() failed: %s", strerror(errno));
		close(sd);
		free(w_client);
		return;
	}
	memset(buffer, 0, sizeof(struct tcp_buffer));
	w_client->data = buffer;

	char ip_str[INET6_ADDRSTRLEN];
	memset(ip_str, '\0', INET6_ADDRSTRLEN);
	log_msg("New connection from %s:%u",
		inet_pton64(&peer, ip_str, INET6_ADDRSTRLEN), inet_port64(&peer));

	ev_io_init(w_client, tcp_recv_cb, sd, EV_READ);
	ev_io_start(loop, w_client);
}

static void udp_recv_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	if (EV_ERROR & revents) {
		log_err("received invalid event");
		return;
	}

	int rc;
	char buffer[BUFFER_SIZE];
	struct sockaddr_storage peer;
	socklen_t peer_len = sizeof(peer);
	memset(buffer, 0, BUFFER_SIZE);
	rc = recvfrom(watcher->fd, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&peer, &peer_len);
	if (rc == -1) {
		log_err("error on recvfrom: %s", strerror(errno));
		ev_io_stop(loop, watcher);
		ev_break(loop, EVBREAK_ALL);
		return;
	}

	struct stun_hdr *stun = (struct stun_hdr*)buffer;
	if (stun_validate(stun)) {
		char ip_str[INET6_ADDRSTRLEN];
		memset(ip_str, '\0', INET6_ADDRSTRLEN);
		log_msg("Received STUN UDP binding request from %s:%u",
			inet_pton64(&peer, ip_str, INET6_ADDRSTRLEN), inet_port64(&peer));
		stun_send_udp_response(watcher->fd, stun, (struct sockaddr*)&peer, peer_len);
	}
}

int register_layer34(int layer3, int layer4, ev_io *client, struct ev_loop *loop)
{
	int rc;
	int sd = socket(layer3, layer4, 0);
	if (sd < 0) {
		log_err("UDP socket() failed: %s", strerror(errno));
		return 1;
	}

	struct sockaddr_storage addr;
	memset(&addr, 0, sizeof(addr));
	addr.ss_family = layer3;

	switch (addr.ss_family) {
	case PF_INET: {
		struct sockaddr_in *addr4 = (struct sockaddr_in*)&addr;
		addr4->sin_port = htons(DEFAULT_PORT);
		break;
	}
	case PF_INET6: {
		setsockopt(sd, SOL_SOCKET, IPV6_V6ONLY, 0, sizeof(int));
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6*)&addr;
		addr6->sin6_port = htons(DEFAULT_PORT);
		break;
	}
	default: {
		log_err("Unsupported network layer protocol.\n");
		return -1;
	}
	}
	rc = bind(sd, (struct sockaddr*)&addr, sizeof(addr));
	if (rc != 0) {
		log_err("bind() failed: %s", strerror(errno));
		return 1;
	}

	if (layer4 == SOCK_STREAM) {
		rc = listen(sd, 0);
		if (rc == -1) {
			log_err("TCP listen() failed: %s", strerror(errno));
			return 1;
		}
	}

	if (layer4 == SOCK_DGRAM) {
		ev_io_init(client, udp_recv_cb, sd, EV_READ);
	}
	else if (layer4 == SOCK_STREAM) {
		ev_io_init(client, tcp_accept_cb, sd, EV_READ);
	}
	ev_io_start(loop, client);

	return 0;
}

int main(int argc, char* argv[])
{
	int debug = 1;

        char *prog_name = strdup(argv[0]);
	log_init(prog_name, debug);

	/* Start the event loop to read incoming requests */
	struct ev_loop *loop = ev_default_loop(0);

	/* UDP */
	ev_io  udp6_client;
	register_layer34(PF_INET6, SOCK_DGRAM, &udp6_client, loop);

	/* TCP */

	ev_loop(loop, 0);

	log_err("Warning: not closing sockets");

	free(prog_name);
	//close(udp_sd);
	//close(tcp_sd);
}

