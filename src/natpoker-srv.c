#include <arpa/inet.h>
#include <errno.h>
#include <ev.h>
#include <string.h>
#include <unistd.h>

#include "natpoker-stun.h"
#include "natpoker-log.h"

#define BUFFER_SIZE 1280
#define DEFAULT_PORT 3478

char* inet_pton64(const struct sockaddr *addr, char *s, size_t maxlen)
{
	switch(addr->sa_family) {
	case AF_INET: {
		inet_ntop(AF_INET, &(((struct sockaddr_in *)addr)->sin_addr), s, maxlen);
		break;
	}
	case AF_INET6: {
		inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)addr)->sin6_addr), s, maxlen);
		break;
	}
	}
	return s;
}

uint16_t inet_port64(struct sockaddr *addr)
{
	switch(addr->sa_family) {
	case AF_INET: {
		return ntohs(((struct sockaddr_in*)addr)->sin_port);
	}
	case AF_INET6: {
		return ntohs(((struct sockaddr_in6*)addr)->sin6_port);
	}
	}
	return -1;
}

static void udp_recv_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	if (EV_ERROR & revents) {
		log_err("received invalid event");
		return;
	}

	int rc;
	char buffer[BUFFER_SIZE];
	struct sockaddr peer;
	socklen_t peer_len = sizeof(struct sockaddr);
	memset(buffer, 0, BUFFER_SIZE);
	rc = recvfrom(watcher->fd, buffer, BUFFER_SIZE, 0, &peer, &peer_len);
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
		log_msg("Received STUN binding request from %s:%u",
			inet_pton64(&peer, ip_str, INET6_ADDRSTRLEN), inet_port64(&peer));
		stun_send_response(watcher->fd, stun, &peer, peer_len);
	}
}

int main(int argc, char* argv[])
{
	int rc;
	int debug = 1;

        char *tmp = strdup(argv[0]);
	log_init(tmp, debug);

	int sd = socket(PF_INET, SOCK_DGRAM, 0);
	if (sd < 0) {
		log_err("socket() failed: %s", strerror(errno));
		exit(1);
	}

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_port = htons(DEFAULT_PORT);
	rc = bind(sd, (struct sockaddr*)&addr, sizeof(addr));
	if (rc != 0) {
		log_err("bind() failed: %s", strerror(errno));
		exit(1);
	}

	/* Start the event loop to read incoming requests */
	ev_io w_client;
	struct ev_loop *loop = ev_default_loop(0);
	ev_io* foo = &w_client;
	ev_io_init(foo, udp_recv_cb, sd, EV_READ);
	ev_io_start(loop, &w_client);

	ev_loop(loop, 0);

	free(tmp);
	close(sd);
}

