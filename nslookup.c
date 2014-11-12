#include <arpa/inet.h>
#include <resolv.h>
#include <netdb.h>
#include <stdio.h>
#include <poll.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

static const int POLL_TIMEOUT = 5000;

static void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET)
		return &(((struct sockaddr_in*)sa)->sin_addr);

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

static void print_address(int count, struct sockaddr *sa, const char *name)
{
	char str[INET6_ADDRSTRLEN];
	printf("Address %d: %s %s\n", count,
	       inet_ntop(sa->sa_family, get_in_addr(sa), str, sizeof(str)),
	       name);
}

static int resolve_server(const char *server, struct sockaddr *sa, socklen_t *slen)
{
	/* translate the server name to an address */
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_DGRAM,
		.ai_flags = AI_PASSIVE|AI_CANONNAME,
	};
	struct addrinfo *res;

	int rv = getaddrinfo(server, "53", &hints, &res);
	if (rv != 0 || res == NULL) {
		fprintf(stderr, "cannot resolve %s:%s\n", server, "53");
		return -1;
	}

	/* save the values into the structure */
	*slen = res->ai_addrlen;
	memmove(sa, res->ai_addr, res->ai_addrlen);

	/* print the server name */
	printf("%-10s %s\n", "Server:", server);

	/* walk the address list and print the addresses */
	struct addrinfo *p;
	int cnt = 0;
	for (p = res; p != NULL; p = p->ai_next)
		print_address(++cnt, p->ai_addr, "");

	fputc('\n', stdout);

	/* free the data and exit */
	freeaddrinfo(res);
	return 0;
}

static int res_ssend(struct sockaddr *sa, socklen_t slen, const unsigned char *msg, int msglen,
		      unsigned char *answer, int anslen)
{
	struct sockaddr_storage src = {
		.ss_family = sa->sa_family,
	};

	int fd = socket(src.ss_family, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
	if (fd < 0) {
		fprintf(stderr, "cannot create the socket\n");
		goto err;
	}

	if (bind(fd, (void *)&src, slen) < 0) {
		fprintf(stderr, "bind failure\n");
		goto err_close;
	}

	/* send the query */
	if (sendto(fd, msg, msglen, MSG_NOSIGNAL, sa, slen) < 0) {
		fprintf(stderr, "sendto failure\n");
		goto err_close;
	}

	/* wait for the answer */
	struct pollfd pfd;
	pfd.fd = fd;
	pfd.events = POLLIN;
	if (poll(&pfd, 1, POLL_TIMEOUT) <= 0) {
		fprintf(stderr, "poll timeout\n");
		goto err_close;
	}

	/* receive the data */
	size_t alen = anslen;
	ssize_t rlen = recvfrom(fd, answer, alen, 0, (void*)&src, &slen);
	if (rlen < 0) {
		fprintf(stderr, "recvfrom error\n");
		goto err_close;
	}

	close(fd);
	return rlen;

err_close:
	close(fd);
err:
	return -1;
}

struct context
{
	int cnt;
};

/* modified from MUSL libc code */
static int dns_parse(const unsigned char *r, int rlen,
		     int (*callback)(void *, int, const void *, int,
				     const void *, const void *, size_t),
		     void *ctx)
{
	int len;

	/* return if we didn't even get the header */
	if (rlen < 12)
		return -1;

	/* return in case of errors */
	if ((r[3] & 15))
		return -1;

	int qdcount = r[4]*256 + r[5];
	int ancount = r[6]*256 + r[7];

	if (qdcount + ancount > 64)
		return -1;

	const unsigned char *p = r+12;
	while (qdcount--) {
		while (p-r < rlen && *p-1U < 127)
			p++;

		if (*p>193 || (*p==193 && p[1]>254) || p>r+rlen-6)
			return -1;

		p += 5 + !!*p;
	}

	while (ancount--) {
		while (p-r < rlen && *p-1U < 127)
			p++;

		const void *as = p;
		if (*p>193 || (*p==193 && p[1]>254) || p>r+rlen-6)
			return -1;

		p += 1 + !!*p;
		len = p[8]*256 + p[9];

		if (p+len > r+rlen)
			return -1;

		if (callback(ctx, p[1], p+10, len, as, r, rlen) < 0)
			return -1;

		p += 10 + len;
	}
	return 0;
}

static int dns_callback(void *c, int rr, const void *data, int len,
			const void *as, const void *packet, size_t packlen)
{
	struct context *ctx = c;
	const uint8_t *bytes = data;
	union {
		struct sockaddr sa;
		struct sockaddr_in v4;
		struct sockaddr_in6 v6;
	} u = {{0}};

	switch (rr) {
	case 1:			/* A */
		if (len < 4)
			return 0;

		u.v4.sin_family = AF_INET;
		u.v4.sin_addr.s_addr = *(long *)data;
		break;

	case 28:		/* AAAA */
		if (len < 16)
			return 0;
		u.v6.sin6_family = AF_INET6;
		memmove(u.v6.sin6_addr.s6_addr, bytes, 16);
		break;

	default:
		return -1;
	}

	const uint8_t *label = as;

	/* find the real position if we have a pointer */
	if ((label[0] & 0xC0) == 0xC0)
		label = packet + label[1] + (label[0] & 0x3F)*256U;

	/* expand the name to a FQDN */
	char name[256];
	if (dn_expand(packet, packet+packlen, label, name, sizeof(name)) < 0) {
		fprintf(stderr, "dn_expand() error\n");
		return -1;
	}

	print_address(++ctx->cnt, &u.sa, name);
	return 0;
}

int main(int argc, char *argv[])
{
	/* check the args */
	if (argc < 2 || argc > 3) {
		fprintf(stderr, "Usage: %s [HOST] [SERVER]\n", argv[0]);
		return EXIT_FAILURE;
	}

	/* build the query */
	unsigned char q[280];
	int ql = res_mkquery(0, argv[1], ns_t_a, ns_c_any, 0, 0, 0, q, sizeof(q));
	if (ql < 0) {
		fprintf(stderr, "cannot build the query\n");
		return EXIT_FAILURE;
	}

	/* send the query to the server */
	struct sockaddr_storage srv;
	socklen_t srvlen;
	unsigned char answer[1024];
	int len;

	if (argc == 2) {
		resolve_server("127.0.0.1", (void *)&srv, &srvlen);
		len = res_send(q, ql, answer, sizeof(answer));
	} else if (argc == 3) {
		resolve_server(argv[2], (void *)&srv, &srvlen);
		len = res_ssend((void *)&srv, srvlen, q, ql, answer, sizeof(answer));
	} else {
		abort();
	}

	if (len < 0) {
		fprintf(stderr, "cannot send the query\n");
		return EXIT_FAILURE;
	}

	/* decode the answer */
	struct context ctx = {0};
	printf("%-10s %s\n", "Name:", argv[1]);
	if (dns_parse(answer, len, dns_callback, &ctx) < 0) {
		fprintf(stderr, "decode failure\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
