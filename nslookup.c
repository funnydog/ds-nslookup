#include <arpa/inet.h>
#include <resolv.h>
#include <netdb.h>
#include <stdio.h>
#include <poll.h>
#include <unistd.h>
#include <string.h>

static const char *reverse(struct sockaddr *sa, socklen_t len)
{
	static char name[256];
	char serv[16];
	int rv = getnameinfo(sa, len, name, sizeof(name), serv, sizeof(serv), 0);
	if (rv < 0)
		return "";

	return name;
}
static void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET)
		return &(((struct sockaddr_in*)sa)->sin_addr);

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

static void print_address(struct sockaddr *sa, socklen_t len)
{
	char str[INET6_ADDRSTRLEN];
	printf("%-10s %s %s\n", "Address:",
	       inet_ntop(sa->sa_family, get_in_addr(sa), str, sizeof(str)),
	       reverse(sa, len));
}

static void print_server(struct sockaddr *sa, socklen_t len)
{
	printf("%-10s %s\n", "Server:", reverse(sa, len));
	print_address(sa, len);
	fputc('\n', stdout);
}

static int res_squery(const char *server, const char *dname, int class, int type,
		      unsigned char *answer, int anslen)
{
	/* build the query */
	unsigned char q[280];
	int ql = res_mkquery(0, dname, ns_t_a, ns_c_any, 0, 0, 0, q, sizeof(q));
	if (ql < 0) {
		fprintf(stderr, "cannot make the query\n");
		goto err;
	}

	/* translate the server name to an address */
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_DGRAM,
		.ai_flags = AI_PASSIVE|AI_CANONNAME,
	};
	struct addrinfo *res;

	int rv = getaddrinfo(server, "53", &hints, &res);
	if ( rv != 0 || res == NULL) {
		fprintf(stderr, "cannot resolve %s:%s\n", server, "53");
		fprintf(stderr, "%s\n", gai_strerror(rv));
		goto err;
	}

	/* print sockaddr */
	print_server(res->ai_addr, res->ai_addrlen);

	/* TODO: store the proper family agnostic sockaddr */
	struct sockaddr_in src = {
		.sin_family = AF_INET,
	};

	int fd = socket(res->ai_family, res->ai_socktype|SOCK_CLOEXEC|SOCK_NONBLOCK, res->ai_protocol);
	if (fd < 0) {
		fprintf(stderr, "cannot create the socket\n");
		goto err_freeaddrinfo;
	}

	if (bind(fd, (void *)&src, sizeof(src)) < 0) {
		fprintf(stderr, "bind failure\n");
		goto err_close;
	}

	/* send the query */
	if (sendto(fd, q, ql, MSG_NOSIGNAL, res->ai_addr, res->ai_addrlen) < 0) {
		fprintf(stderr, "sendto failure\n");
		goto err_close;
	}

	/* wait for the answer */
	struct pollfd pfd;
	pfd.fd = fd;
	pfd.events = POLLIN;
	if (poll(&pfd, 1, 5000) <= 0) {
		fprintf(stderr, "poll timeout\n");
		goto err_close;
	}

	/* receive the data */
	socklen_t len = sizeof(src);
	size_t alen = anslen;
	ssize_t rlen = recvfrom(fd, answer, alen, 0, (void*)&src, &len);
	if (rlen < 0) {
		fprintf(stderr, "recvfrom error\n");
		goto err_close;
	}

	freeaddrinfo(res);
	close(fd);
	return rlen;

err_close:
	close(fd);
err_freeaddrinfo:
	freeaddrinfo(res);
err:
	return -1;
}

/* copied straight from MUSL libc */
static int dns_parse(const unsigned char *r, int rlen,
		int (*callback)(void *, int, const void *, int, const void *),
		void *ctx)
{
	int qdcount, ancount;
	const unsigned char *p;
	int len;

	if (rlen<12)
		return -1;

	if ((r[3]&15))
		return 0;

	p = r+12;
	qdcount = r[4]*256 + r[5];
	ancount = r[6]*256 + r[7];

	if (qdcount+ancount > 64)
		return -1;

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

		if (*p>193 || (*p==193 && p[1]>254) || p>r+rlen-6)
			return -1;

		p += 1 + !!*p;
		len = p[8]*256 + p[9];

		if (p+len > r+rlen)
			return -1;

		if (callback(ctx, p[1], p+10, len, r) < 0)
			return -1;

		p += 10 + len;
	}
	return 0;
}

static int dns_callback(void *c, int rr, const void *data, int len, const void *packet)
{
	const uint8_t *bytes = data;
	union {
		struct sockaddr sa;
		struct sockaddr_in v4;
		struct sockaddr_in6 v6;
	} u = {{0}};
	socklen_t slen;

	switch (rr) {
	case 1:			/* A */
		if (len >= 4) {
			u.v4.sin_family = AF_INET;
			u.v4.sin_addr.s_addr = ((bytes[0]*256U + bytes[1])*256U + bytes[2])*256U + bytes[3];
			slen = sizeof(struct sockaddr_in);
		}
		break;

	case 28:		/* AAAA */
		if (len >= 16) {
			u.v6.sin6_family = AF_INET6;
			memmove(u.v6.sin6_addr.s6_addr, bytes, 16);
			slen = sizeof(struct sockaddr_in);
		}
		break;

	case 5:			/* CNAME */
		break;

	default:
		return -1;
	}

	print_address(&u.sa, slen);
	return 0;
}

int main(int argc, char *argv[])
{
	unsigned char answer[1024];

	int len;
	if (argc == 2) {
		len = res_query(argv[1], 1, 1, answer, sizeof(answer));
		print_server((struct sockaddr *)_res._u._ext.nsaddrs[0],
			     sizeof(struct sockaddr_in6));
	} else if (argc == 3)
		len = res_squery(argv[2], argv[1], 1, 1, answer, sizeof(answer));
	else
		return -1;

	printf("%-10s %s\n", "Name:", argv[1]);
	if (dns_parse(answer, len, dns_callback, NULL) < 0) {
		fprintf(stderr, "parse failure\n");
		return -1;
	}

	return 0;
}
