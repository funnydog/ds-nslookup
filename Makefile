CFLAGS = -Wall -D_DEFAULT_SOURCE -std=c99 -Os
LIBS = -lresolv
SRCS = nslookup.c
OBJS = ${SRCS:.c=.o}
DESTDIR = /usr/local

.PHONY: all clean install

all: nslookup

install: nslookup
	install -d -m 0755 $(DESTDIR)/bin
	install -m 0755 ./nslookup $(DESTDIR)/bin

nslookup: $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

clean:
	@rm -f *.o *~ nslookup
