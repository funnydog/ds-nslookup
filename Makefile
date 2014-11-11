CFLAGS = -Wall -D_DEFAULT_SOURCE -std=c99 -Os
LIBS = -lresolv
SRCS = nslookup.c
OBJS = ${SRCS:.c=.o}

.PHONY: all clean

all: nslookup

nslookup: $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

clean:
	@rm -f *.o *~ nslookup
