CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -I$(OPENSSL_INC)
LDFLAGS = -L$(OPENSSL_LIB) -lssl -lcrypto

OPENSSL_INC = $(shell brew --prefix openssl@3 2>/dev/null)/include
OPENSSL_LIB = $(shell brew --prefix openssl@3 2>/dev/null)/lib

SRCS   = peer.c crypto_utils.c transfer.c integrity.c
OBJS   = $(SRCS:.c=.o)
TARGET = peer_c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)
