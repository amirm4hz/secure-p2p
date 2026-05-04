tab = '\t'
makefile = (
    'CC      = gcc\n'
    'CFLAGS  = -Wall -Wextra -O2 -I$(OPENSSL_INC)\n'
    'LDFLAGS = -L$(OPENSSL_LIB) -lssl -lcrypto\n'
    '\n'
    'OPENSSL_INC = $(shell brew --prefix openssl@3 2>/dev/null)/include\n'
    'OPENSSL_LIB = $(shell brew --prefix openssl@3 2>/dev/null)/lib\n'
    '\n'
    'SRCS   = peer.c crypto_utils.c transfer.c integrity.c\n'
    'OBJS   = $(SRCS:.c=.o)\n'
    'TARGET = peer_c\n'
    '\n'
    '.PHONY: all clean\n'
    '\n'
    'all: $(TARGET)\n'
    '\n'
    '$(TARGET): $(OBJS)\n'
    + tab + '$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)\n'
    '\n'
    '%.o: %.c\n'
    + tab + '$(CC) $(CFLAGS) -c -o $@ $<\n'
    '\n'
    'clean:\n'
    + tab + 'rm -f $(OBJS) $(TARGET)\n'
)
with open('Makefile', 'w') as f:
    f.write(makefile)
print('Written. Verifying tabs:')
with open('Makefile') as f:
    for i, line in enumerate(f, 1):
        if line.startswith('\t'):
            print(f'  Line {i} has tab: {repr(line[:40])}')