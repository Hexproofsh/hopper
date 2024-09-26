GCC_DBG_OPTS= -g
CC=gcc

all:
	$(CC) -o hopper hopper.c sym.c utils.c patch.c
debug:
	$(CC) $(GCC_DBG_OPTS) -o hopper hopper.c sym.c utils.c patch.c
clean:
	rm hopper
