GCC_DBG_OPTS= -g
CC=gcc
SOURCE=hopper.c sym.c utils.c patch.c structure.c parser.c
all:
	$(CC) -o hopper $(SOURCE)
debug:
	$(CC) $(GCC_DBG_OPTS) -o hopper $(SOURCE)
clean:
	rm hopper
