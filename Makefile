CC = gcc
CFLAGS = -O2 -Wall -Wextra -fPIC -I . -c
SRC = alloc.c
SHARE-OBJFLAGS = -shared -o
SHARE-OBJ = libmy_alloc.so
OBJ = alloc.o


all: clean
	$(CC) $(CFLAGS) $(SRC)
	$(CC) $(SHARE-OBJFLAGS) $(SHARE-OBJ) $(OBJ)

test: 
	LD_PRELOAD=./$(SHARE-OBJ) ps aux

clean:
	$(RM) $(SHARE-OBJ) $(OBJ)