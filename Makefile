CFLAGS = -O2 -Wall -Wextra -fPIC -I .
SRC ?= alloc.c
SHARE-OBJFLAGS = -shared -o
SHARE-OBJ = libmy_alloc.so
OBJ = $(patsubst %.c, %.o, $(SRC))
MMAP ?= 0
DEBUG ?= 1

ifeq ($(MMAP), 1)
	CFLAGS += -DMMAP
endif

ifeq ($(DEBUG), 1)
	CFLAGS += -DDEBUG
endif

CFLAGS += -c


all: clean
	$(CC) $(CFLAGS) $(SRC)
	$(CC) $(SHARE-OBJFLAGS) $(SHARE-OBJ) $(OBJ)

test: all
	LD_PRELOAD=./$(SHARE-OBJ) ls

clean:
	$(RM) $(SHARE-OBJ) $(OBJ) 