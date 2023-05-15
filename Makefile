CFLAGS = -std=c11 -D_GNU_SOURCE -g -fvisibility=hidden -Wall -Wextra -fPIC -I .
LDFLAGS = -Wl,--as-needed
LDLIBS = -lpthread
OBJECTS = alloc.o mpool.o
BINARIES = alloc.so test_small test_large test_huge test

DEBUG ?= 0

ifeq ($(DEBUG), 1)
	CFLAGS += -DDEBUG
else
	CFLAGS += -O2 
	LDFLAGS += -O2
endif

all: clean $(BINARIES)

alloc.so: $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared $^ $(LDLIBS) -o $@

test_small: test_small.c $(OBJECTS)
test_large: test_large.c $(OBJECTS)
test_huge : test_huge.c $(OBJECTS)
test      : test.c $(OBJECTS)

alloc.o: alloc.c alloc.h rb.h list.h mpool.h
mpool.o: mpool.c mpool.h list.h

clean:
	rm -f $(OBJECTS) $(BINARIES)

.PHONY: all clean

