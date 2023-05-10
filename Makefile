CFLAGS = -O0 -std=c11 -D_GNU_SOURCE -g -fvisibility=hidden -Wall -Wextra -fPIC -I .
LDFLAGS = -Wl,--as-needed
LDLIBS = -lpthread
OBJECTS = alloc.o 
BINARIES = alloc.so test_small test_large test_huge

DEBUG ?= 1

ifeq ($(DEBUG), 1)
	CFLAGS += -DDEBUG
endif

all: clean $(BINARIES)

alloc.so: $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared $^ $(LDLIBS) -o $@

test_small: test_small.c $(OBJECTS)
test_large: test_large.c $(OBJECTS)
test_huge : test_huge.c $(OBJECTS)

alloc.o: alloc.c alloc.h rb.h

clean:
	rm -f $(OBJECTS) $(BINARIES)

.PHONY: all clean

