CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -Werror -std=c17 -Iinclude -Isrc
LDFLAGS = 

CORE_SRCS = $(wildcard src/core/*.c)
CRYPTO_SRCS = $(wildcard src/crypto/*.c) include/agent.c
CORE_OBJS = $(CORE_SRCS:.c=.o)
CRYPTO_OBJS = $(CRYPTO_SRCS:.c=.o)
LIB_TARGET = libagent.a

CORE_TEST_SRCS = $(wildcard tests/core/*.c)
CORE_TEST_BINS = $(CORE_TEST_SRCS:.c=)
CRYPTO_TEST_SRC = tests/crypto/test_all.c
CRYPTO_TEST_BIN = test_all

.PHONY: all clean test test_core test_crypto

all: $(LIB_TARGET)

$(LIB_TARGET): $(CORE_OBJS) $(CRYPTO_OBJS)
	ar rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

test: test_core test_crypto

test_core: $(CORE_TEST_BINS)
	for test_bin in $(CORE_TEST_BINS); do ./$$test_bin; done

test_crypto: $(CRYPTO_TEST_BIN)
	./$(CRYPTO_TEST_BIN)

$(CRYPTO_TEST_BIN): $(CRYPTO_TEST_SRC) $(LIB_TARGET)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) -L. -lagent

$(CORE_TEST_BINS): %: %.c $(LIB_TARGET)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) -L. -lagent

clean:
	rm -f $(CORE_OBJS) $(CRYPTO_OBJS) $(LIB_TARGET) $(CORE_TEST_BINS) $(CRYPTO_TEST_BIN)
