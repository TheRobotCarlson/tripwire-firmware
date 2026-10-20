CFLAGS ?= -std=c11 -Wall -Wextra -Werror -O1 -g -fsanitize=address,undefined
SRC = ../tw_codec.c tw_aead_openssl.c test_vectors.c

test: test_vectors
	./test_vectors i1_vectors.txt

test_vectors: $(SRC) ../include/tw_codec.h
	$(CC) $(CFLAGS) -I../include -o $@ $(SRC) -lcrypto

clean:
	rm -f test_vectors

.PHONY: test clean
