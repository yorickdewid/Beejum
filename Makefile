CFLAGS=-g -Wall -Werror -pedantic -O0 beejum.c -lcrypto

all:
	$(CC) $(CFLAGS) -DUTIL -o beejum

clean:
	$(RM) -rf beejum btest

test:
	$(CC) $(CFLAGS) -Wno-unused-function -DTESTCASE -o btest
	@./btest
