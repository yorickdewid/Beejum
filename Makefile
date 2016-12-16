CFLAGS=-g -O0 beejum.c -lcrypto

all:
	$(CC) $(CFLAGS) -DUTIL -o beejum

clean:
	$(RM) -rf beejum btest

test:
	$(CC) $(CFLAGS) -DTESTCASE -o btest
	@./btest
