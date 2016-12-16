all:
	$(CC) -O0 main.c -o main -lcrypto

clean:
	$(RM) -rf main
