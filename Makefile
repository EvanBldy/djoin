djoin: main.c
	make -C lib/ libdjoinutils.a
	gcc -Wall -o $@ $< -L./lib -L /usr/local/ssl/lib -ldjoinutils -I /usr/local/ssl/include -lssl -lcrypto -luuid

clean:
	rm -rf lib/*.a
	rm -f djoin


