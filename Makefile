make:
	-gcc -I/opt/homebrew/Cellar/openssl@3/3.2.0/include -o prox proxie.c -L/opt/homebrew/Cellar/openssl@3/3.2.0/lib -lssl -lcrypto

run: 
	-./prox 8898
	
clean:
	-rm prox
	-rm -rf cache