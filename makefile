all:
	@g++ -std=c++11 main.cpp -o a.out -I/usr/local/ssl/include/ -L/usr/local/ssl/lib/ -lcrypto -ldl
	@./a.out