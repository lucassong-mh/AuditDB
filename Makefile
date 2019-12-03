.PHONY:all
all:proxy
proxy:proxy.c
	gcc proxy.c -o proxy
.PHONY:clean
clean:
	rm -rf proxy

# EXTRA_CFLAGS += -Wall -Werror -lssl
# TAIL = -lssl -lcrypto
# .PHONY:all
# all:server client
# server:ssl-server.c
# 	gcc $(EXTRA_CFLAGS) ssl-server.c -o server $(TAIL)
# client:ssl-client.c
# 	gcc $(EXTRA_CFLAGS) ssl-client.c -o client $(TAIL)
# .PHONY:clean
# clean:
# 	rm -rf client server

# .PHONY:all
# all:proxy
# proxy:ssl-proxy.c
# 	gcc ssl-proxy.c -o proxy
# .PHONY:clean
# clean:
# 	rm -rf proxy

# .PHONY:all
# all:server client
# server:server.c
# 	gcc server.c -o server
# client:client.c
# 	gcc client.c -o client
# .PHONY:clean
# clean:
# 	rm -rf client server

# .PHONY:all
# all:server client
# server:server.cpp
# 	g++ server.cpp -o server
# client:client.cpp
# 	g++ client.cpp -o client
# .PHONY:clean
# clean:
# 	rm -rf client server

# .PHONY:all
# all:server client
# server:ssl-server.c
# 	gcc ssl-server.c -o server -lssl -lcrypto
# client:ssl-client.c
# 	gcc ssl-client.c -o client -lssl -lcrypto
# .PHONY:clean
# clean:
# 	rm -rf client server