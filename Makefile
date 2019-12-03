.PHONY:all
all:proxy
proxy:proxy.c
	gcc proxy.c -o proxy
.PHONY:clean
clean:
	rm -rf proxy