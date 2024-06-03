.PHONY: all client server


all: client server

server:
	CGO_ENABLED=1 CC=x86_64-unknown-linux-gnu-gcc GOOS=linux GOARCH=amd64 go build -o nowebshell ./server/

client:
	go build -o nowebshell-client ./client/ 