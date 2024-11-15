all: server.out client.out

# Rule to compile the server
server.out: ./server/server.cpp
	g++ -Wall -O -o twmailer-pro-server.out ./server/server.cpp -lldap -llber

# Rule to compile the client
client.out: ./client/client.cpp
	g++ -Wall -O -o twmailer-pro-client.out ./client/client.cpp

# Clean up the compiled files
clean:
	rm -f twmailer-pro-server.out twmailer-pro-client.out