all: server.out client.out

# Rule to compile the server
server.out: ./server/twmailerPro-server.cpp
	g++ -Wall -O -o twmailer-server.out ./server/twmailerPro-server.cpp

# Rule to compile the client
client.out: ./client/twmailer-client.cpp
	g++ -Wall -O -o twmailer-client.out ./client/twmailer-client.cpp

# Clean up the compiled files
clean:
	rm -f twmailer-server.out twmailer-client.out