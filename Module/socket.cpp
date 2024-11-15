#include <iostream>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h> 
#include <arpa/inet.h>

class NetworkSocket
{
    public:
        NetworkSocket(std::string ip = INADDR_ANY, int port)
        {
            create_socket();
            this->port = port;
            socketAddress.sin_family = AF_INET;
            socketAddress.sin_port = htons(port);
            socketAddress.sin_addr.s_addr = INADDR_ANY;
            if (ip != "0.0.0.0")
                inet_aton(ip.c_str(), &socketAddress.sin_addr);
            setup_socket();
        }
        void create_socket()
        {
            this->sfd = socket(AF_INET, SOCK_STREAM, 0);
            if (this->sfd == -1) {
                std::cerr << "Socket creation failed with error" << errno << std::endl;
                exit(EXIT_FAILURE);
            }
        }
        // Set socket options and bind to the port
        void setup_socket(){
            int enable = 1;
            if (setsockopt(this->sfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) == -1) {
                std::cerr << "Unable to set socket options due to " << errno << std::endl;
                exit(EXIT_FAILURE);
            }
            if (bind(sfd,(struct sockaddr *) &this->socketAddress, sizeof(this->socketAddress)) == -1) {
                std::cerr << "Binding failed to " << errno << std::endl;
                exit(EXIT_FAILURE);
            }
        }
        int getSfd() const
        {
            return this->sfd;
        }
    private:
        struct sockaddr_in socketAddress;
        int port;
        int sfd;
        
};