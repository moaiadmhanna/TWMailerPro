#include <iostream>
#include <string>
#include <ldap.h>
#include "../Module/socket.cpp"
#include <unistd.h>

class Client
{
    public:
        Client(std::string ip, int port)
        {
            this->ip = ip;
            this->port = port;
            this->socket = new NetworkSocket(ip, port);
        }
        void connect_to_server() {
            struct sockaddr_in serveraddr;
            serveraddr.sin_family = AF_INET;
            serveraddr.sin_port = htons(this->port);
            serveraddr.sin_addr.s_addr = INADDR_ANY;

            int corrispondingsfd = connect(this->socket->getSfd(), (struct sockaddr *)&serveraddr, sizeof(serveraddr));
            if (corrispondingsfd == -1) {
                std::cerr << "Failed to connect to the server" << std::endl;
                exit(EXIT_FAILURE);
            }
        }

        void send_to_socket(std::string message) {
            if (send(socket->getSfd(), message.c_str(), message.length(), 0) == -1) {
                std::cerr << "Failed to send message to the server" << std::endl;
                exit(EXIT_FAILURE);
            }
        }

        void login_to_server(){
            std::string username, password;
            std::cout << "Username: ";
            std::getline(std::cin, username);
            std::cout << "Password: ";
            std::getline(std::cin, password);
            send_to_socket(username);
            send_to_socket(password);
        }
 
        void exchange_messages(){
            while (true) {
                std::cout << "(SEND, LIST, READ, DEL, QUIT): ";
                // std::getline(std::cin, command);

            }
        }
  

    private:
        std::string ip;
        int port;
        std::string buffer;
        NetworkSocket* socket;

};
int main(int argc, char* argv[])
{
    if(argc < 3)
    {
        std::cerr << "Usage:"<< argv[0] << " <ip> <port>" << std::endl;
        exit(1);
    }
    std::string ip = argv[1];
    std::string port = argv[2];
    Client* client = new Client(ip, std::stoi(port));
    client->connect_to_server();
    client->login_to_server();
    client->exchange_messages();
    return 0;
}