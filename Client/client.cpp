#include <iostream>
#include <string>
#include <ldap.h>
#include "../Module/socket.cpp"
#include <unistd.h>
#include <termios.h>
#include <vector>

class Client
{
    public:
        Client(std::string ip, int port)
        {
            this->ip = ip;
            this->port = port;
            this->socket = new NetworkSocket(ip, port);
        }
        void connect_to_server()
        {
            struct sockaddr_in serveraddr;
            serveraddr.sin_family = AF_INET;
            serveraddr.sin_port = htons(this->port);
            serveraddr.sin_addr.s_addr = INADDR_ANY;

            int corrispondingsfd = connect(this->socket->getSfd(), (struct sockaddr *)&serveraddr, sizeof(serveraddr));
            if (corrispondingsfd == -1)
            {
                std::cerr << "Failed to connect to the server" << std::endl;
                exit(EXIT_FAILURE);
            }
        }

        void send_to_socket(std::string message)
        {
            uint32_t length = message.size();
            send(socket->getSfd(), &length, sizeof(length), 0);
            send(socket->getSfd(), message.c_str(), length, 0);
        }

        void login_to_server()
        {
            std::string rc;
            while(true){
                std::string username;
                std::string password;
                std::cout << "Username: ";
                std::getline(std::cin, username);

                termios oldt;
                tcgetattr(STDIN_FILENO, &oldt);
                termios newt = oldt;
                newt.c_lflag &= ~ECHO;
                tcsetattr(STDIN_FILENO, TCSANOW, &newt);
                std::cout << "Password: ";
                std::getline(std::cin, password);
                std::cout << std::endl;
                tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

                send_to_socket(username);
                send_to_socket(password);
                if(receive_message() == "0") break;
            }
            std::cout << "Success!" << std::endl;
        }

        std::string receive_message() {
            // Empfang der Länge der Nachricht
            uint32_t length;
            recv(socket->getSfd(), &length, sizeof(length), 0);

            // Speicher für die Nachricht reservieren
            std::vector<char> buffer(length + 1, 0); // Nullterminierung hinzufügen

            recv(socket->getSfd(), buffer.data(), length, 0);
            return std::string(buffer.data());
        }
 
        void exchange_messages()
        {
            // while (true)
            // {
                std::cout << "(SEND, LIST, READ, DEL, QUIT): ";
                // std::getline(std::cin, command);
            // }
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