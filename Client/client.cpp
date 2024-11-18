#include <iostream>
#include <string>
#include <ldap.h>
#include "../Module/socket.cpp"
#include <unistd.h>
#include <termios.h>
#include <vector>
#include <algorithm>

class Client
{
    public:
        Client(std::string ip, int port)
        {
            this->ip = ip;
            this->serverPort = port;
            this->socket = new NetworkSocket(ip, 0);
        }
        void connect_to_server()
        {
            struct sockaddr_in serveraddr;
            serveraddr.sin_family = AF_INET;
            serveraddr.sin_port = htons(this->serverPort);
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
            
        }
        void send_to_server()
        {
            std::string command;
            std::cout << "Receiver >>";
            std::getline(std::cin, command);
            send_to_socket(command);
            std::cout << "Subject >>";
            std::getline(std::cin, command);
            send_to_socket(command);
             // Continue sending message body until user inputs "."
            std::string message_body;
            while(1) {
                std::cout << "Message (. to SEND) >>";
                std::getline(std::cin, command);  // Send input
                message_body += command + "\n";
                if(!command.empty() && command[command.length() - 1] == '.') break;  // End when "." is entered
            }
            send_to_socket(message_body);
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
            while (true)
            {
                std::string command;
                std::cout << "(LOGIN, SEND, LIST, READ, DEL, QUIT): ";
                std::getline(std::cin, command);
                send_to_socket(command);
                std::string response = receive_message();
                command = to_lower(command);
                if(strncmp(response.c_str(),"ERR",3) == 0)
                {
                    std::cout << response << std::endl;
                    continue;
                }
                if(command == "login")
                {
                    login_to_server();
                    std::cout << receive_message() << std::endl;
                }
                else if(command == "send")
                {
                    send_to_server();
                    std::cout << receive_message() << std::endl;
                }
                else if(command == "quit")
                {
                    exit(0);
                }
            }
        }

    private:
        std::string ip;
        int serverPort;
        std::string buffer;
        NetworkSocket* socket;

        std::string to_lower(std::string message)
        {
            std::transform(message.begin(), message.end(), message.begin(),
                [](unsigned char c){ return std::tolower(c); });
            return message;
        }
      

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
    client->exchange_messages();
    return 0;
}