#include <iostream>
#include <string>
#include <ldap.h>
#include "../Module/socket.cpp"
#include <unistd.h>
#include <termios.h>
#include <vector>
#include <algorithm>
#include <functional>
#include <map>

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
            while(true){
               
                // Username
                std::cout << "Username >> ";
                std::getline(std::cin, username);

                // Hide input
                termios oldt;
                tcgetattr(STDIN_FILENO, &oldt);
                termios newt = oldt;
                newt.c_lflag &= ~ECHO;
                tcsetattr(STDIN_FILENO, TCSANOW, &newt);

                // Password
                std::cout << "Password >> ";
                std::getline(std::cin, password);
                std::cout << std::endl;
                tcsetattr(STDIN_FILENO, TCSANOW, &oldt); // Unhide input
                if(!username.empty() && !password.empty())
                    break;
                std::cerr << "ERR: Username or password cannot be blank." << std::endl;
            } 

            send_to_socket(username);
            send_to_socket(password);
            
        }
        void send_to_server()
        {
            std::string receiver;
            do{
                std::cout << "Receiver >> ";
            } while (std::getline(std::cin, receiver) && receiver.empty());
            send_to_socket(receiver);

            std::string subject;
            while(true){
                std::cout << "Subject (max 80 characters) >> ";
                std::getline(std::cin, subject);
                if(subject.length() <= MAX_SUBJECT_LENGTH)
                    break;
                std::cerr << "ERR: Subject must be no longer than " << MAX_SUBJECT_LENGTH << " characters." << std::endl;
            }
            send_to_socket(subject);

            // Continue sending message body until user inputs "."
            std::string message_body;
            while(true) {
                std::cout << "Message (. to SEND) >> ";
                std::string message;
                std::getline(std::cin, message);  // Send input
                message_body += message + "\n";
                if(message == ".") break;  // End when "." is entered
            }
            send_to_socket(message_body);
        }

        bool valid_input_number(std::string command){
            return std::all_of(command.begin(), command.end(), ::isdigit);
        }
        void message_number_to_server(){
            std::string command;
            while (true) {
                std::cout << "Message Number >> ";
                if (std::getline(std::cin, command)) {
                    if (!command.empty() && valid_input_number(command)) {
                        send_to_socket(command);
                        break;
                    }
                }
                std::cerr << "ERR: Please enter a valid number." << std::endl;
            }
        }

        void list_to_server(){
            std::string count = receive_message();
            print_message(count + " message" + (count == "1" ? "": "s"));
            int message_counter = 0;
            while (++message_counter <= std::stoi(count)) 
                print_message(std::to_string(message_counter) + ": " + receive_message());
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

        void print_message(std::string message){
            std::cout << "<< " + message << std::endl;
        }

        void start()
        {
            while (true)
            {
                std::string command;
                std::cout << "(LOGIN, SEND, LIST, READ, DEL, QUIT) >> ";
                if (!std::getline(std::cin, command) || command.empty()) continue;
                send_to_socket(command);
                std::string response = receive_message();
                command = to_lower(command);

                if(strncmp(response.c_str(), "ERR", 3) == 0)
                {
                    print_message(response);
                    continue;
                }
                for (const auto& [name, func] : server_commands) {
                    if (command == name) {
                        func(); 
                        if(command != "list" && command != "quit" ) 
                            print_message(receive_message());
                    }
                }
            }
        }

    private:
        std::string ip;
        int serverPort;
        std::string buffer;
        NetworkSocket* socket;
        const size_t MAX_SUBJECT_LENGTH = 80;
        std::map<std::string, std::function<void()>> server_commands = {
            { "login", [this]() { login_to_server(); }},
            { "send", [this]() { send_to_server(); }},
            { "read",  [this]() { message_number_to_server(); }},
            { "del", [this]() { message_number_to_server(); }},
            { "list", [this]() { list_to_server(); }},
            { "quit", [this](){ exit(0); }}
        };

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
    client->start();
    return 0;
}