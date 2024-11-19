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
            this->socket->bind_socket();
        }
        void connect_to_server()
        {
            struct sockaddr_in serveraddr;
            serveraddr.sin_family = AF_INET; // Set to IPv4
            serveraddr.sin_port = htons(this->serverPort); // Set the server port
            serveraddr.sin_addr.s_addr = INADDR_ANY; // Set the server address to any available interface

            int corrispondingsfd = connect(this->socket->getSfd(), (struct sockaddr *)&serveraddr, sizeof(serveraddr));
            if (corrispondingsfd == -1) // Check if the connection failed
            {
                std::cerr << "Failed to connect to the server" << std::endl;
                exit(EXIT_FAILURE);
            }
        }

        void start()
        {
            std::cout << "\n" << receive_message() << "\n" << std::endl; // Display the server welcome message
            while (true)
            {
                std::string command;
                std::cout << "(LOGIN, SEND, LIST, READ, DEL, QUIT) >> ";
                if (!std::getline(std::cin, command) || command.empty()) continue; // Get the user's input
                send_to_socket(command); // Send the command to the server
                std::string response = receive_message(); // Get the server's response
                command = to_lower(command);

                // Handle error response
                if(strncmp(response.c_str(), "ERR", 3) == 0) 
                {
                    print_message(response);
                    continue;
                }
                if(command == "quit")
                    print_message(response);
                for (const auto& [name, func] : server_options) { // Check if the command matches any option
                    if (command == name) {
                        func();  // Execute the corresponding function
                        if(command != "list" && command != "quit" ) 
                            print_message(receive_message());
                    }
                }
            }
        }

    private:
        std::string ip;
        int serverPort;
        std::string buffer; // Temporary buffer for storing data
        NetworkSocket* socket;
        const size_t MAX_SUBJECT_LENGTH = 80;

        // Mapping of server commands to their corresponding functions
        std::map<std::string, std::function<void()>> server_options = {
            { "login", [this]() { login_to_server(); }}, // Login to the server
            { "send", [this]() { send_to_server(); }}, // Send message to the server
            { "read", [this]() { message_number_to_server(); }}, // Read a message by number
            { "del", [this]() { message_number_to_server(); }}, // Delete a message by number
            { "list", [this]() { list_to_server(); }}, // List messages from the server
            { "quit", [this]() { exit(0); }} // Exit the program
        };

        void send_to_socket(std::string message)
        {
            uint32_t length = message.size(); // Get the length of the message
            send(socket->getSfd(), &length, sizeof(length), 0); // Send the length first
            send(socket->getSfd(), message.c_str(), length, 0); // Then send the message itself
        }

        void login_to_server()
        {
            
            std::string username;
            std::string password;
            while(true){
               
                // Prompt and read the username
                std::cout << "Username >> ";
                std::getline(std::cin, username);

                // Hide password input
                termios oldt;
                tcgetattr(STDIN_FILENO, &oldt);
                termios newt = oldt;
                newt.c_lflag &= ~ECHO; // Disable echoing input
                tcsetattr(STDIN_FILENO, TCSANOW, &newt);

                // Prompt and read the password
                std::cout << "Password >> ";
                std::getline(std::cin, password);
                std::cout << std::endl;

                // Restore terminal settings to show input again
                tcsetattr(STDIN_FILENO, TCSANOW, &oldt); // Unhide input
                if(!username.empty() && !password.empty())
                    break; // Exit the loop if both are provided
                std::cerr << "ERR: Username or password cannot be blank." << std::endl;
            } 

            send_to_socket(username);
            send_to_socket(password);
            
        }
        void send_to_server()
        {
            std::string receiver;
            // Prompt user for a receiver until a non-empty input is provided
            do{
                std::cout << "Receiver >> ";
            } while (std::getline(std::cin, receiver) && receiver.empty());
            send_to_socket(receiver);

            std::string subject;
            // Ensure the subject is within the maximum length
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
                std::getline(std::cin, message); 
                message_body += message + "\n"; // Append message to body
                if(message == ".") break;  // End when "." is entered
            }
            send_to_socket(message_body);
        }

        bool valid_input_number(std::string command){
            return std::all_of(command.begin(), command.end(), ::isdigit);
        }
        void message_number_to_server(){
            std::string command;
            // Keep prompting until a valid number is entered
            while (true) {
                std::cout << "Message Number >> ";
                if (std::getline(std::cin, command)) {
                    // Check if the command is non-empty and a valid number
                    if (!command.empty() && valid_input_number(command)) {
                        send_to_socket(command);
                        break;
                    }
                }
                std::cerr << "ERR: Please enter a valid number." << std::endl;
            }
        }

        void list_to_server(){
            // Receive the count of messages and display it
            std::string count = receive_message();
            print_message(count + " message" + (count == "1" ? "": "s"));
            int message_counter = 0;

            // Loop through each message and print it with its number
            while (++message_counter <= std::stoi(count)) 
                print_message(std::to_string(message_counter) + ": " + receive_message());
        }

        std::string receive_message() {
            // Receive the message length
            uint32_t length;
            recv(socket->getSfd(), &length, sizeof(length), 0);

            // Allocate memory for the message, including space for null termination
            std::vector<char> buffer(length + 1, 0);

            // Receive and return the received message as a string
            recv(socket->getSfd(), buffer.data(), length, 0);
            return std::string(buffer.data());
        }

        void print_message(std::string message){
            std::cout << "<< " + message << std::endl;
        }
        std::string to_lower(std::string message)
        {
            std::transform(message.begin(), message.end(), message.begin(),
                [](unsigned char c){ return std::tolower(c); }); // Convert each character to lowercase
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
    // Extract IP and port from command line arguments
    std::string ip = argv[1];
    std::string port = argv[2];

    // Establish connection to the server and start communication
    Client* client = new Client(ip, std::stoi(port));
    client->connect_to_server();
    client->start();
    return 0;
}