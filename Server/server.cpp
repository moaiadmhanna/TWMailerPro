#include <iostream>
#include <string>
#include "../Module/socket.cpp"
#include "../Module/ldap.cpp"
#include "../Module/directoryManger.cpp"
#include <cstring>
#include <unistd.h>
#include <vector>
#include <chrono>
#include <ctime>
#include <map>
#include <algorithm>
#include <functional>
#include <sys/wait.h>
class Server
{
    public:
        Server(int port, std::string mail_directory)
        {
            this->port = port;
            this->socket = new NetworkSocket(port);
            this->directoryManger = new DirectoryManger(mail_directory);
            socket->bind_socket();
        }
        void start()
        {
            listening(); // Puts the server socket in listening mode
            std::cout << "Waiting for clients..." << std::endl;
            while(true)
            {
                int pid;
                struct sockaddr_in clientAddr;
                socklen_t clientLen = sizeof(clientAddr);

                // Accepts incoming connections and returns a new socket descriptor.
                int clientSfd = accept(this->socket->getSfd(),(struct sockaddr *) &clientAddr,&clientLen);
                if(clientSfd == -1) continue;

                if((pid = fork()) == 0) // Child process to handle the client connection
                {
                    std::string clientIp = get_client_ip(clientSfd); // Retrieve client IP
                    std::cout << "Client accepted with IP: " << clientIp << std::endl;
                    send_to_socket(clientSfd, "==== TW-Mailer PRO ===="); // Welcome message to client
                    Ldap *ldapServer = new Ldap(); // Initialize LDAP for client commands
                    std::string command;

                    // Receive and process client messages.
                    while(true)
                    {
                        command = receive_message(clientSfd); // Client command
                        if(to_lower(command) == "quit") break; // Exit when "quit"
                        handle_socket(clientSfd, ldapServer, command); // Process the command
                    };

                    // Clean up after the session ends.
                    remove_session(clientIp); // Remove session data
                    send_to_socket(clientSfd, "OK: Connection closed successfully."); // Acknowledge closure
                    std::cout << "Client closed with IP: " << clientIp << std::endl;
                    close(clientSfd); // Close the connection
                }
                else if (pid > 0)  // Parent process 
                    while(waitpid(-1, NULL, WNOHANG) > 0);  // Collect terminated child processes to avoid zombies
            }
            close(this->socket->getSfd()); // Close the main server socket on exit
        }

    private: 
        const static int BUFFER_SIZE = 1024;
        char buffer[BUFFER_SIZE];
        struct blacklistFormat {
            std::string ip;
            std::chrono::system_clock::time_point time; // Tracks when the client was blacklisted
        };

        std::vector<blacklistFormat> blacklist; // List of blacklisted IPs with timestamps
        std::map<std::string, int> loginAttempts; // Tracks the number of failed login attempts per IP
        std::map<std::string,std::string> sessions;
        const int minutes_in_blacklist = 1;
        const int max_login_attempts = 3;
        const int connections_backlog = 6;

        int port; // Server's listening port
        NetworkSocket *socket; // Server's network socket
        
        DirectoryManger *directoryManger; // Manages file directories for the application
        std::map<std::string, std::function<void(int, Ldap*, std::string)>> options = {
            { "login", [this](int clientSfd, Ldap* ldapServer, std::string clientIp) { handle_login(clientSfd, ldapServer, clientIp); }},
            { "send", [this](int clientSfd, Ldap* ldapServer, std::string clientIp) { handle_send(clientSfd, ldapServer, clientIp); }},
            { "read", [this](int clientSfd, Ldap* ldapServer, std::string clientIp) { handle_read(clientSfd, ldapServer, clientIp); }},
            { "del", [this](int clientSfd, Ldap* ldapServer, std::string clientIp) { handle_delete(clientSfd, ldapServer, clientIp); }},
            { "list", [this](int clientSfd, Ldap* ldapServer, std::string clientIp) { handle_list(clientSfd, ldapServer, clientIp); }},
        };

        void listening()
        {
            // Puts the server socket into listening mode with a backlog of 6 connections
            if (listen(this->socket->getSfd(), connections_backlog) == -1 )
            {
                std::cerr << "Connection could not be established. Socket is unable to accept new connections." << errno << std::endl;
                exit(EXIT_FAILURE);
            }
        }
        std::string get_client_ip(int client_sfd) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);

            // Retrieves the peer (client) address associated with the socket
            if (getpeername(client_sfd, (struct sockaddr *)&client_addr, &addr_len) == 0) {
                char client_ip[INET_ADDRSTRLEN]; 

                // Converts the client IP from binary to text format
                inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
                return std::string(client_ip);
            }
            return "Unknown"; // Returns Unknown if the IP could not be retrieved
        }
        void handle_login(int clientSfd, Ldap* ldapServer, std::string clientIp)
        {
            // Receive username and password from the client.
            std::string username = receive_message(clientSfd);
            std::string password = receive_message(clientSfd);

            // Attempt to bind LDAP credentials
            int rc = ldapServer->bind_ldap_credentials((char*)username.c_str(),(char*) password.c_str());
            int attempts;
            std::string message = "";
            switch(rc){
                case LDAP_INVALID_CREDENTIALS:
                    // Invalid credentials, increment login attempts
                    attempts = get_login_attempts(clientIp);
                    message = "Username or password is wrong. " + (attempts - 1 > 0 ? std::to_string(attempts - 1) + " attempts remaining.":"Try again in " + std::to_string(minutes_in_blacklist) + " min.");
                    add_username_attempts(clientIp);
                    break;
                case LDAP_SUCCESS:
                    // Successful login
                    send_to_socket(clientSfd, "OK: Login succeeded.");
                    sessions[clientIp] = username;
                    return;
                default:
                    message = "Server error";
            }
            // Send error message to client
            send_to_socket(clientSfd, set_error_message(message));
        }

        void handle_send(int clientSfd,Ldap* ldapServer,std::string clientIp)
        {
            // Get sender's username from the session
            std::string senderName = sessions[clientIp];

            // Receive receiver's username, subject, and message body from the client
            std::string receiverName = receive_message(clientSfd);
            std::string subject = receive_message(clientSfd);
            std::string messageBody = receive_message(clientSfd);

            // Check if the receiver exists in the LDAP server
            if(!ldapServer->valid_user(receiverName))
                send_to_socket(clientSfd,"ERR: Receiver does not exist.");
            else{
                bool success = directoryManger->save_message(senderName, receiverName, subject, messageBody);
                if (success)
                    send_to_socket(clientSfd, "OK: Message sent successfully.");
                else 
                    send_to_socket(clientSfd, "ERR: Message failed to send."); // Error saving the message
            }
        }
        void handle_list(int clientSfd, Ldap* ldapServer, std::string clientIp){
            // Get the list of messages for the current user (from the session)
            std::vector<std::string> messages_list = directoryManger->get_messages(sessions[clientIp]);

            // Send the number of messages to the client
            send_to_socket(clientSfd, std::to_string(messages_list.size())); 
            if (messages_list.empty()) return;

            // Send each message filename to the socket
            for(auto file: messages_list)
                send_to_socket(clientSfd, file);
        }
        void handle_read(int clientSfd, Ldap* ldapServer, std::string clientIp)
        {
            size_t messageNumber = std::stoi(receive_message(clientSfd)) - 1;

            // Retrieve the requested message from the directory manager
            std::string message_file = directoryManger->get_message(sessions[clientIp],messageNumber);

            if(message_file.empty())
                send_to_socket(clientSfd, "ERR: Message not found.");
            else send_to_socket(clientSfd, message_file); // If the message exists, send it to the client
        }
        void handle_delete(int clientSfd, Ldap* ldapServer, std::string clientIp)
        {
            size_t  messageNumber = std::stoi(receive_message(clientSfd)) - 1; // Adjust to 0-based indexing
            bool deleted = directoryManger->delete_message(sessions[clientIp],messageNumber);  // Attempt to delete the message

            // Send appropriate response
            deleted ? send_to_socket(clientSfd, "OK: Message deleted succesfully."): send_to_socket(clientSfd,"ERR: Message not found.");
        }

        void handle_socket(int clientSfd, Ldap* ldapServer, std::string command)
        {
            std::string clientIp = get_client_ip(clientSfd); // Retrieve client's IP address

            if(is_user_in_blacklist(clientIp) ){
                if(!is_blacklist_expired(clientIp)){
                    std::string message = set_error_message("You are blacklisted. Try again in " + std::to_string(minutes_in_blacklist) + " min.");
                    send_to_socket(clientSfd, message); // Notify the user they are blacklisted
                    return;
                }
                remove_from_blacklist(clientIp); // Remove user from blacklist if expired
                remove_username_attempts(clientIp); // Reset login attempts
            }

            command = to_lower(command);
            auto it = options.find(command);// Find the command in available options  // first: name | second: func() 
            if (it != options.end()) { // If command is valid
                if (command == "login") {
                    if (is_logged_in(clientIp)) // Check if user is already logged in
                    {
                        send_to_socket(clientSfd, set_error_message("You are already logged in."));
                        return;
                    } 
                    send_to_socket(clientSfd, "OK");
                    handle_login(clientSfd,ldapServer,clientIp);
                } else if (!is_logged_in(clientIp)) // If user is not logged in
                    send_to_socket(clientSfd, set_error_message("Please log in to continue."));
                else{
                    send_to_socket(clientSfd, "OK");
                    it->second(clientSfd, ldapServer, clientIp); 
                }
            }
            else send_to_socket(clientSfd, set_error_message("Invalid option."));
            
        }
        
        void close_connection(int clientSfd){
            close(clientSfd); // Close the client socket
            exit(0);
        }
        
        std::string receive_message(int socketFd) {
            // Receive the length of the message
            uint32_t length;
            recv(socketFd, &length, sizeof(length), 0);

            // Allocate buffer for the message (including space for null terminator)
            std::vector<char> buffer(length + 1, 0); 

            // Receive and return the actual message
            recv(socketFd, buffer.data(), length, 0);
            return std::string(buffer.data());
        }
        
        void send_to_socket(int clientSfd, std::string message)
        {
            uint32_t length = message.size(); // Get the length of the message
            send(clientSfd, &length, sizeof(length), 0); // Send the length first
            send(clientSfd, message.c_str(), length, 0); // Then send the message itself
        }
        
        void const add_user_to_blacklist(std::string clientIp)
        {
            // Add user to blacklist according to its format
            blacklistFormat client;
            client.ip = clientIp;
            client.time = std::chrono::system_clock::now();
            blacklist.push_back(client);
        }

        bool const is_blacklist_expired(const std::string& clientIp) {
            auto curr_time = std::chrono::system_clock::now(); // Current time
            const auto timeout_duration = std::chrono::minutes(minutes_in_blacklist);

            for (const auto& entry : blacklist) {
                if (entry.ip == clientIp)
                    return curr_time >= entry.time + timeout_duration; // Check if the blacklist time has expired
            }
            return false;  // if the IP is not found
        }

        std::string set_error_message(std::string message){
            return "ERR: " + message;
        }

        bool is_user_in_blacklist(std::string clientIp){
            for (auto& entry : blacklist) {
                if (entry.ip == clientIp)
                    return true; // IP is in blacklist
            }
            return false; // IP is not in blacklist
        }

        void remove_from_blacklist(const std::string& clientIp) {
            for (auto it = blacklist.begin(); it != blacklist.end(); ) {
                if (it->ip == clientIp) {
                    blacklist.erase(it);
                    return;
                } 
                else
                    ++it;
            }
        }

        void add_username_attempts(std::string clientIp){
            auto it = loginAttempts.find(clientIp);
            if (it != loginAttempts.end()){ // If the client IP is found
                if(it->second + 1 < max_login_attempts)
                    it->second++; // Increment the login attempts count
                else add_user_to_blacklist(clientIp); // If max attempts reached, blacklist the user
            }
            else
                loginAttempts[clientIp] = 1; // If client IP is not found, start counting from 1
        }

        void remove_username_attempts(std::string clientIp){
            auto it = loginAttempts.find(clientIp);
            if (it != loginAttempts.end()) // If the client IP is found
                loginAttempts.erase(it);
        }
        
        std::string to_lower(std::string message)
        {
            std::transform(message.begin(), message.end(), message.begin(),
                [](unsigned char c){ return std::tolower(c); }); // Convert each character to lowercase
            return message;
        }
        
        bool is_logged_in(std::string clientIp)
        {
            auto it = sessions.find(clientIp);
            return it != sessions.end();
        }

        void remove_session(std::string clientIp)
        {
            auto it = sessions.find(clientIp);
            if (it != sessions.end()) // Remove session if Client IP is found
                sessions.erase(it);
        }

        int get_login_attempts(std::string clientIp){
            auto it = loginAttempts.find(clientIp);
            if (it != loginAttempts.end()) // If client has attempted to log in
                return max_login_attempts - it->second; // Return remaining attempts
            return max_login_attempts; // If no attempts, return the max allowed attempts
        }
};
int main(int argc, char* argv[])
{
    if(argc < 3)
    {
        std::cerr << "Usage: " << argv[0] << " <port> <mail-spool-directoryname>" << std::endl;
        exit(1);
    }
    
    // Extract port and Mail directory from command line arguments
    std::string port = argv[1];
    std::string mailDirectory = argv[2];

    Server* server = new Server(std::stoi(port),mailDirectory);
    server->start(); // Start the server
    return 0;
}