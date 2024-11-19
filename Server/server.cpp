#include <iostream>
#include <string>
#include "../Module/socket.cpp"
#include "../Module/ldap.cpp"
#include "../Module/directoryManager.cpp"
#include "../Module/blacklistManager.cpp"
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
            this->directoryManager = new DirectoryManager(mail_directory);
            socket->bind_socket();
            this->blacklistManager = new BlacklistManager("blacklist.txt");
        }
        void start()
        {
            listening();
            std::cout << "Waiting for clients..." << std::endl;
            while(true)
            {
                int pid;
                struct sockaddr_in clientAddr;
                socklen_t clientLen = sizeof(clientAddr);
                int clientSfd = accept(this->socket->getSfd(),(struct sockaddr *) &clientAddr,&clientLen);
                if(clientSfd == -1) continue;
                if((pid = fork()) == 0) // Child
                {
                    std::string clientIp = get_client_ip(clientSfd);
                    std::cout << "Client accepted with ID: " << clientSfd << std::endl;
                    send_to_socket(clientSfd, "==== TW-Mailer PRO ====");
                    Ldap *ldapServer = new Ldap();
                    std::string command;
                    while(true)
                    {
                        command = receive_message(clientSfd);
                        if(to_lower(command) == "quit") break;
                        handle_socket(clientSfd, ldapServer, command);
                    };
                    remove_session(clientIp);
                    send_to_socket(clientSfd,"OK: Connection closed successfully.");
                    std::cout << "Client closed with ID: " << clientIp << std::endl;
                    close(clientSfd);
                }
                else if (pid > 0)  // Parent
                    while(waitpid(-1, NULL, WNOHANG) > 0); 
            }
            close(this->socket->getSfd());
        }

    private: 
        int port;
        const static int BUFFER_SIZE = 1024;
        char buffer[BUFFER_SIZE];
        NetworkSocket *socket;
        std::map<std::string, int> loginAttempts;
        std::map<std::string,std::string> sessions;
        const int minutes_in_blacklist = 1;
        const int max_login_attempts = 3;
        DirectoryManager *directoryManager;
        BlacklistManager *blacklistManager;
        const int connections_backlog = 6;
        
        std::map<std::string, std::function<void(int, Ldap*, std::string)>> options = {
            { "login", [this](int clientSfd, Ldap* ldapServer, std::string clientIp) { handle_login(clientSfd, ldapServer, clientIp); }},
            { "send", [this](int clientSfd, Ldap* ldapServer, std::string clientIp) { handle_send(clientSfd, ldapServer, clientIp); }},
            { "read", [this](int clientSfd, Ldap* ldapServer, std::string clientIp) { handle_read(clientSfd, ldapServer, clientIp); }},
            { "del", [this](int clientSfd, Ldap* ldapServer, std::string clientIp) { handle_delete(clientSfd, ldapServer, clientIp); }},
            { "list", [this](int clientSfd, Ldap* ldapServer, std::string clientIp) { handle_list(clientSfd, ldapServer, clientIp); }},
        };

        void listening()
        {
            if (listen(this->socket->getSfd(), connections_backlog) == -1 )
            {
                std::cerr << "Connection could not be established. Socket is unable to accept new connections." << errno << std::endl;
                exit(EXIT_FAILURE);
            }
        }
        std::string get_client_ip(int client_sfd) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);

            if (getpeername(client_sfd, (struct sockaddr *)&client_addr, &addr_len) == 0) {
                char client_ip[INET_ADDRSTRLEN]; 
                inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
                return std::string(client_ip);
            }
            return "Unknown";
        }
        void handle_login(int clientSfd, Ldap* ldapServer, std::string clientIp)
        {
            std::string username = receive_message(clientSfd);
            std::string password = receive_message(clientSfd);
            std::string message = "";
            int rc = ldapServer->bind_ldap_credentials((char*)username.c_str(),(char*) password.c_str());
            int attempts;
            switch(rc){
                case LDAP_INVALID_CREDENTIALS:
                    attempts = get_login_attempts(clientIp);
                    message = "Username or password is wrong. " + (attempts - 1 > 0 ? std::to_string(attempts - 1) + " attempts remaining.":"Try again in " + std::to_string(minutes_in_blacklist) + " min.");
                    add_username_attempts(clientIp);
                    break;
                case LDAP_SUCCESS:
                    send_to_socket(clientSfd, "OK: Login succeeded.");
                    sessions[clientIp] = username;
                    return;
                default:
                    message = "Server error";
            }
            
            send_to_socket(clientSfd, set_error_message(message));
        }

        void handle_send(int clientSfd,Ldap* ldapServer,std::string clientIp)
        {
            std::string senderName = sessions[clientIp];
            std::string receiverName = receive_message(clientSfd);
            std::string subject = receive_message(clientSfd);
            std::string messageBody = receive_message(clientSfd);
            if(!ldapServer->valid_user(receiverName))
                send_to_socket(clientSfd,"ERR: Receiver does not exist.");
            else
                directoryManager->save_message(senderName,receiverName,subject,messageBody) ? send_to_socket(clientSfd,"OK: Message sent successfully.") : send_to_socket(clientSfd,"ERR");

        }
        void handle_list(int clientSfd, Ldap* ldapServer, std::string clientIp){
            std::vector<std::string> messages_list = directoryManager->get_messages(sessions[clientIp]);
            send_to_socket(clientSfd, std::to_string(messages_list.size())); 
            if (messages_list.empty()) return;
            for(auto file: messages_list)
                send_to_socket(clientSfd, file);
        }
        void handle_read(int clientSfd, Ldap* ldapServer, std::string clientIp)
        {
            size_t messageNumber = std::stoi(receive_message(clientSfd)) - 1;
            std::string message_file = directoryManager->get_message(sessions[clientIp],messageNumber);
            if(message_file.empty())
                send_to_socket(clientSfd,"ERR: Message not found.");
            else send_to_socket(clientSfd,message_file);
        }
        void handle_delete(int clientSfd, Ldap* ldapServer, std::string clientIp)
        {
            size_t  messageNumber = std::stoi(receive_message(clientSfd)) - 1;
            bool deleted = directoryManager->delete_message(sessions[clientIp],messageNumber);
            deleted ? send_to_socket(clientSfd, "OK: Message deleted succesfully."): send_to_socket(clientSfd,"ERR: Message not found.");
        }

        void handle_socket(int clientSfd, Ldap* ldapServer, std::string command)
        {
            std::string clientIp = get_client_ip(clientSfd);

            if(is_user_in_blacklist(clientIp) ){
                if(!is_blacklist_expired(clientIp)){
                    std::string message = set_error_message("You are blacklisted. Try again in " + std::to_string(minutes_in_blacklist) + " min.");
                    send_to_socket(clientSfd, message);
                    return;
                }
                remove_from_blacklist(clientIp);
                remove_username_attempts(clientIp);
            }

            command = to_lower(command);
            auto it = options.find(command); // first: name | second: func()
            if (it != options.end()) {
                if (command == "login") {
                    if (is_logged_in(clientIp))
                    {
                        send_to_socket(clientSfd, set_error_message("You are already logged in."));
                        return;
                    } 
                    send_to_socket(clientSfd, "OK");
                    handle_login(clientSfd,ldapServer,clientIp);
                }else if (!is_logged_in(clientIp))
                    send_to_socket(clientSfd, set_error_message("Please log in to continue."));
                else{
                    send_to_socket(clientSfd, "OK");
                    it->second(clientSfd, ldapServer, clientIp); 
                }
            }
            else send_to_socket(clientSfd, set_error_message("Invalid option."));
            
        }
        
        void close_connection(int clientSfd){
            close(clientSfd);
            exit(0);
        }
        
        std::string receive_message(int socketFd) {
            // Empfang der Länge der Nachricht
            uint32_t length;
            recv(socketFd, &length, sizeof(length), 0);

            // Speicher für die Nachricht reservieren
            std::vector<char> buffer(length + 1, 0); // Nullterminierung hinzufügen

            recv(socketFd, buffer.data(), length, 0);
            return std::string(buffer.data());
        }
        
        void send_to_socket(int clientSfd, std::string message)
        {
            uint32_t length = message.size();
            send(clientSfd, &length, sizeof(length), 0);
            send(clientSfd, message.c_str(), length, 0);
        }
        
        void const add_user_to_blacklist(std::string clientIp)
        {
            this->blacklistManager->add_user_to_blacklist_file(clientIp,std::chrono::system_clock::now());   
        }

        bool const is_blacklist_expired(std::string clientIp) {
            auto curr_time = std::chrono::system_clock::now();
            const auto timeout_duration = std::chrono::minutes(minutes_in_blacklist);
            if (this->blacklistManager->is_user_in_blacklist_file(clientIp))
                return curr_time >= this->blacklistManager->get_user_timepoint(clientIp) + timeout_duration;
            return false;  
        }

        bool is_user_in_blacklist(std::string clientIp)
        {
            return this->blacklistManager->is_user_in_blacklist_file(clientIp);
        }

        void remove_from_blacklist(std::string clientIp)
        {
            this->blacklistManager->remove_user_from_blacklist_file(clientIp);
        }

        void add_username_attempts(std::string clientIp){
            auto it = loginAttempts.find(clientIp);
            if (it != loginAttempts.end()){
                if(it->second + 1 < max_login_attempts)
                    it->second++;
                else add_user_to_blacklist(clientIp);
            }
            else
                loginAttempts[clientIp] = 1;
        }

        void remove_username_attempts(std::string clientIp){
            auto it = loginAttempts.find(clientIp);
            if (it != loginAttempts.end())
                loginAttempts.erase(it);
        }

        std::string set_error_message(std::string message)
        {
            return "ERR: " + message;
        }
        std::string to_lower(std::string message)
        {
            std::transform(message.begin(), message.end(), message.begin(),
                [](unsigned char c){ return std::tolower(c); });
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
            if (it != sessions.end())
                sessions.erase(it);
        }

        int get_login_attempts(std::string clientIp){
            auto it = loginAttempts.find(clientIp);
            if (it != loginAttempts.end())
                return max_login_attempts - it->second;
            return max_login_attempts;
        }
};
int main(int argc, char* argv[])
{
    if(argc < 3)
    {
        std::cerr << "Usage: " << argv[0] << " <port> <mail-spool-directoryname>" << std::endl;
        exit(1);
    }
    std::string port = argv[1];
    std::string mailDirectory = argv[2];
    Server* server = new Server(std::stoi(port),mailDirectory);
    server->start();
    return 0;
}