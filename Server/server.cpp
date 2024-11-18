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
        void listening()
        {
            if (listen(this->socket->getSfd(), 6) == -1 )
            {
                std::cerr << "Connection could not be established. Socket is unable to accept new connections" << errno << std::endl;
                exit(EXIT_FAILURE);
            }
        }
        void accept_clients()
        {
            std::cout << "Waiting for clients..." << std::endl;
            while(true)
            {
                int pid;
                struct sockaddr_in clientAddr;
                socklen_t clientLen = sizeof(clientAddr);
                int clientSfd = accept(this->socket->getSfd(),(struct sockaddr *) &clientAddr,&clientLen);
                if(clientSfd == -1) continue;
                if((pid = fork()) == 0)
                {
                    std::string clientIp = get_client_ip(clientSfd);
                    std::cout << "Client accepted with ID: " << clientSfd << std::endl;
                    Ldap *ldapServer = new Ldap();
                    std::string command;
                    while(true)
                    {
                        command = receive_message(clientSfd);
                        if(to_lower(command) == "quit") break;
                        handle_client(clientSfd, ldapServer, command);
                    };
                    remove_session(clientIp);
                    send_to_socket(clientSfd,"OK: Connection closed successfully.");
                    std::cout << "Client closed with ID: " << clientIp << std::endl;
                    close(clientSfd);
                }
            }
            close(this->socket->getSfd());
        }

    private: 

        struct blacklistFormat {
            std::string ip;
            std::chrono::system_clock::time_point time;
        };
        int port;
        const static int BUFFER_SIZE = 1024;
        char buffer[BUFFER_SIZE];
        NetworkSocket *socket;
        std::vector<blacklistFormat> blacklist;
        std::map<std::string, int> loginAttempts;
        std::map<std::string,std::string> sessions;
        const int minutes_in_blacklist = 1;
        const int max_login_attempts = 3;
        DirectoryManger *directoryManger;

        std::string get_client_ip(int client_sfd) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);

            if (getpeername(client_sfd, (struct sockaddr *)&client_addr, &addr_len) == 0) {
                char client_ip[INET_ADDRSTRLEN]; 
                inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
                return std::string(client_ip);
            }
            return nullptr;
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

        void handle_send(int clientSfd,std::string clientIp)
        {
            std::string senderName = sessions[clientIp];
            std::string receiverName = receive_message(clientSfd);
            std::string subject = receive_message(clientSfd);
            std::string messageBody = receive_message(clientSfd);

        }
        void handle_list(int clientSfd, std::string clientIp){
            std::vector<std::string> messages_list = directoryManger->get_messages(sessions[clientIp]);
            send_to_socket(clientSfd, std::to_string(messages_list.size())); 
            if (messages_list.empty()) return;
            for(auto file: messages_list){
                send_to_socket(clientSfd, file);
            }
        }

        void handle_client(int clientSfd, Ldap* ldapServer, std::string command)
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
            if (command == "login") {
                if (is_logged_in(clientIp))
                {
                    send_to_socket(clientSfd, set_error_message("You are already logged in"));
                    return;
                } 
                send_to_socket(clientSfd, "OK");
                handle_login(clientSfd,ldapServer,clientIp);
            } 
            else if (!is_logged_in(clientIp))
                send_to_socket(clientSfd, set_error_message("You need to login"));
            else if(command == "send")
            {  
                send_to_socket(clientSfd, "OK");
                handle_send(clientSfd,clientIp);
            }
            else if(command == "list"){
                send_to_socket(clientSfd, "OK");
                handle_list(clientSfd,clientIp);
            }
            else
            {
                send_to_socket(clientSfd, set_error_message("Invalid Input!"));
            }
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
            blacklistFormat client;
            client.ip = clientIp;
            client.time = std::chrono::system_clock::now();
            blacklist.push_back(client);
        }

        bool const is_blacklist_expired(const std::string& clientIp) {
            auto curr_time = std::chrono::system_clock::now();
            const auto timeout_duration = std::chrono::minutes(minutes_in_blacklist);

            for (const auto& entry : blacklist) {
                if (entry.ip == clientIp) {
                    return curr_time >= entry.time + timeout_duration;
                }
            }
            return false;  
        }

        std::string set_error_message(std::string message){
            return "ERR: " + message;
        }

        bool is_user_in_blacklist(std::string clientIp){
            for (auto& entry : blacklist) {
                if (entry.ip == clientIp) {
                    return true;
                }
            }
            return false;
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
            if (it != loginAttempts.end()) {
                loginAttempts.erase(it);
            }
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
            if (it != sessions.end()) {
                sessions.erase(it);
            }
        }

        int get_login_attempts(std::string clientIp){
            auto it = loginAttempts.find(clientIp);
            if (it != loginAttempts.end()) {
                return max_login_attempts - it->second;
            }
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
    server->listening();
    server->accept_clients();
    return 0;
}