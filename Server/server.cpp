#include <iostream>
#include <string>
#include "../Module/socket.cpp"
#include "../Module/ldap.cpp"
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
        Server(int port)
        {
            this->port = port;
            this->socket = new NetworkSocket(port);
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
        void acceptClients()
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
                    std::cout << "Client accepted with ID: " << clientSfd << std::endl;
                    Ldap *ldapServer = new Ldap();
                    std::string command;
                    while(true)
                    {
                        command = receive_message(clientSfd);
                        if(to_lower(command) == "quit") break;
                        handleClient(clientSfd, ldapServer, command);
                    };
                    remove_session(get_client_ip(clientSfd));
                    send_to_socket(clientSfd,"OK: Connection closed successfully.");
                    std::cout << "Client closed with ID: " << get_client_ip(clientSfd) << std::endl;
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
        std::map<std::string, int> usernameAttempts;
        std::map<std::string, int> sessions;
        int minutes_in_blacklist = 20;

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
        void loginClient(int clientSfd, Ldap* ldapServer)
        {
            std::string clientIp = get_client_ip(clientSfd);
            std::string username = receive_message(clientSfd);
            std::string password = receive_message(clientSfd);
            std::string message = "";
            int rc = ldapServer->bind_ldap_credentials((char*)username.c_str(),(char*) password.c_str());
            switch(rc){
                case LDAP_INVALID_CREDENTIALS:
                    message = "Username or password is wrong.";
                    break;
                case LDAP_SUCCESS:
                    send_to_socket(clientSfd, "OK: Login succeeded.");
                    sessions[clientIp] = clientSfd;
                    return;
                default:
                    message = "Server error";
            }
            add_username_attempts(clientIp);
            send_to_socket(clientSfd, set_error_message(message));
        }

        void handleClient(int clientSfd, Ldap* ldapServer, std::string command)
        {
            std::string clientIp = get_client_ip(clientSfd);
            if(is_user_in_blacklist(clientIp) ){
                if(!is_blacklist_expired(clientIp)){
                    std::string message = set_error_message("You are on blacklist. Try again in " + std::to_string(minutes_in_blacklist) + " min.");
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
                loginClient(clientSfd, ldapServer);
            } 
            else if (!is_logged_in(clientIp))
                send_to_socket(clientSfd, set_error_message("You need to login"));
            else if(command == "read")
            {
                
                send_to_socket(clientSfd, "OK");
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
            const auto timeout_duration = std::chrono::seconds(minutes_in_blacklist);

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
                } else {
                    ++it;
                }
            }
        }

        void add_username_attempts(std::string clientIp){
            auto it = usernameAttempts.find(clientIp);
            if (it != usernameAttempts.end()){
                if(it->second + 1 == 3)
                    add_user_to_blacklist(clientIp);
                else it->second++;
            }
            else
                usernameAttempts[clientIp] = 1;
        }

        void remove_username_attempts(std::string clientIp){
            auto it = usernameAttempts.find(clientIp);
            if (it != usernameAttempts.end()) {
                usernameAttempts.erase(it);
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
};
int main(int argc, char* argv[])
{
    if(argc < 3)
    {
        std::cerr << "Usage: " << argv[0] << " <port> <mail-spool-directoryname>" << std::endl;
        exit(1);
    }
    std::string port = argv[1];
    Server* server = new Server(std::stoi(port));
    server->listening();
    server->acceptClients();
    return 0;
}