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
                    do
                    {
                        command = receive_message(clientSfd);
                        handleClient(clientSfd, ldapServer, command);
                    } while(command != "QUIT");
                    std::cout << "Client closed with ID: " << clientSfd << std::endl;
                    close(clientSfd);
                }
            }
            close(this->socket->getSfd());
        }

        

        void loginClient(int clientSfd, Ldap* ldapServer)
        {
            std::string username = receive_message(clientSfd);
            std::string password = receive_message(clientSfd);
            std::string message = "";
            if(is_user_in_blacklist(username) ){
                if(!is_blacklist_expired(username)){
                    message = set_error_message(username + " on blacklist. Try again in " + std::to_string(minutes_in_blacklist) + " min.");
                    send_to_socket(clientSfd, message);
                    return;
                }
                remove_from_blacklist(username);
                remove_username_attempts(username);
                
            }
            int rc = ldapServer->bind_ldap_credentials((char*)username.c_str(),(char*) password.c_str());
            std::cerr << "msg" << ": " << ldap_err2string(rc) << " (" << rc << ")" << std::endl;
            switch(rc){
                case LDAP_INVALID_CREDENTIALS:
                    message = "Username or password is wrong.";
                    break;
                case LDAP_SUCCESS:
                    send_to_socket(clientSfd, "OK: Login succeeded.");
                    return;
                default:
                    message = "Server error";
            }
            add_username_attempts(username);
            send_to_socket(clientSfd, set_error_message(message));
        }

        void handleClient(int clientSfd, Ldap* ldapServer, std::string command)
        {
            // std::cout << command << std::endl;
            if(command == "LOGIN" || command == "Login" || command == "login")
            {
                loginClient(clientSfd, ldapServer);
            }
        }

    private: 

        struct blacklistFormat {
            std::string name;
            std::chrono::system_clock::time_point time;
        };
        int port;
        const static int BUFFER_SIZE = 1024;
        char buffer[BUFFER_SIZE];
        NetworkSocket *socket;
        std::vector<blacklistFormat> blacklist;
        std::map<std::string, int> usernameAttempts;
        int minutes_in_blacklist = 20;

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
        void const add_user_to_blacklist(std::string username)
        {
            blacklistFormat user;
            user.name = username;
            user.time = std::chrono::system_clock::now();
            blacklist.push_back(user);
        }

        bool const is_blacklist_expired(const std::string& username) {
            auto curr_time = std::chrono::system_clock::now();
            const auto timeout_duration = std::chrono::seconds(minutes_in_blacklist);

            for (const auto& entry : blacklist) {
                if (entry.name == username) {
                    return curr_time >= entry.time + timeout_duration;
                }
            }
            return false;  
        }

        std::string set_error_message(std::string message){
            return "ERR: " + message;
        }

        bool is_user_in_blacklist(std::string username){
            for (auto& entry : blacklist) {
                if (entry.name == username) {
                    return true;
                }
            }
            return false;
        }

        void remove_from_blacklist(const std::string& username) {
            for (auto it = blacklist.begin(); it != blacklist.end(); ) {
                if (it->name == username) {
                    it = blacklist.erase(it);
                } else {
                    ++it;
                }
            }
        }

        void add_username_attempts(std::string username){
            auto it = usernameAttempts.find(username);
            if (it != usernameAttempts.end()){
                if(it->second + 1 == 3)
                    add_user_to_blacklist(username);
                else it->second++;
            }
            else
                usernameAttempts[username] = 1;
        }

        void remove_username_attempts(std::string username){
            auto it = usernameAttempts.find(username);
            if (it != usernameAttempts.end()) {
                usernameAttempts.erase(it);
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