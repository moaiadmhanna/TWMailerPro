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
                    do
                    {
                        std::cout << "AM going to run handleclient" << std::endl; 
                        std::cout << "HELLO ITS ME" << std::endl;
                        //handleClient(clientSfd, ldapServer);
                    } while(strncmp(buffer, "quit", 4) == 0);
                    close(clientSfd);
                }
            }
            close(this->socket->getSfd());
        }

        bool is_user_in_blacklist(std::string username){
            for (auto& entry : blacklist) {
                if (entry.name == username) {
                    return true;
                }
            }
            return false;
        }

        void loginClient(int clientSfd, Ldap* ldapServer)
        {
            std::string username = receive_message(clientSfd);
            std::string password = receive_message(clientSfd);
            if(is_user_in_blacklist(username)){
                std::cout << username << " is currently in the blacklist" << std::endl;
                send_to_socket(clientSfd, "ERR");
                return;
            }
            int rc = ldapServer->bind_ldap_credentials((char*)username.c_str(),(char*) password.c_str());
            switch(rc){
                case LDAP_INVALID_CREDENTIALS:
                    std::cerr << "Login failed: Username or password is wrong." << std::endl;
                    break;
                case LDAP_SUCCESS:
                    std::cout << "Login succeeded." << std::endl;
                    send_to_socket(clientSfd, "OK");
                    return;
                default:
                    std::cerr << "Login failed: Server error" << std::endl;
            }
            auto it = usernameAttempts.find(username);
            if (it != usernameAttempts.end()){
                if(it->second == 3)
                    add_user_to_blacklist(username);
                else it->second++;
            }
            else 
                usernameAttempts[username] = 1;
                
            send_to_socket(clientSfd, "ERR");
        }

        void handleClient(int clientSfd, Ldap* ldapServer)
        {
            std::string message = receive_message(clientSfd);
            std::cout << message << std::endl;
            if(message == "LOGIN")
            {
                std::cout << "here" << std::endl;
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