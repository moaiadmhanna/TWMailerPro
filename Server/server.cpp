#include <iostream>
#include <string>
#include <ldap.h>
#include "../Module/socket.cpp"
#include <cstring>
#include <unistd.h>

class Server
{
    public:
        Server(int port)
        {
            this->port = port;
            this->socket = new NetworkSocket(port);
            socket->bind_socket();
            init_ldap();
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
                    loginClient(clientSfd);
                    do
                    {
                        handleClient(clientSfd);
                    } while(strncmp(buffer, "quit", 4) == 0);
                    close(clientSfd);
                }
            }
            close(this->socket->getSfd());
        }

        void loginClient(int clientSfd){
            char *username = receive_message(clientSfd);
            std::cout << "Username: " << username << std::endl;
            char *password = receive_message(clientSfd);
            std::cout << "Password: " << password << std::endl;
        }

        void handleClient(int clientSfd) {
            char *message = receive_message(clientSfd);
            std::cout << "Received message: " << message << std::endl;
        }

    private: 
        int port;
        const static int BUFFER_SIZE = 1024;
        char buffer[BUFFER_SIZE];
        NetworkSocket* socket;
        LDAP *ldapServer;
        const char *ldaphost = "ldap.technikum.wien.at";
        const int ldapport = 389;

        char * receive_message(int clientSfd){
            std::memset(buffer, 0, BUFFER_SIZE);
            int bytes_received = recv(clientSfd, buffer, BUFFER_SIZE, 0);
            if (bytes_received == -1) {
                std::cerr << "Failed to receive message from client" << std::endl;
                exit(EXIT_FAILURE);
            } else if (bytes_received == 0) {
                std::cout << "Client disconnected." << std::endl;
                close(clientSfd);
            }
            buffer[bytes_received] = '\0';
            return buffer;
        } 
        void init_ldap(){
            LDAP* ldapServer;
            const char* ldaphost = "ldap.technikum.wien.at"; // Replace with your LDAP server address
            int ldapport = 389;

            if (ldap_initialize(&ldapServer, ldaphost) != LDAP_SUCCESS) {
                std::cerr << "Failed to initialize LDAP connection." << std::endl;
                exit(EXIT_FAILURE);
            }
        }
};
int main(int argc, char* argv[])
{
    if(argc < 3)
    {
        std::cerr << "Usage:"<< argv[0] << " <port> <mail-spool-directoryname>" << std::endl;
        exit(1);
    }
    std::string port = argv[1];
    Server* server = new Server(std::stoi(port));
    server->listening();
    server->acceptClients();
    return 0;
}