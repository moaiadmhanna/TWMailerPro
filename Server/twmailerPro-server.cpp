#include <iostream>
#include <string>
#include <ldap.h>
#include "../Module/socket.cpp"
#include <unistd.h>

class Server
{
    public:
        Server(int port)
        {
            this->port = port;
            this->serverSocket = new NetworkSocket(INADDR_ANY,port);
        }
        void listening()
        {
            if (listen(this->serverSocket->getSfd(), 6) == -1 )
            {
                std::cerr << "Connection could not be established. Socket is unable to accept new connections" << errno << std::endl;
                exit(EXIT_FAILURE);
            }
        }
        void acceptClients()
        {
            while(true)
            {
                int pid;
                std::cout << "Waiting for clients..." << std::endl;
                struct sockaddr_in clientAddr;
                socklen_t clientLen = sizeof(clientAddr);
                int clientSfd = accept(this->serverSocket->getSfd(),(struct sockaddr *) &clientAddr,&clientLen);
                if((pid = fork()) == 0)
                {
                    do
                    {

                    } while(this->buffer != "quit");
                    close(clientSfd);
                }
            }
        }

    private: 
        int port;
        std::string buffer;
        NetworkSocket* serverSocket;

};
int main(int argc, std::string argv[])
{
    if(argc < 2)
    {
        std::cerr << "Usage:"<< argv[0] << "<server_ip> <port>" << std::endl;
        exit(1);
    }
    std::string port = argv[1];
    Server* server = new Server(std::stoi(port));
    server->listening();

}