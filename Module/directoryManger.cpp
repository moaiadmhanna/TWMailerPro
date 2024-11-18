#include <iostream>
#include <dirent.h>
#include <fstream>
#include <sys/types.h>
#include <sys/stat.h>
class DirectoryManger
{
    public:
        DirectoryManger(std::string mail_directory)
        {
            if(!directory_exists(mail_directory))
                mkdir(mail_directory.c_str(),0777);
            this->directory = opendir(mail_directory.c_str());
        }
        void save_message(std::string sender, std::string receiver, std::string subject, std::string messageFull)
        {
            
        }
    private:
        DIR* directory = nullptr;
        bool directory_exists(std::string path)
        {
            DIR* dir = opendir(path.c_str());
            return dir;
        }
};