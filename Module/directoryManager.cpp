#include <iostream>
#include <dirent.h>
#include <fstream>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <filesystem>
#include <chrono>
#include <ctime>
#include <vector>
#include <filesystem>
#include <string>
namespace fs = std::filesystem;

class DirectoryManager
{
    public:
        DirectoryManager(std::string mail_directory)
        {
            if(!directory_exists(mail_directory))
                mkdir(mail_directory.c_str(),0777);
            this->directory = opendir(mail_directory.c_str());
            this->mailDirectory = mail_directory;
        }
        bool save_message(std::string sender, std::string receiver, std::string subject, std::string messageFull)
        {
            // Create the receiver directory if dont exist
            std::string receiver_path = mailDirectory + "/" + receiver;
            if(!directory_exists(receiver_path))
            {
                mkdir(receiver_path.c_str(),0777);
            }
            DIR * receiverDir = opendir(receiver_path.c_str());
            if(!receiverDir) return false;

            // Create the file path
            std::string file_path = receiver_path + "/" + sender + "-" + subject + ".txt";

            // If file exists, generate a unique filename
            int counter = 1;
            while (file_exists(file_path)) {
                file_path = receiver_path + "/" + sender + "-" + subject + "(" + std::to_string(counter) + ").txt";
                counter++;
            }
            // Open the File to write into
            std::ofstream file(file_path);
            if(file.is_open())
            {
                // Save the sender in the Message
                file << "FROM: " + sender << std::endl;

                // Save the time with the Date
                auto now = std::chrono::system_clock::now();  // Get current time
                auto now_time_t = std::chrono::system_clock::to_time_t(now);  // Convert to time_t
                std::tm tm = *std::localtime(&now_time_t);  // Convert to local time
                file <<"AT: " <<std::put_time(&tm, "%Y-%m-%d %H:%M") << std::endl;
                // Use a stringstream to break the message into lines by newline
                std::stringstream ss(messageFull);
                std::string line ;
                file << "---Message---" << std::endl;
                // Write each line from the message to the file
                while (std::getline(ss, line)) {
                    if(line == ".") continue;
                    file << line << std::endl; // Write the line followed by a newline
                }

                file.close();
            }
            else
                return false;
            return true;
        }
        std::vector<std::string> get_messages(std::string sender) {
            std::vector<std::string> messages;
            std::string client_dir = mailDirectory + "/" + sender;
            DIR* dir = opendir(client_dir.c_str());
            if (dir) {
                for (const auto & entry : fs::directory_iterator(client_dir))
                    messages.push_back(entry.path().filename().string());
                closedir(directory); 
            }
            return messages;
        }
        std::string get_message(std::string sender, size_t  messageNumber)
        {
            auto messages = get_messages(sender);
            if(messageNumber >= messages.size()) return "";
            std::string filePath = mailDirectory + "/" + sender + "/" + messages[messageNumber];
            std::ifstream file(filePath);
            std::string message = "\n\n";
            if(file)
            {
                std::string line;
                while (std::getline(file, line))
                    message += line + "\n";
            }
            return message;
        }
        bool delete_message(std::string sender, size_t  messageNumber)
        {
            auto messages = get_messages(sender);
            if(messageNumber >= messages.size()) return false;
            std::string filename = mailDirectory + "/" + sender + "/" + messages[messageNumber];
            return std::remove(filename.c_str()) == 0;
        }
    private:
        DIR* directory = nullptr;
        std::string mailDirectory;
        bool directory_exists(std::string path)
        {
            DIR* dir = opendir(path.c_str());
            return dir;
        }
        bool file_exists(std::string path)
        {
            struct stat buffer;
            return (stat(path.c_str(), &buffer) == 0);
        }
};