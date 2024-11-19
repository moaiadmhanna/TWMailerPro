#include <iostream>        
#include <fstream>         
#include <string>          
#include <chrono>          
#include <ctime>           // For time conversion (std::tm, std::localtime, std::mktime)
#include <iomanip>         
#include <vector>          
#include <sstream>         // For std::istringstream to parse strings
#include <cstdlib>         // For std::remove (to delete files)
#include <sys/stat.h>      // For chmod
class BlacklistManager
{
    public:
        BlacklistManager(std::string blacklistFile)
        {
            std::ofstream file(blacklistFile);  // Opens the file, creating it if it doesn't exist
            if (file)
            {
                // header text for structure
                file << "# Blacklist File\n";
                file << "# Ips one per line\n";   
            }
            chmod(blacklistFile.c_str(), 0777);
            this->blackListFile = blacklistFile;
            file.close();
        }
        void const add_user_to_blacklist_file(std::string clientIp,std::chrono::system_clock::time_point time)
        {
            // Open blacklist.txt in append mode
            std::ofstream file(blackListFile, std::ios::app);
            if (file)
            {
                // Convert the time_point to a readable time format
                std::time_t timeFormat = std::chrono::system_clock::to_time_t(time);
                std::tm tm = *std::localtime(&timeFormat);

                // Format the time as "YYYY-MM-DD HH:MM:SS"
                file << clientIp << " - " << std::put_time(&tm, "%Y-%m-%d %H:%M") << "\n";

            }
            // Close the file (optional as ofstream's destructor will close it)
            file.close();
        }
        bool is_user_in_blacklist_file(std::string clientIp)
        {
            std::ifstream file(blackListFile);  // Open the blacklist file in read mode
            if (file)
            {
                std::string line;
                while (std::getline(file, line))
                {
                    // Check if the line starts with the IP address
                    if (line.find(clientIp) != std::string::npos)
                        // If the client IP is found in the line, return true
                        return true;
                }
            }
            // Close the file (optional as ifstream will close automatically on destruction)
            file.close();
            
            // If no match was found, return false
            return false;  
        }
        void const remove_user_from_blacklist_file(std::string clientIp)
        {
            std::ifstream fileIn(blackListFile);
            std::vector<std::string> lines;
            if (fileIn)
            {
                // Read all lines into a vector
                std::string line;
                while (std::getline(fileIn, line)) {
                    if (line.find(clientIp) == std::string::npos)
                        lines.push_back(line);
                }
            }
            fileIn.close();

            // Rewrite the file with only the lines we kept
            std::ofstream fileOut(blackListFile);
            if (fileOut)
            {
                for (const auto& line : lines)
                    fileOut << line << "\n"; 
            }
            fileOut.close();
        }
        std::chrono::system_clock::time_point get_user_timepoint(std::string clientIp)
        {
            std::ifstream file(blackListFile);  // Open the blacklist file in read mode
            if (file)
            {
                std::string line;
                while (std::getline(file, line))
                {
                    // Check if the line contains the client IP
                    if (line.find(clientIp) != std::string::npos)
                    {
                        // Extract the timestamp part from the line
                        size_t pos = line.find(" - ");
                        if (pos != std::string::npos)
                        {
                            std::string timestamp_str = line.substr(pos + 3);  // Get the timestamp part after " - "

                            // Parse the timestamp into a std::tm structure
                            std::tm tm = {};
                            std::istringstream time_stream(timestamp_str);
                            time_stream >> std::get_time(&tm, "%Y-%m-%d %H:%M");
                            if (!time_stream.fail())
                            {
                                // Convert std::tm to std::chrono::system_clock::time_point
                                std::time_t time = std::mktime(&tm);
                                return std::chrono::system_clock::from_time_t(time);
                            }
                        }
                    }
                }
            }
            // Close the file (optional as ifstream will close automatically on destruction)
            file.close();
            
            // If no match was found, return false
            return {};  
        }
    private:
        std::string blackListFile;
};