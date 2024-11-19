#include <iostream>
#include <string>
#include <ldap.h>
class Ldap
{
    public:
        Ldap()
        {
            init_ldap();
        };
       
        int bind_ldap_credentials(char *username, char *password)
        {
            if(ldapHandle == nullptr) init_ldap();

            // Construct LDAP bind user DN
            std::string ldapBindUser = "uid=" + std::string(username) + ",ou=people," + std::string(ldapSearchBase);

            // Set bind credentials
            bindCredentials.bv_val = password;
            bindCredentials.bv_len = strlen(password);
            const char *bindUserCStr = ldapBindUser.c_str();

            // Perform SASL bind operation
            BerValue *servercredp;
            int rc = ldap_sasl_bind_s(ldapHandle,bindUserCStr,LDAP_SASL_SIMPLE,&bindCredentials,NULL,NULL,&servercredp);
            
            // Unbind on failure
            if(rc != LDAP_SUCCESS)
            {
                ldap_unbind_ext(ldapHandle, nullptr, nullptr);
                ldapHandle = nullptr;
            }
            return rc;
        };
        bool valid_user(std::string user)
        {
            // Construct LDAP filter to search for user by uid
            std::string ldapFilter = "(uid=" + user + ")";

            // Perform LDAP search operation
            LDAPMessage *searchResult;
            int rc = ldap_search_ext_s(
                ldapHandle,
                ldapSearchBase,
                ldapSearchScope,
                ldapFilter.c_str(),
                (char **)ldapSearchResultAttributes,
                0,
                NULL,
                NULL,
                NULL,
                5000,
                &searchResult);
            // Get the number of entries in the search result
            int entryCount = ldap_count_entries(ldapHandle, searchResult);

            // Check if search was successful
            if (rc != LDAP_SUCCESS)
            {
                std::cerr << "LDAP search error: " << ldap_err2string(rc) << std::endl;
                return false;
            }
            // Free the search result memory
            ldap_msgfree(searchResult);

            // Return true if there are entries, otherwise false
            return entryCount > 0;

        }

    private:
        // LDAP server URI and configuration
        const char *ldapUri = "ldap://ldap.technikum-wien.at:389";  // URI of the LDAP server
        const int ldapVersion = LDAP_VERSION3;  // LDAP protocol version (v3)
        const char *ldapSearchBase = "dc=technikum-wien,dc=at";  // Base DN for LDAP search
        ber_int_t ldapSearchScope = LDAP_SCOPE_SUBTREE;  // Search scope (subtree search)
        const char *ldapSearchResultAttributes[3] = {"uid", "cn", NULL};  // Attributes to retrieve in search result

        // LDAP bind credentials and handle
        BerValue bindCredentials;  // Stores credentials for LDAP bind
        LDAP *ldapHandle;  // LDAP handle to maintain the session


        void print_error(std::string msg, int errorCode){
            std::cerr << msg << ": " << ldap_err2string(errorCode) << " (" << errorCode << ")" << std::endl;
        }

        void init_ldap(){
            int rc = ldap_initialize(&ldapHandle, ldapUri);
            if(rc != LDAP_SUCCESS)
            {
                print_error("Failed to initialize LDAP connection.", rc);
                exit(EXIT_FAILURE);
            }
            rc = ldap_set_option(ldapHandle,LDAP_OPT_PROTOCOL_VERSION,&ldapVersion);
            if(rc != LDAP_SUCCESS)
            {
                ldap_unbind_ext_s(ldapHandle, NULL, NULL);
                print_error("Failed to set LDAP options.", rc);
                exit(EXIT_FAILURE);
            }
            if(ldap_start_tls_s(ldapHandle,NULL,NULL) != LDAP_SUCCESS)
            {
                ldap_unbind_ext_s(ldapHandle, NULL, NULL);
                print_error("Failed to start LDAP connection.", rc);
                exit(EXIT_FAILURE);
            }
        }
};