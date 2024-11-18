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
            std::string ldapBindUser = "uid=" + std::string(username) + ",ou=people," + std::string(ldapSearchBase);
            bindCredentials.bv_val = password;
            bindCredentials.bv_len = strlen(password);
            const char *bindUserCStr = ldapBindUser.c_str();

            BerValue *servercredp;
            int rc = ldap_sasl_bind_s(ldapHandle,bindUserCStr,LDAP_SASL_SIMPLE,&bindCredentials,NULL,NULL,&servercredp);
            if(rc != LDAP_SUCCESS)
            {
                ldap_unbind_ext(ldapHandle, nullptr, nullptr);
                ldapHandle = nullptr;
            }
            return rc;
        };
        bool valid_user(std::string user)
        {
            LDAPMessage *searchResult;
            std::string ldapFilter = "(uid="+ user + ")";
            rc = ldap_search_ext_s(
                ldapHandle,
                ldapSearchBase,
                ldapSearchScope,
                ldapFilter,
                (char **)ldapSearchResultAttributes,
                0,
                NULL,
                NULL,
                NULL,
                500,
                &searchResult);
            if (rc != LDAP_SUCCESS)
            {
                std::cerr << "LDAP search error: " << ldap_err2string(rc) << std::endl;
                return false;
            }
            return ldap_count_entries(ldapHandle, searchResult) > 0;

        }

    private:
        const char *ldapUri = "ldap://ldap.technikum-wien.at:389";
        const int ldapVersion = LDAP_VERSION3;
        const char *ldapSearchBase= "dc=technikum-wien,dc=at";
        ber_int_t ldapSearchScope = LDAP_SCOPE_SUBTREE;
        const char *ldapSearchResultAttributes[3] = {"uid", "cn", NULL};
        BerValue bindCredentials;
        LDAP *ldapHandle;

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
                std::cout << rc << std::endl;
                exit(EXIT_FAILURE);
            }
        }
};