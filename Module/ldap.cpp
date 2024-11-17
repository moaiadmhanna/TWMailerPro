#include <iostream>
#include <string>
#include <ldap.h>
class Ldap
{
    public:
        Ldap()
        {
            if(ldap_initialize(&ldapHandle, ldapUri) != LDAP_SUCCESS)
            {
                std::cerr << "Failed to initialize LDAP connection." << std::endl;
                exit(EXIT_FAILURE);
            }
            int rc = ldap_set_option(ldapHandle,LDAP_OPT_PROTOCOL_VERSION,&ldapVersion);
            if(rc != LDAP_SUCCESS)
            {
                ldap_unbind_ext_s(ldapHandle, NULL, NULL);
                std::cerr << "Failed to set LDAP options." << std::endl;
                exit(EXIT_FAILURE);
            }
            if(ldap_start_tls_s(ldapHandle,NULL,NULL) != LDAP_SUCCESS)
            {
                ldap_unbind_ext_s(ldapHandle, NULL, NULL);
                std::cerr << "Failed to start LDAP connection." << std::endl;
                exit(EXIT_FAILURE);
            }

        };
        void bind_ldap_credentials(char *username, char *password)
        {
            std::string ldapBindUser = "uid=" + std::string(username) + ",ou=people," + ldapSearchBase;
            bindCredentials.bv_val = password;
            bindCredentials.bv_len = strlen(password);
            BerValue *servercredp;
            int rc = ldap_sasl_bind_s(ldapHandle,ldapBindUser.c_str(),LDAP_SASL_SIMPLE,&bindCredentials,NULL,NULL,&servercredp);
            if(rc != LDAP_SUCCESS)
            {
                ldap_unbind_ext_s(ldapHandle, NULL, NULL);
                std::cerr << "Failed to bind LDAP credentials." << std::endl;
                exit(EXIT_FAILURE);
            }

        };
        bool user_exists()
        {
            LDAPMessage *searchResult;
            int rc = ldap_search_ext_s(ldapHandle,ldapSearchBase,ldapSearchScope,ldapSearchFilter,(char **)ldapSearchResultAttributes,0,NULL,NULL,NULL,500,&searchResult);
            if(rc != LDAP_SUCCESS)
            {
                ldap_unbind_ext_s(ldapHandle, NULL, NULL);
                exit(EXIT_FAILURE);
            }
            int count = ldap_count_entries(ldapHandle, searchResult);
            return count == 0;
        };
    private:
        const char *ldapUri = "ldap://ldap.technikum-wien.at:389";
        const int ldapVersion = LDAP_VERSION3;
        const char *ldapSearchBase= "dc=technikum-wien,dc=at";
        const char *ldapSearchFilter = "(uid=if22b00*)";
        ber_int_t ldapSearchScope = LDAP_SCOPE_SUBTREE;
        const char *ldapSearchResultAttributes[3] = {"uid", "cn", NULL};
        BerValue bindCredentials;
        LDAP *ldapHandle;
};