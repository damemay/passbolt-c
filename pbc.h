#include <stdlib.h>
#include <gpgme.h>
#include <curl/curl.h>

typedef struct pbc_str {
    char* ptr;
    size_t size;
} pbc_str;

typedef struct pbc_header {
    char* name;
    pbc_str* content;
} pbc_header;

typedef struct pbc {
    gpgme_ctx_t gpg_ctx;
    CURL* curl;
    struct curl_slist* headers;
    char* url;
    char* fprt;
} pbc;

pbc* pbc_init(const char* baseurl, const char* key);
int pbc_login(pbc* _pbc);
int pbc_check(pbc* _pbc);

char* pbc_get_my_user(pbc* _pbc);
char* pbc_get_users(pbc* _pbc);
char* pbc_get_user_per_uuid(pbc* _pbc, const char* uuid);
char* pbc_get_groups(pbc* _pbc);
char* pbc_get_resources(pbc* _pbc);
char* pbc_get_resource_per_uuid(pbc* _pbc, const char* uuid);
char* pbc_get_resource_secret(pbc* _pbc, const char* res_id);
char* pbc_get_resource_types(pbc* _pbc);

void pbc_free(pbc* _pbc);
