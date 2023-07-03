#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "pbc.h"

#ifdef pbc_verbose
#define pbc_err_nofile()        fprintf(stderr, "[PASSBOLT C] Could not find file!\n")
#define pbc_err_nopen()         fprintf(stderr, "[PASSBOLT C] Could not open file!\n")
#define pbc_err_nomem()         fprintf(stderr, "[PASSBOLT C] Could not allocate memory!\n")
#define pbc_err_gpg(err)        fprintf(stderr, "[PASSBOLT C] GgpME: %s\n", gpgme_strerror(err))
#endif

static inline void str_free(pbc_str* _str) {
    free(_str->ptr);
    free(_str);
}

static inline int init_gpgme(gpgme_ctx_t* ctx) {
    gpgme_error_t err;

    gpgme_check_version(NULL);
    gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);
    err = gpgme_new(ctx);
    if(err != GPG_ERR_NO_ERROR) {
#ifdef pbc_verbose
        pbc_err_gpg(err);
#endif
        return -1;
    }
    return 0;
}

static inline gpgme_import_result_t gpgme_import_key(const char* key, gpgme_ctx_t* ctx) {
    gpgme_error_t err;
    gpgme_data_t dh;
    err = gpgme_data_new_from_mem(&dh, key, strlen(key)+1, 1);
    if(err != GPG_ERR_NO_ERROR) {
#ifdef pbc_verbose
        pbc_err_gpg(err);
#endif
        return NULL;
    }
    err = gpgme_op_import(*ctx, dh);
    if(err != GPG_ERR_NO_ERROR) {
#ifdef pbc_verbose
        pbc_err_gpg(err);
#endif
        return NULL;
    }
    gpgme_data_release(dh);
    return gpgme_op_import_result(*ctx);
}

static inline char* get_gpg_fingerprint(const char* key, gpgme_ctx_t* ctx) {
    if(!key) return NULL;
    gpgme_import_result_t res = gpgme_import_key(key, ctx);
    if(!res) return NULL;
    if(!res->imports) return NULL;
    char* fprt = malloc(strlen(res->imports->fpr)+1);
    if(!fprt) { 
#ifdef pbc_verbose
        pbc_err_nomem();
#endif
        return NULL;
    }
    strcpy(fprt, res->imports->fpr);
    return fprt;
}

static inline CURL* curl_init() {
    curl_global_init(CURL_GLOBAL_DEFAULT);

    CURL* curl;
    if((curl = curl_easy_init()) == NULL)
        { curl_global_cleanup(); return NULL; }

    return curl;
}

static inline size_t creads(void* buffer, size_t size, size_t nmemb, void* _data) {
    pbc_str* data = (pbc_str*)_data;
    if(data) {
        char* new = realloc(data->ptr, data->size + nmemb*size + 1);
        if(!new) return 0;
        data->ptr = new;

        if(!memcpy(&(data->ptr[data->size]), buffer, size*nmemb))
            free(data->ptr);
        data->size += nmemb;
        data->ptr[data->size] = '\0';
    }

    return size*nmemb;
}

static inline size_t creadv(void* buffer, size_t size, size_t nmemb, void* data) {
    return size*nmemb;
}

static inline int curl_do(CURL* handle) {
    CURLcode curl_res;
    char curl_err[CURL_ERROR_SIZE];
    curl_easy_setopt(handle, CURLOPT_ERRORBUFFER, curl_err);

    if((curl_res = curl_easy_perform(handle)) != CURLE_OK) {
#ifdef pbc_verbose
        printf("[PASSBOLT C] CURL: %d\n", curl_res);
        if(strlen(curl_err)) printf("%sn", curl_err);	
        else printf("%s\n", curl_easy_strerror(curl_res));
#endif
        return -1;
    }

    return 0;
}

static inline size_t curl_get_header(char* buffer, size_t size, size_t nmemb, void* _data) {
    pbc_header* data = (pbc_header*)_data;
    if(data) {
        if(strstr(buffer, data->name)) {
            data->content->ptr = calloc(nmemb+1, size);
            data->content->size = nmemb+1;
            if(!memcpy(data->content->ptr, buffer, size*nmemb))
                free(data->content->ptr), data->content->ptr = NULL;
            data->content->ptr[nmemb] = '\0';
        }
    }

    return size*nmemb;
}

static inline void remove_url_whitespace(char* string, const size_t len) {
    int move = 0;
    for(size_t i=0; i<len; ++i) {
        if(string[i] == '\n') move = 0;
        if(!move) {
            if(string[i] == '\\' && string[i+1] == '+') {
                string[i] = ' ';
                move = 1;
                continue;
            }
        } else {
            if(string[i+1] == '\\' && string[i+2] == '+') {
                string[i] = ' ';
                ++move;
                continue;
            }
        }
        if(move) string[i] = string[i+move];
    }
}

static inline int parse_url_string(pbc_str* undecoded, CURL* handle) {
    int decoded_len = 0;
    char* f = strchr(undecoded->ptr, ':');
    size_t pos = 0;
    if(f) pos = f - undecoded->ptr + 2;
    size_t new_size = undecoded->size-pos;
    char new[new_size];
    for(size_t i=0; i<new_size; ++i) new[i] = undecoded->ptr[i+pos];
    free(undecoded->ptr);

    char* decoded = curl_easy_unescape(handle, new, new_size, &decoded_len);
    remove_url_whitespace(decoded, decoded_len);

    undecoded->ptr = malloc(decoded_len);
    undecoded->size = decoded_len;
    strcpy(undecoded->ptr, decoded);
#ifdef pbc_debug
    puts(undecoded->ptr);
#endif
    curl_free(decoded);
    return 0;
}

static inline pbc_str* gpg_decrypt(pbc_str* string, gpgme_ctx_t* ctx) {
    gpgme_error_t err;
    gpgme_data_t encr, decr;
    err = gpgme_data_new_from_mem(&encr, string->ptr, string->size, 1);
    if(err != GPG_ERR_NO_ERROR) { 
#ifdef pbc_verbose
        pbc_err_gpg(err);
#endif
        return NULL;
    }
    err = gpgme_data_new(&decr);
    if(err != GPG_ERR_NO_ERROR) { 
        gpgme_data_release(encr);
#ifdef pbc_verbose
        pbc_err_gpg(err); 
#endif
        return NULL;
    }
    err = gpgme_op_decrypt(*ctx, encr, decr);
    if(err != GPG_ERR_NO_ERROR) {
        gpgme_data_release(decr); 
        gpgme_data_release(encr);
#ifdef pbc_verbose
        pbc_err_gpg(err);
#endif
        return NULL;
    }
    gpgme_decrypt_result_t res = gpgme_op_decrypt_result(*ctx);
    gpgme_data_release(encr);

    pbc_str* ret = malloc(sizeof(pbc_str));
    if(!ret) {
        gpgme_data_release(decr); 
#ifdef pbc_verbose
        pbc_err_nomem();
#endif
        return NULL;
    }
    char buf[68];
    gpgme_data_seek(decr, 0, SEEK_SET);
    size_t t = gpgme_data_read(decr, buf, 68);
    buf[67] = '\0';
    gpgme_data_release(decr);
#ifdef pbc_debug
    puts(buf);
#endif

    ret->size = strlen(buf);
    ret->ptr = calloc(ret->size+1, sizeof(char));
    if(!ret->ptr) {
        free(ret);
#ifdef pbc_verbose
        pbc_err_nomem();
#endif
        return NULL;
    }
    strncpy(ret->ptr, buf, ret->size);
#ifdef pbc_debug
    puts(ret->ptr);
#endif

    return ret;
}

static inline struct curl_slist* json_headers_init() {
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "charset: utf-8");
    return headers;
}

static inline char* new_strcat(const char* first, const char* second) {
    size_t t_size = strlen(first)+strlen(second)+2;
    char* t = malloc(t_size);
    if(!t) {
#ifdef pbc_verbose
        pbc_err_nomem();
#endif
        return NULL;
    }
    strcpy(t, first);
    strcat(t, second);
    return t;
}

static inline char* tr_strcat(const char* first, const char* second, const char* third, const char* fourth) {
    size_t t_size = strlen(first)+strlen(second)+strlen(third)+strlen(fourth)+4;
    char* t = malloc(t_size);
    if(!t) {
#ifdef pbc_verbose
        pbc_err_nomem();
#endif
        return NULL;
    }
    strcpy(t, first);
    strcat(t, second);
    strcat(t, third);
    strcat(t, fourth);
    return t;
}

static inline pbc_str* stage1(pbc* t) {
    char* login_url = new_strcat(t->url, "/auth/login.json");
    if(!login_url) return NULL;
    curl_easy_setopt(t->curl, CURLOPT_URL, login_url);

    t->headers = json_headers_init();
    curl_easy_setopt(t->curl, CURLOPT_HTTPHEADER, t->headers);

    char json[256];
    strcpy(json, "{\"data\": {\"gpg_auth\": {\"keyid\":\"");
    strcat(json, t->fprt);
    strcat(json, "\"}}}");
    curl_easy_setopt(t->curl, CURLOPT_POSTFIELDS, json);
    curl_easy_setopt(t->curl, CURLOPT_HEADER, 1L);

    pbc_header gpgauth = {
        .name = "X-GPGAuth-User-Auth-Token:",
        .content = malloc(sizeof(pbc_str)),
    };
    if(!gpgauth.content) { 
        free(login_url);
#ifdef pbc_verbose
        pbc_err_nomem();
#endif
        return NULL;
    }

    curl_easy_setopt(t->curl, CURLOPT_HEADERFUNCTION, curl_get_header);
    curl_easy_setopt(t->curl, CURLOPT_HEADERDATA, &gpgauth);
    curl_easy_setopt(t->curl, CURLOPT_WRITEFUNCTION, creadv);

    if(curl_do(t->curl) < 0) { free(login_url); return NULL; }

    parse_url_string(gpgauth.content, t->curl);
    pbc_str* msg = gpg_decrypt(gpgauth.content, &t->gpg_ctx);
    if(!msg) { str_free(gpgauth.content); free(login_url); return NULL; }

    str_free(gpgauth.content);
    free(login_url);

    return msg;
}

static inline int stage2(pbc* t, pbc_str* nonce) {
    char json[256];
    strcpy(json, "{\"data\": {\"gpg_auth\": {\"keyid\":\"");
    strcat(json, t->fprt);
    strcat(json, "\", \"user_token_result\":\"");
    strcat(json, nonce->ptr);
    strcat(json, "\"}}}");
    curl_easy_setopt(t->curl, CURLOPT_POSTFIELDS, json);
    curl_easy_setopt(t->curl, CURLOPT_HEADER, 0);

    pbc_str body = {.ptr = NULL, .size = 0};
    curl_easy_setopt(t->curl, CURLOPT_HEADERFUNCTION, NULL);
    curl_easy_setopt(t->curl, CURLOPT_HEADERDATA, NULL);
    curl_easy_setopt(t->curl, CURLOPT_WRITEFUNCTION, creads);
    curl_easy_setopt(t->curl, CURLOPT_WRITEDATA, &body);
    if(curl_do(t->curl) < 0) return -1;

    long code;
    curl_easy_getinfo(t->curl, CURLINFO_RESPONSE_CODE, &code);
    if(code != 200) { free(body.ptr); return -1; }

    free(body.ptr);

    return 0;
}

static inline char* make_csrf(pbc_str* string) {
    char* set = string->ptr;
    char* f = strchr(set, '=');
    size_t pos0 = 0;
    if(f) pos0 = f - set + 1;
    char* v = strchr(set, ';');
    size_t pos1 = 0;
    if(v) pos1 = v - set;
    size_t n_size = pos1 - pos0 + 1;
    char token[n_size];
    for(size_t i=0; i<n_size-1; ++i) token[i] = set[i+pos0];
    token[n_size-1] = '\0';

    char* new_cook = calloc(256, sizeof(char));
    if(!new_cook) { 
#ifdef pbc_verbose
        pbc_err_nomem();
#endif
        return NULL;
    }
    strcpy(new_cook, "X-CSRF-Token: ");
    strcat(new_cook, token);

    return new_cook;
}

static inline int get_cookie(pbc* t) {
    char* me_url = new_strcat(t->url, "/users/me.json");
    if(!me_url) return -1;
    curl_easy_setopt(t->curl, CURLOPT_URL, me_url);
    curl_easy_setopt(t->curl, CURLOPT_POSTFIELDS, NULL);

    pbc_header setck = {
        .name = "Set-Cookie:",
        .content = malloc(sizeof(pbc_str)),
    };
    if(!setck.content) {
        free(me_url);
#ifdef pbc_verbose
        pbc_err_nomem();
#endif
        return -1;
    }

    curl_easy_setopt(t->curl, CURLOPT_HEADER, 1L);
    curl_easy_setopt(t->curl, CURLOPT_HEADERFUNCTION, curl_get_header);
    curl_easy_setopt(t->curl, CURLOPT_HEADERDATA, &setck);
    curl_easy_setopt(t->curl, CURLOPT_WRITEFUNCTION, creadv);
    curl_easy_setopt(t->curl, CURLOPT_WRITEDATA, NULL);
    curl_easy_setopt(t->curl, CURLOPT_HTTPGET, 1L);
    if(curl_do(t->curl) < 0) {
        free(setck.content);
        free(me_url);
        return -1;
    }

    long code;
    curl_easy_getinfo(t->curl, CURLINFO_RESPONSE_CODE, &code);
    if(code != 200) {
        free(setck.content);
        free(me_url);
        return -1;
    }

    char* token = make_csrf(setck.content);
    if(!token) {
        free(setck.content);
        free(me_url);
        return -1;
    }
#ifdef pbc_debug
    puts(token);
#endif

    t->headers = curl_slist_append(t->headers, token);
    curl_easy_setopt(t->curl, CURLOPT_HTTPHEADER, t->headers);

    str_free(setck.content);
    free(me_url);
    free(token);

    curl_easy_setopt(t->curl, CURLOPT_HEADER, 0);
    curl_easy_setopt(t->curl, CURLOPT_HEADERFUNCTION, NULL);
    curl_easy_setopt(t->curl, CURLOPT_HEADERDATA, NULL);
    curl_easy_setopt(t->curl, CURLOPT_WRITEFUNCTION, fwrite);
    curl_easy_setopt(t->curl, CURLOPT_WRITEDATA, stdout);
    curl_easy_setopt(t->curl, CURLOPT_HTTPGET, 0);

    return 0;
}

pbc* pbc_init(const char* baseurl, const char* key) {
    pbc* t = malloc(sizeof(pbc));
    if(!t) {
#ifdef pbc_verbose
        pbc_err_nomem(); 
#endif
        return NULL;
    }
    t->curl = NULL;
    t->fprt = NULL;
    t->gpg_ctx = NULL;
    t->headers = NULL;
    t->url = NULL;

    if(init_gpgme(&t->gpg_ctx) < 0) { pbc_free(t); return NULL; }

    t->curl = curl_init();
    if(!t->curl) { pbc_free(t); return NULL; }

    t->url = malloc(strlen(baseurl)+1);
    if(!t->url) { 
        pbc_free(t); 
#ifdef pbc_verbose
        pbc_err_nomem(); 
#endif
        return NULL;
    }
    strcpy(t->url, baseurl);

    t->fprt = get_gpg_fingerprint(key, &t->gpg_ctx);
    if(!t->fprt) { pbc_free(t); return NULL; }

    return t;
}

int pbc_login(pbc* _pbc) {
#ifdef pbc_curl_verbose
    curl_easy_setopt(_pbc->curl, CURLOPT_VERBOSE, 1L);
#endif
    curl_easy_setopt(_pbc->curl, CURLOPT_COOKIEFILE, "");

    pbc_str* nonce = stage1(_pbc);
    if(!nonce) {
#ifdef pbc_verbose
        fprintf(stderr, "[PASSBOLT C] Could not get NONCE from stage 1.\n");
#endif
        return -1;
    }

    if(stage2(_pbc, nonce) < 0) {
        str_free(nonce); 
#ifdef pbc_verbose
        fprintf(stderr, "[PASSBOLT C] Stage 2 did not pass.\n");
#endif
        return -1;
    }
    str_free(nonce);

    if(get_cookie(_pbc) < 0) return -1;

    return 0;
}

static inline void pbc_curl_reset(pbc* t, const char* url) {
    curl_easy_setopt(t->curl, CURLOPT_URL, url);
    curl_easy_setopt(t->curl, CURLOPT_POSTFIELDS, NULL);
    curl_easy_setopt(t->curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(t->curl, CURLOPT_HEADER, 0);
    curl_easy_setopt(t->curl, CURLOPT_HEADERFUNCTION, NULL);
    curl_easy_setopt(t->curl, CURLOPT_HEADERDATA, NULL);
}

int pbc_check(pbc* _pbc) {
    char* url = new_strcat(_pbc->url, "/");
    if(!url) return -1;
    pbc_curl_reset(_pbc, url);
    curl_easy_setopt(_pbc->curl, CURLOPT_WRITEFUNCTION, creadv);
    curl_easy_setopt(_pbc->curl, CURLOPT_WRITEDATA, NULL);
    if(curl_do(_pbc->curl) < 0) {
        free(url);
        return -1;
    }
    free(url);

    long code;
    curl_easy_getinfo(_pbc->curl, CURLINFO_RESPONSE_CODE, &code);
    if(code != 200) {
        return -1;
    }

    return 0;
}

static inline int pbc_request(pbc* t) {
    if(curl_do(t->curl) < 0) return -1;
    long code;
    curl_easy_getinfo(t->curl, CURLINFO_RESPONSE_CODE, &code);
    if(code != 200) return -1;
    return 0;
}

char* pbc_get_my_user(pbc* _pbc) {
    char* url = new_strcat(_pbc->url, "/users/me.json");
    if(!url) return NULL;
    pbc_curl_reset(_pbc, url);
    pbc_str data = {.ptr = NULL, .size = 0};
    curl_easy_setopt(_pbc->curl, CURLOPT_WRITEFUNCTION, creads);
    curl_easy_setopt(_pbc->curl, CURLOPT_WRITEDATA, &data);
    free(url);
    if(pbc_request(_pbc) < 0) return NULL;
    return data.ptr;
}

char* pbc_get_users(pbc* _pbc) {
    char* url = new_strcat(_pbc->url, "/users.json");
    if(!url) return NULL;
    pbc_curl_reset(_pbc, url);
    pbc_str data = {.ptr = NULL, .size = 0};
    curl_easy_setopt(_pbc->curl, CURLOPT_WRITEFUNCTION, creads);
    curl_easy_setopt(_pbc->curl, CURLOPT_WRITEDATA, &data);
    free(url);
    if(pbc_request(_pbc) < 0) return NULL;
    return data.ptr;
}

char* pbc_get_user_per_uuid(pbc* _pbc, const char* uuid) {
    char* url = tr_strcat(_pbc->url, "/users/", uuid, ".json");
    if(!url) return NULL;
    pbc_curl_reset(_pbc, url);
    pbc_str data = {.ptr = NULL, .size = 0};
    curl_easy_setopt(_pbc->curl, CURLOPT_WRITEFUNCTION, creads);
    curl_easy_setopt(_pbc->curl, CURLOPT_WRITEDATA, &data);
    free(url);
    if(pbc_request(_pbc) < 0) return NULL;
    return data.ptr;
}

char* pbc_get_groups(pbc* _pbc) {
    char* url = new_strcat(_pbc->url, "/groups.json");
    if(!url) return NULL;
    pbc_curl_reset(_pbc, url);
    pbc_str data = {.ptr = NULL, .size = 0};
    curl_easy_setopt(_pbc->curl, CURLOPT_WRITEFUNCTION, creads);
    curl_easy_setopt(_pbc->curl, CURLOPT_WRITEDATA, &data);
    free(url);
    if(pbc_request(_pbc) < 0) return NULL;
    return data.ptr;
}

char* pbc_get_resources(pbc* _pbc) {
    char* url = new_strcat(_pbc->url, "/resources.json");
    if(!url) return NULL;
    pbc_curl_reset(_pbc, url);
    pbc_str data = {.ptr = NULL, .size = 0};
    curl_easy_setopt(_pbc->curl, CURLOPT_WRITEFUNCTION, creads);
    curl_easy_setopt(_pbc->curl, CURLOPT_WRITEDATA, &data);
    free(url);
    if(pbc_request(_pbc) < 0) return NULL;
    return data.ptr;
}

char* pbc_get_resource_per_uuid(pbc* _pbc, const char* uuid) {
    char* url = tr_strcat(_pbc->url, "/resources/", uuid, ".json");
    if(!url) return NULL;
    pbc_curl_reset(_pbc, url);
    pbc_str data = {.ptr = NULL, .size = 0};
    curl_easy_setopt(_pbc->curl, CURLOPT_WRITEFUNCTION, creads);
    curl_easy_setopt(_pbc->curl, CURLOPT_WRITEDATA, &data);
    free(url);
    if(pbc_request(_pbc) < 0) return NULL;
    return data.ptr;
}

char* pbc_get_resource_secret(pbc* _pbc, const char* res_id) {
    char* url = tr_strcat(_pbc->url, "/secrets/resource/", res_id, ".json");
    if(!url) return NULL;
    pbc_curl_reset(_pbc, url);
    pbc_str data = {.ptr = NULL, .size = 0};
    curl_easy_setopt(_pbc->curl, CURLOPT_WRITEFUNCTION, creads);
    curl_easy_setopt(_pbc->curl, CURLOPT_WRITEDATA, &data);
    free(url);
    if(pbc_request(_pbc) < 0) return NULL;
    return data.ptr;
}

char* pbc_get_resource_types(pbc* _pbc) {
    char* url = new_strcat(_pbc->url, "/resource-types.json");
    if(!url) return NULL;
    pbc_curl_reset(_pbc, url);
    pbc_str data = {.ptr = NULL, .size = 0};
    curl_easy_setopt(_pbc->curl, CURLOPT_WRITEFUNCTION, creads);
    curl_easy_setopt(_pbc->curl, CURLOPT_WRITEDATA, &data);
    free(url);
    if(pbc_request(_pbc) < 0) return NULL;
    return data.ptr;
}

void pbc_free(pbc* _pbc) {
    if(_pbc->url) free(_pbc->url);
    if(_pbc->fprt) free(_pbc->fprt);
    if(_pbc->headers) curl_slist_free_all(_pbc->headers);
    if(_pbc->curl) curl_easy_cleanup(_pbc->curl), curl_global_cleanup();
    if(_pbc->gpg_ctx) gpgme_release(_pbc->gpg_ctx);
    free(_pbc);
}
