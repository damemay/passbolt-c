#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "pbc.h"

static inline char* get_key_from_file(const char* filepath) {
    struct stat filestat;
    if(stat(filepath, &filestat) != 0) return NULL;
    size_t filesize = filestat.st_size;

    char* filecontent = malloc(filesize+1);
    if(!filecontent) return NULL;

    FILE* fs = fopen(filepath, "rt");
    if(!fs) { fclose(fs); free(filecontent); return NULL; }

    if(fread(filecontent, filesize, 1, fs) != 1) { fclose(fs); free(filecontent); return NULL; }

    fclose(fs);
    filecontent[filesize] = '\0';

    return filecontent;
}

int main(int argc, char** argv) {
    if(argc > 2) {
        char* key = get_key_from_file(argv[2]);

        pbc* t = pbc_init(argv[1], key);

        free(key);

        if(!t) printf("Could not init Passbolt C\n"), exit(EXIT_FAILURE);

        if(pbc_login(t) < 0) printf("Could not authorize login to %s Passbolt\n", argv[1]), exit(EXIT_FAILURE);

        if(pbc_check(t) == 0) printf("Successfully logged onto %s Passbolt!\n", t->url);

        pbc_free(t);
    } else {
        printf("%s: <passbolt base url> <private key file>\n", argv[0]);
    }

    return EXIT_SUCCESS;
}
