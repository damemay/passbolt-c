# passbolt-c
small C library for Passbolt API with minimal dependecies that can be used to implement Passbolt into your application.

- depends on libcurl and GpgME
- **no json handling** - functions return json responses in char* to feed into a parser of your choice
- **limited to authentication and GET functions** as an effect of aforementioned
- **GpgME context and libcurl handler are always alive** until `pbc_free` is called 

## example
```c
#include "pbc.h"
int main() {
    char* pkey;
    // load a passbolt private key your preferred way into char* pkey
    pbc* t = pbc_init("http://127.0.0.1", pkey);
    pbc_login(t);
    pbc_free(t);
}
```
more robust example in [sample.c](sample.c)
