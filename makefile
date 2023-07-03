src = pbc.c
obj = pbc.o
flags = -O2
link = -lgpgme -lcurl
debug = -Dpbc_debug -Dpbc_verbose -Dpbc_curl_verbose -g

all:
	gcc $(flags) -c pbc.c

sample:
	gcc $(obj) sample.c $(link) -o passbolt

asan:
	gcc $(src) sample.c $(debug) -fsanitize=address -O1 -fno-omit-frame-pointer $(link) -o passbolt
