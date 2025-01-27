LIBS:=-lgcrypt -lpcap
CFLAGS:=${CFLAGS} -Wall
CC:=gcc

# If the first argument is "run"...
ifeq (run,$(firstword $(MAKECMDGOALS)))
  # use the rest as arguments for "run"
  RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  # ...and turn them into do-nothing targets
  $(eval $(RUN_ARGS):;@:)
endif

default: clean build

utils: utils.c utils.h
	${CC} ${CFLAGS} -c $< -o utils.o

cipher_suite_extraction: cipher_suite_extraction.c cipher_suite_extraction.h
	${CC} ${CFLAGS} -c $< -o cipher_suite_extraction.o

info_digger: info_digger.c info_digger.h utils.o
	${CC} ${CFLAGS} -c $< -o info_digger.o

key_derivation: key_derivation.c key_derivation.h utils.o
	${CC} ${CFLAGS} -c $< -o key_derivation.o

tls_decrypt: tls_decrypt.c tls_decrypt.h utils.o cipher_suite_extraction.o
	${CC} ${CFLAGS} -c $< -o tls_decrypt.o

main: main.c tls_decrypt.o key_derivation.o utils.o info_digger.o cipher_suite_extraction.o
	${CC} ${CFLAGS} -c $< -o main.o

build: main.o tls_decrypt.o key_derivation.o utils.o info_digger.o cipher_suite_extraction.o
	${CC} ${CFLAGS} ${LIBS} $^ -o tls-bf

run: build
	./tls-bf $(RUN_ARGS)

clean: 
	if [[ -n $$(find . -name "*.o") ]]; then rm *.o; fi
