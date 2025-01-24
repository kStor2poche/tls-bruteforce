LIBS:=gcrypt
CFLAGS:=${CFLAGS} -Wall

# If the first argument is "run"...
ifeq (run,$(firstword $(MAKECMDGOALS)))
  # use the rest as arguments for "run"
  RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  # ...and turn them into do-nothing targets
  $(eval $(RUN_ARGS):;@:)
endif

bytearray: bytearray.c bytearray.h
	${CC} ${CFLAGS} -c $< -o bytearray.o

key_derivation: key_derivation.c key_derivation.h bytearray.o
	${CC} ${CFLAGS} -c $< -o key_derivation.o

tls_decrypt: tls_decrypt.c tls_decrypt.h bytearray.o
	${CC} ${CFLAGS} -c $< -o tls_decrypt.o

main: main.c tls_decrypt.o key_derivation.o bytearray.o
	${CC} ${CFLAGS} -c $< -o main.o

build: main.o bytearray.o tls_decrypt.o key_derivation.o
	${CC} ${CFLAGS} -l${LIBS} $^ -o tls-bf

run: build
	./tls-bf $(RUN_ARGS)

clean: 
	rm *.o
