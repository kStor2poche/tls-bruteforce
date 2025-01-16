LIBS:=gcrypt
CFLAGS:=${CFLAGS} -Wall

# If the first argument is "run"...
ifeq (run,$(firstword $(MAKECMDGOALS)))
  # use the rest as arguments for "run"
  RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  # ...and turn them into do-nothing targets
  $(eval $(RUN_ARGS):;@:)
endif

tls_decrypt: tls_decrypt.c
	${CC} ${CFLAGS} -c $< -o tls_decrypt.o

main: main.c tls_decrypt.h
	${CC} ${CFLAGS} -c $< -o main.o

build: main.o tls_decrypt.o
	${CC} ${CFLAGS} -l${LIBS} $^ -o tls-bf

run: build
	./tls-bf $(RUN_ARGS)

clean: 
	rm *.o
