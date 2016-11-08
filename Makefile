CFLAGS = -Wall -Wextra

OBJECTS = infect.o shellcode.o shellcodegen.h hello.o

hello: hello.o infect
	$(CC) -o hello-original hello.o
	$(CC) -o hello-infected hello.o
	./infect hello-infected

infect: $(OBJECTS)
	$(CC) -o infect infect.o

shellcode.o: shellcode.s
	nasm -f elf64 -o shellcode.o shellcode.s

shellcodegen.h: shellcode.o
	for byte in `objdump -d shellcode.o | grep "^ "| cut -f2`; do \
		printf "\x$$byte"; \
	done | xxd -i > shellcodegen.h

infect.c: shellcodegen.h

syscalltable.h:
	echo "#include <sys/syscall.h>" | \
		cpp -dM | \
		grep '^#define __NR_' | \
		sed -r -n -e 's/^\#define[ \t]+__NR_([a-z0-9_]+)[ \t]+([0-9]+)(.*)/ [\2] = "\1",/p' > $@

infect: infect.c

clean:
	rm -f infect hello-infected hello-original $(OBJECTS) *~

all: Makefile infect hello

