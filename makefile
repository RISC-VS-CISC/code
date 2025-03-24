cc = riscv64-unknown-elf-gcc
flags = -ansi -Wall -g -O
targets = main

link: main.c uart.c
	$(cc) $(flags) -c main.c uart.c
compile: main.o uart.o
	$(cc) $(flags) main.o uart.o -o main
all:
	make link
	make compile    
clean:
	rm $(targets)
	rm ./*.o
