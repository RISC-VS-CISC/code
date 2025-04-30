cc = /home/Brandon/Documents/Research/riscv/bin/riscv64-unknown-elf-gcc#/home/Brandon/Documents/Research/riscv/bin/riscv64-unknown-elf-gcc #f-march=rv64gci_zicfilp_zicfiss_zicsr <program.c> -static -o <program.elf>
flags = -O2 -march=rv64gc_zicfilp_zicfiss -fcf-protection=full -mabi=lp64d #-Wall -g -O2 -march=rv64gc_zicfilp_zicfiss_zicsr -mabi=lp64d -fstack-protector  -fstack-protector-all  -fstack-protector-strong -fstack-protector-explicit -fstack-check -static#-nostartfiles -Wl,-e,main
targets = main

all: link compile
link: cfi_test.c uart.c
	$(cc) $(flags) -c cfi_test.c uart.c
compile: cfi_test.o uart.o
	$(cc) $(flags) cfi_test.o uart.o -o main    
clean:
	rm $(targets)
	rm ./*.o
