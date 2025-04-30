	.file	"main.c"
	.option nopic
	.attribute arch, "rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0_zicfilp1p0_zicfiss1p0_zicsr2p0_zifencei2p0"
	.attribute unaligned_access, 0
	.attribute stack_align, 16
	.text
	.section	.rodata
	.align	3
.LC0:
	.string	"\n========== RISC-V Security Test: Control Flow Integrity (CFI) =========\r"
	.align	3
.LC1:
	.string	"\n===== [TEST] Function Pointer Overwrite Attack (Zicfilp) =====\r"
	.text
	.align	1
	.globl	main
	.type	main, @function
main:
	addi	sp,sp,-16
	sd	ra,8(sp)
	sd	s0,0(sp)
	addi	s0,sp,16
	li	a5,114688
	addi	a0,a5,512
	call	setup_uart
	lui	a5,%hi(.LC0)
	addi	a0,a5,%lo(.LC0)
	call	printf
	lui	a5,%hi(.LC1)
	addi	a0,a5,%lo(.LC1)
	call	printf
.L2:
	j	.L2
	.size	main, .-main
	.ident	"GCC: (gb8636e8768b) 13.3.0"
	.section	.note.GNU-stack,"",@progbits
