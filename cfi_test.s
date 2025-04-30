	.file	"cfi_test.c"
	.option nopic
	.attribute arch, "rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0_zicfilp1p0_zicflip_zicsr2p0_zifencei2p0"
	.attribute unaligned_access, 0
	.attribute stack_align, 16
	.text
	.section	.rodata
	.align	3
.LC0:
	.string	"\n==========RISC-V Security Test: Control Flow Integrity (CFI)=========\n\r"
	.align	3
.LC1:
	.string	"\nAll tests completed.\n\r"
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
	call	test_function_pointer_attack
	call	test_invalid_function_pointer
	call	return_address_attack
	lui	a5,%hi(.LC1)
	addi	a0,a5,%lo(.LC1)
	call	printf
.L2:
	j	.L2
	.size	main, .-main
	.section	.rodata
	.align	3
.LC2:
	.string	"[INFO] Executing safe function: Secure Execution\n\r"
	.text
	.align	1
	.globl	safe_function
	.type	safe_function, @function
safe_function:
	addi	sp,sp,-16
	sd	ra,8(sp)
	sd	s0,0(sp)
	addi	s0,sp,16
	lui	a5,%hi(.LC2)
	addi	a0,a5,%lo(.LC2)
	call	printf
	nop
	ld	ra,8(sp)
	ld	s0,0(sp)
	addi	sp,sp,16
	jr	ra
	.size	safe_function, .-safe_function
	.section	.rodata
	.align	3
.LC3:
	.string	"[ALERT] Security Breach: Malicious function executed!\n\r"
	.align	3
.LC4:
	.string	"[WARNING] Possible Control Flow Integrity (CFI) violation detected.\n\r"
	.text
	.align	1
	.globl	malicious_function
	.type	malicious_function, @function
malicious_function:
	addi	sp,sp,-16
	sd	ra,8(sp)
	sd	s0,0(sp)
	addi	s0,sp,16
	lui	a5,%hi(.LC3)
	addi	a0,a5,%lo(.LC3)
	call	printf
	lui	a5,%hi(.LC4)
	addi	a0,a5,%lo(.LC4)
	call	printf
	nop
	ld	ra,8(sp)
	ld	s0,0(sp)
	addi	sp,sp,16
	jr	ra
	.size	malicious_function, .-malicious_function
	.section	.rodata
	.align	3
.LC5:
	.string	"===== [TEST] Function Pointer Overwrite Attack (Zicfilp) =====\n\r"
	.align	3
.LC6:
	.string	"[INFO] Function pointer initially set to safe_function\n\r"
	.align	3
.LC7:
	.string	"[ATTACK] Overwriting function pointer...\n\r"
	.align	3
.LC8:
	.string	"[INFO] Calling function pointer:\n\r"
	.text
	.align	1
	.globl	test_function_pointer_attack
	.type	test_function_pointer_attack, @function
test_function_pointer_attack:
	addi	sp,sp,-32
	sd	ra,24(sp)
	sd	s0,16(sp)
	addi	s0,sp,32
	lui	a5,%hi(.LC5)
	addi	a0,a5,%lo(.LC5)
	call	printf
	lui	a5,%hi(safe_function)
	addi	a5,a5,%lo(safe_function)
	sd	a5,-24(s0)
	lui	a5,%hi(.LC6)
	addi	a0,a5,%lo(.LC6)
	call	printf
	lui	a5,%hi(.LC7)
	addi	a0,a5,%lo(.LC7)
	call	printf
	lui	a5,%hi(malicious_function)
	addi	a5,a5,%lo(malicious_function)
	sd	a5,-24(s0)
	lui	a5,%hi(.LC8)
	addi	a0,a5,%lo(.LC8)
	call	printf
	ld	a5,-24(s0)
	jalr	a5
	nop
	ld	ra,24(sp)
	ld	s0,16(sp)
	addi	sp,sp,32
	jr	ra
	.size	test_function_pointer_attack, .-test_function_pointer_attack
	.section	.rodata
	.align	3
.LC9:
	.string	"===== [TEST] Invalid Function Pointer Call (Zicfilp) =====\n\r"
	.align	3
.LC10:
	.string	"[INFO] Calling invalid function pointer:\n\r"
	.text
	.align	1
	.globl	test_invalid_function_pointer
	.type	test_invalid_function_pointer, @function
test_invalid_function_pointer:
	addi	sp,sp,-32
	sd	ra,24(sp)
	sd	s0,16(sp)
	addi	s0,sp,32
	lui	a5,%hi(.LC9)
	addi	a0,a5,%lo(.LC9)
	call	printf
	lui	a5,%hi(malicious_function+4)
	addi	a5,a5,%lo(malicious_function+4)
	sd	a5,-24(s0)
	lui	a5,%hi(.LC10)
	addi	a0,a5,%lo(.LC10)
	call	printf
	ld	a5,-24(s0)
	jalr	a5
	nop
	ld	ra,24(sp)
	ld	s0,16(sp)
	addi	sp,sp,32
	jr	ra
	.size	test_invalid_function_pointer, .-test_invalid_function_pointer
	.section	.rodata
	.align	3
.LC11:
	.string	"\n===== [TEST] Return Address Overwrite Attack (Zicfiss) =====\n\r"
	.align	3
.LC12:
	.string	"[INFO] Returning from function:\n\r"
	.text
	.align	1
	.globl	return_address_attack
	.type	return_address_attack, @function
return_address_attack:
	addi	sp,sp,-32
	sd	ra,24(sp)
	sd	s0,16(sp)
	addi	s0,sp,32
	lui	a5,%hi(.LC11)
	addi	a0,a5,%lo(.LC11)
	call	printf
	lui	a5,%hi(safe_function)
	addi	a5,a5,%lo(safe_function)
	sd	a5,-24(s0)
	lui	a5,%hi(malicious_function)
	addi	a5,a5,%lo(malicious_function)
 #APP
# 71 "cfi_test.c" 1
	addi sp, sp, -8
sw a5, 0(sp)

# 0 "" 2
 #NO_APP
	lui	a5,%hi(.LC12)
	addi	a0,a5,%lo(.LC12)
	call	printf
	nop
	ld	ra,24(sp)
	ld	s0,16(sp)
	addi	sp,sp,32
	jr	ra
	.size	return_address_attack, .-return_address_attack
	.ident	"GCC: (gb8636e8768b) 13.3.0"
	.section	.note.GNU-stack,"",@progbits
