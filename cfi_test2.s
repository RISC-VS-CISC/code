	.file	"cfi_test2.c"
	.option nopic
	.attribute arch, "rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0_zicfilp1p0_zicfiss1p0_zicsr2p0_zifencei2p0"
	.attribute unaligned_access, 0
	.attribute stack_align, 16
	.text
	.section	.rodata
	.align	3
.LC0:
	.string	"[INFO] Secure function executed successfully."
	.text
	.align	1
	.globl	secure_function
	.type	secure_function, @function
secure_function:
.LFB6:
	.cfi_startproc
	addi	sp,sp,-16
	.cfi_def_cfa_offset 16
	sd	ra,8(sp)
	sd	s0,0(sp)
	.cfi_offset 1, -8
	.cfi_offset 8, -16
	addi	s0,sp,16
	.cfi_def_cfa 8, 0
	lui	a5,%hi(.LC0)
	addi	a0,a5,%lo(.LC0)
	call	puts
	nop
	ld	ra,8(sp)
	.cfi_restore 1
	ld	s0,0(sp)
	.cfi_restore 8
	.cfi_def_cfa 2, 16
	addi	sp,sp,16
	.cfi_def_cfa_offset 0
	jr	ra
	.cfi_endproc
.LFE6:
	.size	secure_function, .-secure_function
	.section	.rodata
	.align	3
.LC1:
	.string	"[ALERT] Security Breach: Malicious function executed!"
	.text
	.align	1
	.globl	hijacked_function
	.type	hijacked_function, @function
hijacked_function:
.LFB7:
	.cfi_startproc
	addi	sp,sp,-16
	.cfi_def_cfa_offset 16
	sd	ra,8(sp)
	sd	s0,0(sp)
	.cfi_offset 1, -8
	.cfi_offset 8, -16
	addi	s0,sp,16
	.cfi_def_cfa 8, 0
	lui	a5,%hi(.LC1)
	addi	a0,a5,%lo(.LC1)
	call	puts
	nop
	ld	ra,8(sp)
	.cfi_restore 1
	ld	s0,0(sp)
	.cfi_restore 8
	.cfi_def_cfa 2, 16
	addi	sp,sp,16
	.cfi_def_cfa_offset 0
	jr	ra
	.cfi_endproc
.LFE7:
	.size	hijacked_function, .-hijacked_function
	.section	.rodata
	.align	3
.LC2:
	.string	"\n[TEST] Return Address Attack (Zicfiss Protection)"
	.align	3
.LC3:
	.string	"[INFO] Original return address: %p\n"
	.align	3
.LC4:
	.string	"[ATTACK] Overwritten return address: %p\n"
	.text
	.align	1
	.globl	return_address_attack
	.type	return_address_attack, @function
return_address_attack:
.LFB8:
	.cfi_startproc
	addi	sp,sp,-32
	.cfi_def_cfa_offset 32
	sd	ra,24(sp)
	sd	s0,16(sp)
	.cfi_offset 1, -8
	.cfi_offset 8, -16
	addi	s0,sp,32
	.cfi_def_cfa 8, 0
	lui	a5,%hi(.LC2)
	addi	a0,a5,%lo(.LC2)
	call	puts
#APP
# 22 "/home/abentley/CFI_Tests/cfi_test2.c" 1
	mv a5, ra
# 0 "" 2
#NO_APP
	sd	a5,-24(s0)
	ld	a1,-24(s0)
	lui	a5,%hi(.LC3)
	addi	a0,a5,%lo(.LC3)
	call	printf
	lui	a5,%hi(hijacked_function)
	addi	a5,a5,%lo(hijacked_function)
	sd	a5,-32(s0)
	ld	a5,-32(s0)
#APP
# 28 "/home/abentley/CFI_Tests/cfi_test2.c" 1
	mv ra, a5
# 0 "" 2
#NO_APP
	ld	a1,-32(s0)
	lui	a5,%hi(.LC4)
	addi	a0,a5,%lo(.LC4)
	call	printf
	nop
	ld	ra,24(sp)
	.cfi_restore 1
	ld	s0,16(sp)
	.cfi_restore 8
	.cfi_def_cfa 2, 32
	addi	sp,sp,32
	.cfi_def_cfa_offset 0
	jr	ra
	.cfi_endproc
.LFE8:
	.size	return_address_attack, .-return_address_attack
	.section	.rodata
	.align	3
.LC5:
	.string	"\n[TEST] Function Pointer Hijack (Zicfilp Protection)"
	.align	3
.LC6:
	.string	"[INFO] Function pointer initially set to secure_function."
	.align	3
.LC7:
	.string	"[ATTACK] Function pointer overwritten!"
	.align	3
.LC8:
	.string	"[INFO] Calling function pointer..."
	.text
	.align	1
	.globl	function_pointer_attack
	.type	function_pointer_attack, @function
function_pointer_attack:
.LFB9:
	.cfi_startproc
	addi	sp,sp,-32
	.cfi_def_cfa_offset 32
	sd	ra,24(sp)
	sd	s0,16(sp)
	.cfi_offset 1, -8
	.cfi_offset 8, -16
	addi	s0,sp,32
	.cfi_def_cfa 8, 0
	lui	a5,%hi(secure_function)
	addi	a5,a5,%lo(secure_function)
	sd	a5,-24(s0)
	lui	a5,%hi(.LC5)
	addi	a0,a5,%lo(.LC5)
	call	puts
	lui	a5,%hi(.LC6)
	addi	a0,a5,%lo(.LC6)
	call	puts
	lui	a5,%hi(hijacked_function)
	addi	a5,a5,%lo(hijacked_function)
	sd	a5,-24(s0)
	lui	a5,%hi(.LC7)
	addi	a0,a5,%lo(.LC7)
	call	puts
	lui	a5,%hi(.LC8)
	addi	a0,a5,%lo(.LC8)
	call	puts
	ld	a5,-24(s0)
	jalr	a5
	nop
	ld	ra,24(sp)
	.cfi_restore 1
	ld	s0,16(sp)
	.cfi_restore 8
	.cfi_def_cfa 2, 32
	addi	sp,sp,32
	.cfi_def_cfa_offset 0
	jr	ra
	.cfi_endproc
.LFE9:
	.size	function_pointer_attack, .-function_pointer_attack
	.section	.rodata
	.align	3
.LC9:
	.string	"\n===== RISC-V Security Test: Zicfiss & Zicfilp ====="
	.align	3
.LC10:
	.string	"\n[TEST] Normal Function Execution"
	.text
	.align	1
	.globl	main
	.type	main, @function
main:
.LFB10:
	.cfi_startproc
	addi	sp,sp,-16
	.cfi_def_cfa_offset 16
	sd	ra,8(sp)
	sd	s0,0(sp)
	.cfi_offset 1, -8
	.cfi_offset 8, -16
	addi	s0,sp,16
	.cfi_def_cfa 8, 0
	lui	a5,%hi(.LC9)
	addi	a0,a5,%lo(.LC9)
	call	puts
	lui	a5,%hi(.LC10)
	addi	a0,a5,%lo(.LC10)
	call	puts
	call	secure_function
	call	return_address_attack
	call	function_pointer_attack
	li	a5,0
	mv	a0,a5
	ld	ra,8(sp)
	.cfi_restore 1
	ld	s0,0(sp)
	.cfi_restore 8
	.cfi_def_cfa 2, 16
	addi	sp,sp,16
	.cfi_def_cfa_offset 0
	jr	ra
	.cfi_endproc
.LFE10:
	.size	main, .-main
	.ident	"GCC: (gb8636e8768b) 13.3.0"
	.section	.note.GNU-stack,"",@progbits
