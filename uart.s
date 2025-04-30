	.file	"uart.c"
	.option nopic
	.attribute arch, "rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0_zicfilp1p0_zicfiss1p0_zicsr2p0_zifencei2p0"
	.attribute unaligned_access, 0
	.attribute stack_align, 16
	.text
	.align	1
	.globl	setup_uart
	.type	setup_uart, @function
setup_uart:
	addi	sp,sp,-48
	sd	s0,40(sp)
	addi	s0,sp,48
	mv	a5,a0
	sw	a5,-36(s0)
	lw	a5,-36(s0)
	slliw	a5,a5,3
	sext.w	a5,a5
	addiw	a5,a5,7
	sext.w	a5,a5
	li	a4,40001536
	addiw	a4,a4,-1536
	divw	a5,a4,a5
	sw	a5,-20(s0)
	li	a5,16748544
	slli	a5,a5,8
	sd	a5,-32(s0)
	ld	a5,-32(s0)
	addi	a5,a5,12
	lw	a4,-20(s0)
	sw	a4,0(a5)
	ld	a5,-32(s0)
	addi	a5,a5,8
	lw	a5,0(a5)
	sext.w	a4,a5
	ld	a5,-32(s0)
	addi	a5,a5,8
	ori	a4,a4,2
	sext.w	a4,a4
	sw	a4,0(a5)
	nop
	ld	s0,40(sp)
	addi	sp,sp,48
	jr	ra
	.size	setup_uart, .-setup_uart
	.align	1
	.globl	_print_char
	.type	_print_char, @function
_print_char:
	addi	sp,sp,-48
	sd	s0,40(sp)
	addi	s0,sp,48
	mv	a5,a0
	sb	a5,-33(s0)
	li	a5,16748544
	slli	a5,a5,8
	sd	a5,-24(s0)
	ld	a5,-24(s0)
	addi	a5,a5,4
	lw	a5,0(a5)
	sw	a5,-28(s0)
	lw	a5,-28(s0)
	andi	a5,a5,512
	sext.w	a5,a5
	bne	a5,zero,.L3
	lbu	a5,-33(s0)
	sext.w	a4,a5
	ld	a5,-24(s0)
	sw	a4,0(a5)
	li	a5,0
	j	.L4
.L3:
	li	a5,1
.L4:
	mv	a0,a5
	ld	s0,40(sp)
	addi	sp,sp,48
	jr	ra
	.size	_print_char, .-_print_char
	.align	1
	.globl	_print_word
	.type	_print_word, @function
_print_word:
	addi	sp,sp,-48
	sd	ra,40(sp)
	sd	s0,32(sp)
	addi	s0,sp,48
	sd	a0,-40(s0)
	ld	a5,-40(s0)
	sd	a5,-24(s0)
	j	.L6
.L7:
	ld	a5,-24(s0)
	lbu	a5,0(a5)
	mv	a0,a5
	call	_print_char
	mv	a5,a0
	sw	a5,-28(s0)
	lw	a5,-28(s0)
	sext.w	a5,a5
	bne	a5,zero,.L6
	ld	a5,-24(s0)
	addi	a5,a5,1
	sd	a5,-24(s0)
.L6:
	ld	a5,-24(s0)
	lbu	a5,0(a5)
	bne	a5,zero,.L7
	nop
	nop
	ld	ra,40(sp)
	ld	s0,32(sp)
	addi	sp,sp,48
	jr	ra
	.size	_print_word, .-_print_word
	.align	1
	.globl	printf
	.type	printf, @function
printf:
	addi	sp,sp,-624
	sd	ra,552(sp)
	sd	s0,544(sp)
	addi	s0,sp,560
	sd	a0,-552(s0)
	sd	a1,8(s0)
	sd	a2,16(s0)
	sd	a3,24(s0)
	sd	a4,32(s0)
	sd	a5,40(s0)
	sd	a6,48(s0)
	sd	a7,56(s0)
	addi	a5,s0,64
	sd	a5,-560(s0)
	ld	a5,-560(s0)
	addi	a5,a5,-56
	sd	a5,-24(s0)
	ld	a4,-24(s0)
	addi	a5,s0,-536
	mv	a2,a4
	ld	a1,-552(s0)
	mv	a0,a5
	call	vsprintf
	addi	a5,s0,-536
	mv	a0,a5
	call	_print_word
	li	a5,0
	mv	a0,a5
	ld	ra,552(sp)
	ld	s0,544(sp)
	addi	sp,sp,624
	jr	ra
	.size	printf, .-printf
	.ident	"GCC: (gb8636e8768b) 13.3.0"
	.section	.note.GNU-stack,"",@progbits
