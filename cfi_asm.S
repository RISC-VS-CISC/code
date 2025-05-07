/**
 * cfi_asm.S - Assembly implementation of CFI for RISC-V
 *
 * Low-level assembly functions for CFI on RISC-V
 */

.section .data
/* External symbols from C code - these must match cfi.c */
.global shadow_stack
.global shadow_stack_top

/* Constants */
.equ SHADOW_STACK_SIZE, 1024

.section .text
.global _cfi_function_enter
.global _cfi_function_exit

/**
 * RISC-V assembly implementation of CFI function entry
 * a0: function ID
 */
_cfi_function_enter:
    /* Save caller registers */
    addi sp, sp, -16          /* Allocate stack space */
    sw ra, 0(sp)              /* Save return address */
    sw s0, 4(sp)              /* Save frame pointer */
    sw s1, 8(sp)              /* Save s1 */
    
    /* Load shadow stack pointer */
    la t0, shadow_stack_top
    lw t1, 0(t0)              /* t1 = shadow_stack_top */
    
    /* Check for overflow */
    li t2, SHADOW_STACK_SIZE
    bge t1, t2, _cfi_error    /* If t1 >= SHADOW_STACK_SIZE, error */
    
    /* Store return address in shadow stack */
    la t2, shadow_stack
    slli t3, t1, 2            /* t3 = t1 * 4 (word size) */
    add t2, t2, t3            /* t2 = shadow_stack + t1*4 */
    sw ra, 0(t2)              /* shadow_stack[top] = ra */
    
    /* Store function ID in shadow stack */
    addi t1, t1, 1            /* shadow_stack_top++ */
    sw a0, 4(t2)              /* shadow_stack[top+1] = function_id */
    
    /* Update shadow stack top */
    addi t1, t1, 2            /* shadow_stack_top += 2 */
    sw t1, 0(t0)              /* Store updated top */
    
    /* Restore caller registers */
    lw ra, 0(sp)
    lw s0, 4(sp)
    lw s1, 8(sp)
    addi sp, sp, 16
    ret

/**
 * RISC-V assembly implementation of CFI function exit
 * a0: expected function ID
 */
_cfi_function_exit:
    /* Save caller registers */
    addi sp, sp, -16          /* Allocate stack space */
    sw ra, 0(sp)              /* Save return address */
    sw s0, 4(sp)              /* Save frame pointer */
    sw s1, 8(sp)              /* Save s1 */
    
    /* Load shadow stack pointer */
    la t0, shadow_stack_top
    lw t1, 0(t0)              /* t1 = shadow_stack_top */
    
    /* Check for underflow */
    li t2, 2
    blt t1, t2, _cfi_error    /* If t1 < 2, error */
    
    /* Get function ID from shadow stack */
    addi t1, t1, -1           /* top-- */
    la t2, shadow_stack
    slli t3, t1, 2            /* t3 = t1 * 4 */
    add t2, t2, t3            /* t2 = shadow_stack + t1*4 */
    lw t4, 0(t2)              /* t4 = shadow_stack[top] (function ID) */
    
    /* Compare function IDs */
    bne t4, a0, _cfi_error    /* If stored ID != expected ID, error */
    
    /* Get return address from shadow stack */
    addi t1, t1, -1           /* top-- */
    slli t3, t1, 2            /* t3 = t1 * 4 */
    add t2, t2, t3            /* t2 = shadow_stack + t1*4 */
    lw t5, 0(t2)              /* t5 = shadow_stack[top-1] (return address) */
    
    /* Update shadow stack top */
    sw t1, 0(t0)              /* Store updated top */
    
    /* Check if return address matches what's in ra */
    lw t6, 0(sp)              /* t6 = saved ra */
    bne t5, t6, _cfi_error    /* If shadow ra != actual ra, error */
    
    /* Restore caller registers */
    lw ra, 0(sp)
    lw s0, 4(sp)
    lw s1, 8(sp)
    addi sp, sp, 16
    ret

/**
 * CFI error handler
 */
_cfi_error:
    /* For simple implementation, just terminate program */
    li a7, 93                 /* exit syscall number */
    li a0, 1                  /* exit code 1 - error */
    ecall                     /* syscall */
    
    /* Should never reach here */
    ret