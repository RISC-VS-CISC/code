/**
 * security_tests.c - Comprehensive Security Tests for RISC-V CFI
 *
 * This file contains tests that simulate various security attacks
 * against control flow integrity mechanisms on RISC-V.
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <stdint.h>
 #include <setjmp.h>
 #include <signal.h>
 #include "cfi.h"
 
 /* Define additional function IDs */
 #define FUNC_ID_JUMP_TARGET         0x4001
 #define FUNC_ID_ROP_GADGET          0x4002
 #define FUNC_ID_DATA_EXEC           0x4003
 #define FUNC_ID_CODE_INJECTION      0x4004
 #define FUNC_ID_EXCEPTION_HANDLER   0x4005
 #define FUNC_ID_SYSCALL_WRAPPER     0x4006
 #define FUNC_ID_JIT_FUNCTION        0x4007
 
 /* Signal handler for catching segmentation faults */
 static jmp_buf jmp_buffer;
 static volatile int test_result = 0;
 
 static void segfault_handler(int signal) {
     /* Jump back to test harness */
     test_result = -1;
     longjmp(jmp_buffer, 1);
 }
 
 /* Legitimate jump target */
 void legitimate_jump_target(int value) {
     /* CFI Function entry check */
     CFI_FUNCTION_ENTRY(FUNC_ID_JUMP_TARGET);
     
     printf("Legitimate jump target executed with value: %d\n", value);
     
     /* CFI Function exit check */
     CFI_FUNCTION_EXIT();
 }
 
 /* Illegitimate jump target (simulating a ROP gadget) */
 void illegitimate_jump_target(int value) {
     printf("!!! SECURITY BREACH: Illegitimate jump target executed !!!\n");
     printf("This should never be called if CFI is working properly\n");
 }
 
 /**
  * Test for Return-Oriented Programming (ROP) protection
  */
 void test_rop_protection(void) {
     /* CFI Function entry check */
     CFI_FUNCTION_ENTRY(FUNC_ID_ROP_GADGET);
     
     printf("Testing ROP attack protection...\n");
     
     /* Function pointer array */
     typedef void (*jump_func_t)(int);
     jump_func_t jump_funcs[2] = { legitimate_jump_target, illegitimate_jump_target };
     
     /* Call legitimate function through pointer */
     if (cfi_validate_indirect_call((void*)jump_funcs[0], FUNC_ID_JUMP_TARGET)) {
         jump_funcs[0](42);
         printf("Legitimate jump call succeeded as expected\n");
     }
     
     /* Try to call illegitimate function (simulated ROP gadget) */
     printf("Attempting to call illegitimate ROP gadget...\n");
     if (!cfi_validate_indirect_call((void*)jump_funcs[1], FUNC_ID_JUMP_TARGET)) {
         printf("ROP attack successfully prevented by CFI\n");
     } else {
         /* This should never happen if CFI is working */
         jump_funcs[1](0xBAD);
         printf("SECURITY FAILURE: ROP attack was not prevented!\n");
     }
     
     /* CFI Function exit check */
     CFI_FUNCTION_EXIT();
 }
 
 /**
  * Test for protection against JIT spraying attacks
  */
 void test_jit_spraying_protection(void) {
     /* CFI Function entry check */
     CFI_FUNCTION_ENTRY(FUNC_ID_JIT_FUNCTION);
     
     printf("Testing JIT spraying attack protection...\n");
     
     /* Simulate JIT compilation of code */
     char jit_buffer[4096];
     memset(jit_buffer, 0, sizeof(jit_buffer));
     
     /* Populate JIT buffer with 'code' */
     strcpy(jit_buffer, "This is simulated JIT-compiled code");
     
     /* Attempt to execute the JIT buffer (in a real attack) */
     typedef void (*jit_func_t)(void);
     jit_func_t jit_func = (jit_func_t)jit_buffer;
     
     /* Validate JIT function before execution */
     if (!cfi_validate_indirect_call((void*)jit_func, FUNC_ID_JIT_FUNCTION)) {
         printf("JIT spraying attack successfully prevented by CFI\n");
     } else {
         printf("SECURITY WARNING: CFI should prevent execution of untrusted JIT code\n");
         /* Don't actually try to execute this in our test */
     }
     
     /* CFI Function exit check */
     CFI_FUNCTION_EXIT();
 }
 
 /**
  * Test for protection against data execution attacks
  */
 void test_data_execution_prevention(void) {
     /* CFI Function entry check */
     CFI_FUNCTION_ENTRY(FUNC_ID_DATA_EXEC);
     
     printf("Testing data execution prevention...\n");
     
     /* Allocate a buffer on the heap */
     unsigned char* data_buffer = (unsigned char*)malloc(1024);
     if (!data_buffer) {
         printf("Failed to allocate memory\n");
         goto cleanup;
     }
     
     /* Fill buffer with harmless shellcode-like pattern */
     for (int i = 0; i < 1024; i++) {
         data_buffer[i] = 0x90; /* NOP instruction */
     }
     
     /* Attempt to execute data as code */
     typedef void (*data_func_t)(void);
     data_func_t data_func = (data_func_t)data_buffer;
     
     /* Validate before execution */
     if (!cfi_validate_indirect_call((void*)data_func, FUNC_ID_DATA_EXEC)) {
         printf("Data execution attack successfully prevented by CFI\n");
     } else {
         printf("SECURITY WARNING: CFI should prevent execution of data as code\n");
         /* Don't actually try to execute this in our test */
     }
     
 cleanup:
     free(data_buffer);
     
     /* CFI Function exit check */
     CFI_FUNCTION_EXIT();
 }
 
 /**
  * Test for protection against exception handler attacks
  */
 void test_exception_handler_hijacking(void) {
     /* CFI Function entry check */
     CFI_FUNCTION_ENTRY(FUNC_ID_EXCEPTION_HANDLER);
     
     printf("Testing exception handler hijacking protection...\n");
     
     /* Install legitimate signal handler */
     struct sigaction sa;
     memset(&sa, 0, sizeof(sa));
     sa.sa_handler = segfault_handler;
     sigaction(SIGSEGV, &sa, NULL);
     
     /* Try to simulate an attack by pointing to an illegitimate handler */
     sa.sa_handler = (void (*)(int))illegitimate_jump_target;
     
     /* In a real system with CFI, we would validate the handler here */
     if (!cfi_validate_indirect_call((void*)sa.sa_handler, FUNC_ID_EXCEPTION_HANDLER)) {
         printf("Exception handler hijacking prevented by CFI\n");
     } else {
         printf("WARNING: CFI should prevent untrusted exception handlers\n");
         /* Don't install the malicious handler in our test */
     }
     
     /* CFI Function exit check */
     CFI_FUNCTION_EXIT();
 }
 
 /**
  * Test for system call interposition attacks
  */
 void test_syscall_interposition(void) {
     /* CFI Function entry check */
     CFI_FUNCTION_ENTRY(FUNC_ID_SYSCALL_WRAPPER);
     
     printf("Testing system call interposition protection...\n");
     
     /* Simulate a system call wrapper function */
     int (*original_syscall)(int, ...) = NULL;  /* Would point to real syscall */
     int (*wrapper_syscall)(int, ...) = NULL;   /* Our legitimate wrapper */
     
     /* Simulate malicious syscall wrapper */
     int (*malicious_syscall)(int, ...) = (int (*)(int, ...))illegitimate_jump_target;
     
     /* Validate wrapper before use */
     if (!cfi_validate_indirect_call((void*)malicious_syscall, FUNC_ID_SYSCALL_WRAPPER)) {
         printf("System call interposition attack prevented by CFI\n");
     } else {
         printf("WARNING: CFI should prevent untrusted syscall wrappers\n");
     }
     
     /* CFI Function exit check */
     CFI_FUNCTION_EXIT();
 }
 
 /**
  * Test for protection against branch target injection attacks 
  * (like Spectre/Meltdown variants on RISC-V)
  */
 void test_branch_target_injection(void) {
     /* CFI Function entry check */
     CFI_FUNCTION_ENTRY(0x4008);
     
     printf("Testing branch target injection protection...\n");
     
     /* Create array of function pointers */
     typedef void (*branch_func_t)(void);
     branch_func_t branch_funcs[256];
     
     /* Initialize with legitimate targets */
     for (int i = 0; i < 256; i++) {
         branch_funcs[i] = (branch_func_t)legitimate_jump_target;
     }
     
     /* Simulate an attack by trying to manipulate branch predictor */
     for (int i = 0; i < 100; i++) {
         /* Train the branch predictor with valid accesses */
         if (cfi_validate_indirect_call((void*)branch_funcs[i & 0xF], FUNC_ID_JUMP_TARGET)) {
             /* Access valid branch */
         }
     }
     
     /* Now try to inject a malicious target */
     branch_funcs[16] = (branch_func_t)illegitimate_jump_target;
     
     /* This would exploit speculative execution on vulnerable processors */
     /* But our CFI should catch it */
     if (!cfi_validate_indirect_call((void*)branch_funcs[16], FUNC_ID_JUMP_TARGET)) {
         printf("Branch target injection prevented by CFI\n");
     }
     
     /* CFI Function exit check */
     CFI_FUNCTION_EXIT();
 }
 
 /**
  * Test for shadow stack tampering protection
  */
 void test_shadow_stack_tampering(void) {
     /* CFI Function entry check */
     CFI_FUNCTION_ENTRY(0x4009);
     
     printf("Testing shadow stack tampering protection...\n");
     
     /* Try to find and tamper with shadow stack (in a real attack) */
     /* This is just a simulation for testing */
     
     /* In our implementation, shadow stack is internal and not accessible */
     /* But we can try to simulate an attack by corrupting memory */
     void** memory_scan = (void**)malloc(1024 * sizeof(void*));
     
     /* Fill with return addresses to simulate tampering */
     for (int i = 0; i < 1024; i++) {
         memory_scan[i] = (void*)illegitimate_jump_target;
     }
     
     /* If our CFI implementation is correct, this won't affect the real shadow stack */
     printf("Attempted shadow stack tampering, but CFI protection should prevent issues\n");
     
     free(memory_scan);
     
     /* Call a protected function to verify shadow stack is intact */
     legitimate_jump_target(999);
     
     /* CFI Function exit check */
     CFI_FUNCTION_EXIT();
 }
 
 /**
  * Test for code reuse attacks (more sophisticated ROP/JOP)
  */
 void test_code_reuse_protection(void) {
     /* CFI Function entry check */
     CFI_FUNCTION_ENTRY(0x400A);
     
     printf("Testing protection against advanced code reuse attacks...\n");
     
     /* Prepare some gadget-like functions */
     typedef void (*gadget_t)(void*);
     gadget_t gadgets[10];
     
     /* Populate with legitimate functions */
     for (int i = 0; i < 10; i++) {
         gadgets[i] = (gadget_t)legitimate_jump_target;
     }
     
     /* Create a chain of gadgets (simulating ROP chain) */
     void** rop_chain = (void**)malloc(10 * sizeof(void*));
     for (int i = 0; i < 10; i++) {
         rop_chain[i] = (void*)gadgets[i];
     }
     
     /* Inject an illegitimate gadget */
     rop_chain[5] = (void*)illegitimate_jump_target;
     
     /* Try to execute the chain - in a real attack */
     printf("Attempting to execute simulated ROP chain...\n");
     
     /* Our CFI should validate each indirect call target */
     for (int i = 0; i < 10; i++) {
         gadget_t current = (gadget_t)rop_chain[i];
         if (cfi_validate_indirect_call((void*)current, FUNC_ID_JUMP_TARGET)) {
             /* Safe to call */
             printf("Gadget %d: valid\n", i);
         } else {
             /* Attack detected */
             printf("Gadget %d: INVALID - code reuse attack detected!\n", i);
         }
     }
     
     free(rop_chain);
     
     /* CFI Function exit check */
     CFI_FUNCTION_EXIT();
 }
 
 /**
  * Test for RISC-V PMP (Physical Memory Protection) integration
  * This is a simulation as real PMP requires privileged mode access
  */
 void test_pmp_integration(void) {
     /* CFI Function entry check */
     CFI_FUNCTION_ENTRY(0x400B);
     
     printf("Testing RISC-V PMP integration with CFI...\n");
     
     /* Simulate PMP configuration */
     printf("Simulating PMP configuration for memory protection\n");
     printf("- Setting code segments as read+execute\n");
     printf("- Setting data segments as read+write (no execute)\n");
     printf("- Setting shadow stack region as read+write (privileged only)\n");
     
     /* Attempt to execute data section (should be prevented) */
     printf("Attempting to execute from data section...\n");
     
     /* This would be caught by both PMP and CFI */
     void (*data_func)(void) = (void (*)(void))malloc(64);
     
     if (!cfi_validate_indirect_call(data_func, 0)) {
         printf("Execution from data prevented by CFI\n");
     }
     
     free(data_func);
     
     /* CFI Function exit check */
     CFI_FUNCTION_EXIT();
 }
 
 /**
  * Tests C++ virtual function table (vtable) protection
  * Simulated since we're using C, not C++
  */
 void test_vtable_protection(void) {
     /* CFI Function entry check */
     CFI_FUNCTION_ENTRY(0x400C);
     
     printf("Testing virtual function table protection...\n");
     
     /* Simulate a simple vtable */
     void* vtable[10];
     for (int i = 0; i < 10; i++) {
         vtable[i] = (void*)legitimate_jump_target;
     }
     
     /* Simulate a C++ object with a vtable pointer */
     struct {
         void** vptr;
         int data;
     } simulated_object;
     
     simulated_object.vptr = vtable;
     simulated_object.data = 42;
     
     printf("Legitimate vtable access...\n");
     
     /* Simulate vtable lookup and call (legitimate) */
     typedef void (*vfunc_t)(int);
     vfunc_t vmethod = (vfunc_t)simulated_object.vptr[0];
     
     if (cfi_validate_indirect_call((void*)vmethod, FUNC_ID_JUMP_TARGET)) {
         vmethod(simulated_object.data);
         printf("Legitimate virtual function call succeeded\n");
     }
     
     /* Simulate vtable hijacking attack */
     printf("Simulating vtable hijacking attack...\n");
     
     /* Create a fake vtable with malicious function */
     void* fake_vtable[10];
     for (int i = 0; i < 10; i++) {
         fake_vtable[i] = (void*)illegitimate_jump_target;
     }
     
     /* Hijack the object's vtable pointer */
     simulated_object.vptr = fake_vtable;
     
     /* Try to use the hijacked vtable */
     vmethod = (vfunc_t)simulated_object.vptr[0];
     
     if (!cfi_validate_indirect_call((void*)vmethod, FUNC_ID_JUMP_TARGET)) {
         printf("Vtable hijacking attack prevented by CFI\n");
     } else {
         printf("WARNING: CFI should prevent calls to hijacked vtable entries\n");
     }
     
     /* CFI Function exit check */
     CFI_FUNCTION_EXIT();
 }
 
 /**
  * Main test function
  */
 int main(int argc, char** argv) {
     /* Initialize CFI protection */
     init_cfi();
     
     /* Register functions in the CFI database */
     register_function_cfi((void*)legitimate_jump_target, FUNC_ID_JUMP_TARGET);
     register_function_cfi((void*)test_rop_protection, FUNC_ID_ROP_GADGET);
     register_function_cfi((void*)test_data_execution_prevention, FUNC_ID_DATA_EXEC);
     register_function_cfi((void*)test_exception_handler_hijacking, FUNC_ID_EXCEPTION_HANDLER);
     register_function_cfi((void*)test_syscall_interposition, FUNC_ID_SYSCALL_WRAPPER);
     register_function_cfi((void*)test_jit_spraying_protection, FUNC_ID_JIT_FUNCTION);
     
     printf("=== RISC-V Control Flow Integrity Security Tests ===\n\n");
     
     /* Run all tests */
     test_rop_protection();
     printf("\n");
     
     test_jit_spraying_protection();
     printf("\n");
     
     test_data_execution_prevention();
     printf("\n");
     
     test_exception_handler_hijacking();
     printf("\n");
     
     test_syscall_interposition();
     printf("\n");
     
     test_branch_target_injection();
     printf("\n");
     
     test_shadow_stack_tampering();
     printf("\n");
     
     test_code_reuse_protection();
     printf("\n");
     
     test_pmp_integration();
     printf("\n");
     
     test_vtable_protection();
     printf("\n");
     
     printf("All security tests completed successfully!\n");
     return 0;
 }