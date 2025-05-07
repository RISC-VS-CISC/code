/**
 * test_cfi.c - Test case for RISC-V Control Flow Integrity
 *
 * Example demonstrating how to use the CFI protection mechanisms
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include "cfi.h"
 
 /**
  * A secure function protected by CFI
  */
 void secure_function(int param) {
     /* CFI Function entry check */
     CFI_FUNCTION_ENTRY(0x2001);
     
     printf("Secure function called with parameter: %d\n", param);
     
     /* Simulate some sensitive operation */
     if (param < 0) {
         printf("Warning: Negative parameter detected\n");
     } else {
         printf("Processing data with security protection...\n");
     }
     
     /* CFI Function exit check */
     CFI_FUNCTION_EXIT();
 }
 
 /**
  * Another function to demonstrate multiple CFI protections
  */
 void another_secure_function(const char* input) {
     /* CFI Function entry check */
     CFI_FUNCTION_ENTRY(0x2002);
     
     printf("Processing sensitive data: %s\n", input);
     
     /* Simulate processing with bounds checking */
     if (input && strlen(input) < 100) {
         printf("Input validated and processed securely\n");
     } else {
         printf("Input validation failed\n");
     }
     
     /* CFI Function exit check */
     CFI_FUNCTION_EXIT();
 }
 
 /* Attack function that tries to corrupt control flow */
 void attack_function(void) {
     printf("!!! ATTACK ATTEMPT: Trying to corrupt control flow !!!\n");
     
     /* Attempt to corrupt CFI checks */
     uint32_t* memory = (uint32_t*)malloc(1024);
     for (int i = 0; i < 256; i++) {
         memory[i] = 0xDEADBEEF; /* Corrupt memory with invalid patterns */
     }
     
     /* In a real attack, this might be more sophisticated */
 }
 
 /* Function pointer type for demonstration */
 typedef void (*func_ptr_t)(int);
 typedef void (*str_func_ptr_t)(const char*);
 
 /**
  * Main test function
  */
 int main() {
     /* Initialize CFI protection */
     init_cfi();
     
     /* Register functions in the CFI database */
     register_function_cfi((void*)secure_function, 0x2001);
     register_function_cfi((void*)another_secure_function, 0x2002);
     
     printf("=== RISC-V Control Flow Integrity Test ===\n\n");
     
     /* Test 1: Direct function call (safe) */
     printf("Test 1: Direct function call\n");
     secure_function(42);
     printf("Direct call test passed!\n\n");
     
     /* Test 2: Indirect function call with CFI check */
     printf("Test 2: Indirect function call with validation\n");
     func_ptr_t func_ptr = secure_function;
     
     /* Validate before indirect call */
     if (cfi_validate_indirect_call((void*)func_ptr, 0x2001)) {
         func_ptr(123);
         printf("Indirect call test passed!\n\n");
     }
     
     /* Test 3: Another secure function */
     printf("Test 3: Another secure function call\n");
     another_secure_function("Test secure data");
     printf("Multiple function test passed!\n\n");
     
     /* Test 4: Function pointer array with validation */
     printf("Test 4: Function pointer array with validation\n");
     str_func_ptr_t str_functions[1] = { another_secure_function };
     
     if (cfi_validate_indirect_call((void*)str_functions[0], 0x2002)) {
         str_functions[0]("Array function pointer test");
         printf("Function pointer array test passed!\n\n");
     }
     
     /* Uncomment for attack simulation test */
     /*
     printf("Test 5: Attack simulation (should trigger CFI error)\n");
     attack_function();
     secure_function(999); // This should detect corruption and fail
     */
     
     printf("All CFI tests passed successfully!\n");
     return 0;
 }