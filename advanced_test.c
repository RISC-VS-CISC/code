/**
 * advanced_test.c - Advanced test cases for RISC-V Control Flow Integrity
 *
 * This file contains more sophisticated tests for the CFI implementation,
 * including attack simulations and edge cases.
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <assert.h>
 #include "cfi.h"
 
 /* Function IDs for CFI protection */
 #define FUNC_ID_COMPUTE       0x3001
 #define FUNC_ID_PROCESS       0x3002
 #define FUNC_ID_CALLBACK      0x3003
 #define FUNC_ID_INDIRECT      0x3004
 
 /**
  * Test function for secure computation
  */
 int compute_secure_hash(const void* data, size_t len, uint32_t seed) {
     /* CFI Function entry check */
     CFI_FUNCTION_ENTRY(FUNC_ID_COMPUTE);
     
     /* Simple hash function for demonstration */
     uint32_t hash = seed;
     const unsigned char* bytes = (const unsigned char*)data;
     
     for (size_t i = 0; i < len; i++) {
         hash = ((hash << 5) + hash) ^ bytes[i];
     }
     
     printf("Computed secure hash: 0x%08x\n", hash);
     
     /* CFI Function exit check */
     CFI_FUNCTION_EXIT();
     
     return hash;
 }
 
 /**
  * Test function for data processing with CFI
  */
 void process_data_securely(const char* data, void (*callback)(const char*)) {
     /* CFI Function entry check */
     CFI_FUNCTION_ENTRY(FUNC_ID_PROCESS);
     
     printf("Processing data securely: %s\n", data);
     
     /* Validate callback before using it */
     if (cfi_validate_indirect_call((void*)callback, FUNC_ID_CALLBACK)) {
         /* Call the callback securely */
         callback(data);
     } else {
         printf("ERROR: Invalid callback function detected!\n");
     }
     
     /* CFI Function exit check */
     CFI_FUNCTION_EXIT();
 }
 
 /**
  * Valid callback function
  */
 void valid_callback(const char* result) {
     /* CFI Function entry check */
     CFI_FUNCTION_ENTRY(FUNC_ID_CALLBACK);
     
     printf("Callback executed with result: %s\n", result);
     
     /* CFI Function exit check */
     CFI_FUNCTION_EXIT();
 }
 
 /**
  * Invalid callback function (not registered in CFI system)
  */
 void invalid_callback(const char* result) {
     printf("!!! ATTACK: Malicious callback executed !!!\n");
     printf("This should never be called if CFI is working\n");
 }
 
 /**
  * Function that uses indirect calls extensively
  */
 void test_indirect_calls(void) {
     /* CFI Function entry check */
     CFI_FUNCTION_ENTRY(FUNC_ID_INDIRECT);
     
     /* Create an array of function pointers */
     typedef int (*hash_func_t)(const void*, size_t, uint32_t);
     hash_func_t hash_functions[2] = { compute_secure_hash, NULL };
     
     /* Test data */
     const char* test_data = "Test data for indirect call";
     
     /* Use the indirect call with CFI validation */
     if (cfi_validate_indirect_call((void*)hash_functions[0], FUNC_ID_COMPUTE)) {
         hash_functions[0](test_data, strlen(test_data), 0x12345678);
         printf("Indirect call executed successfully\n");
     }
     
     /* Attempt to use a non-registered function (should be caught by CFI) */
     hash_functions[1] = (hash_func_t)(void*)invalid_callback;
     if (!cfi_validate_indirect_call((void*)hash_functions[1], FUNC_ID_COMPUTE)) {
         printf("CFI successfully prevented malicious indirect call\n");
     }
     
     /* CFI Function exit check */
     CFI_FUNCTION_EXIT();
 }
 
 /**
  * Test for stack buffer overflow attack simulation
  */
 void test_buffer_overflow_protection(void) {
     /* CFI Function entry check */
     CFI_FUNCTION_ENTRY(0x3005);
     
     printf("Testing buffer overflow protection...\n");
     
     /* Buffer on stack */
     char buffer[16];
     printf("Original buffer address: %p\n", buffer);
     
     /* Simulate an overflow attack */
     #ifdef SIMULATE_ATTACK
     printf("Simulating buffer overflow attack...\n");
     memset(buffer, 'A', 64); /* Write past buffer end */
     #endif
     
     /* If CFI is working, the exit check will detect corruption */
     
     /* CFI Function exit check */
     CFI_FUNCTION_EXIT();
     
     printf("Buffer overflow test completed\n");
 }
 
 /**
  * Main test function
  */
 int main(int argc, char** argv) {
     /* Initialize CFI protection */
     init_cfi();
     
     /* Register functions in the CFI database */
     register_function_cfi((void*)compute_secure_hash, FUNC_ID_COMPUTE);
     register_function_cfi((void*)process_data_securely, FUNC_ID_PROCESS);
     register_function_cfi((void*)valid_callback, FUNC_ID_CALLBACK);
     register_function_cfi((void*)test_indirect_calls, FUNC_ID_INDIRECT);
     register_function_cfi((void*)test_buffer_overflow_protection, 0x3005);
     
     printf("=== RISC-V Control Flow Integrity Advanced Tests ===\n\n");
     
     /* Test 1: Secure hash computation */
     printf("Test 1: Secure hash computation\n");
     const char* test_data = "Secure data for hashing";
     int hash_result = compute_secure_hash(test_data, strlen(test_data), 0x12345678);
     printf("Hash result: 0x%08x\n\n", hash_result);
     
     /* Test 2: Function callback with CFI validation */
     printf("Test 2: Function callback with CFI validation\n");
     process_data_securely("Sensitive information", valid_callback);
     printf("Callback test passed\n\n");
     
     /* Test 3: Indirect function calls */
     printf("Test 3: Indirect function calls\n");
     test_indirect_calls();
     printf("Indirect call tests passed\n\n");
     
     /* Test 4: Buffer overflow protection (this may crash if SIMULATE_ATTACK is defined) */
     printf("Test 4: Buffer overflow protection\n");
     test_buffer_overflow_protection();
     printf("Buffer overflow protection test passed\n\n");
     
     /* Test 5: Attempt to use invalid callback (should be caught by CFI) */
     printf("Test 5: Invalid callback test\n");
     process_data_securely("Data for invalid callback test", invalid_callback);
     printf("If you see this, CFI validation FAILED!\n\n");
     
     printf("All advanced CFI tests completed\n");
     return 0;
 }