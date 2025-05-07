/**
 * cfi.c - Control Flow Integrity for RISC-V
 *
 * Implementation of the CFI protection mechanisms
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <stdint.h>
 #include "cfi.h"
 
 /* CFI shadow stack implementation */
 #define SHADOW_STACK_SIZE 1024
 static void* shadow_stack[SHADOW_STACK_SIZE];
 static int shadow_stack_top = 0;
 
 /* Function ID table - in a real implementation this would be much larger */
 static function_id_entry_t function_id_table[128];
 static int function_id_count = 0;
 
 /* CFI initialization function */
 void init_cfi(void) {
     /* Clear shadow stack */
     memset(shadow_stack, 0, sizeof(shadow_stack));
     shadow_stack_top = 0;
     
     /* Initialize function ID table to empty */
     memset(function_id_table, 0, sizeof(function_id_table));
     function_id_count = 0;
     
     printf("CFI protection initialized\n");
 }
 
 /* Register a function in the CFI table */
 void register_function_cfi(void* function_addr, uint32_t function_id) {
     if (function_id_count >= sizeof(function_id_table)/sizeof(function_id_table[0])) {
         fprintf(stderr, "CFI Error: Function ID table full\n");
         return;
     }
     
     function_id_table[function_id_count].function_addr = function_addr;
     function_id_table[function_id_count].function_id = function_id;
     function_id_count++;
 }
 
 /* Shadow stack push operation */
 void cfi_push_return_address(void* ret_addr, uint32_t function_id) {
     if (shadow_stack_top >= SHADOW_STACK_SIZE - 1) {
         fprintf(stderr, "CFI Error: Shadow stack overflow\n");
         exit(EXIT_FAILURE);
     }
     
     /* Store both return address and calling function ID */
     shadow_stack[shadow_stack_top++] = ret_addr;
     shadow_stack[shadow_stack_top++] = (void*)(uintptr_t)function_id;
 }
 
 /* Shadow stack pop and validate operation */
 void* cfi_pop_return_address(uint32_t expected_function_id) {
     if (shadow_stack_top <= 1) {
         fprintf(stderr, "CFI Error: Shadow stack underflow\n");
         exit(EXIT_FAILURE);
     }
     
     /* Pop function ID and validate */
     uint32_t stored_function_id = (uint32_t)(uintptr_t)shadow_stack[--shadow_stack_top];
     void* ret_addr = shadow_stack[--shadow_stack_top];
     
     if (stored_function_id != expected_function_id) {
         fprintf(stderr, "CFI Error: Function ID mismatch (expected: 0x%x, got: 0x%x)\n", 
                 expected_function_id, stored_function_id);
         exit(EXIT_FAILURE);
     }
     
     return ret_addr;
 }
 
 /* Validate indirect call target */
 int cfi_validate_indirect_call(void* target_addr, uint32_t expected_type) {
     /* Check if the target is in our function ID database with matching type */
     for (int i = 0; i < function_id_count; i++) {
         if (function_id_table[i].function_addr == target_addr) {
             /* In a real implementation we would check if the function type matches */
             return 1; /* Valid target */
         }
     }
     
     fprintf(stderr, "CFI Error: Invalid indirect call target: %p\n", target_addr);
     return 0; /* Invalid target */
 }
 
 /* C wrapper for assembly functions */
 void cfi_function_enter(uint32_t function_id) {
     /* Get return address - this is compiler/platform specific */
     void* ret_addr = __builtin_return_address(0);
     
     /* Either call assembly implementation or use C implementation */
 #ifdef USE_ASSEMBLY_CFI
     _cfi_function_enter(function_id);
 #else
     cfi_push_return_address(ret_addr, function_id);
 #endif
 }
 
 void cfi_function_exit(uint32_t expected_function_id) {
 #ifdef USE_ASSEMBLY_CFI
     _cfi_function_exit(expected_function_id);
 #else
     cfi_pop_return_address(expected_function_id);
 #endif
 }