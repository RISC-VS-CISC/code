/**
 * cfi.h - Control Flow Integrity for RISC-V
 *
 * Header file defining CFI interfaces for RISC-V architecture
 */

 #ifndef RISCV_CFI_H
 #define RISCV_CFI_H
 
 #include <stdint.h>
 
 /* CFI magic values for function validation */
 #define CFI_MAGIC_VALUE_1 0x52495343 /* "RISC" */
 #define CFI_MAGIC_VALUE_2 0x56434649 /* "VCFI" */
 
 /* Function ID database for CFI checks */
 typedef struct {
     void* function_addr;
     uint32_t function_id;
 } function_id_entry_t;
 
 /* CFI initialization function */
 void init_cfi(void);
 
 /* Shadow stack push operation */
 void cfi_push_return_address(void* ret_addr, uint32_t function_id);
 
 /* Shadow stack pop and validate operation */
 void* cfi_pop_return_address(uint32_t expected_function_id);
 
 /* Validate indirect call target */
 int cfi_validate_indirect_call(void* target_addr, uint32_t expected_type);
 
 /* 
  * Function entry point instrumentation - in real implementation these would
  * be added automatically by the compiler
  */
 #define CFI_FUNCTION_ENTRY(func_id) \
     uint32_t __cfi_func_id = (func_id); \
     uint32_t __cfi_check_1 = CFI_MAGIC_VALUE_1; \
     uint32_t __cfi_check_2 = CFI_MAGIC_VALUE_2
 
 /* Function exit instrumentation */
 #define CFI_FUNCTION_EXIT() \
     if (__cfi_check_1 != CFI_MAGIC_VALUE_1 || __cfi_check_2 != CFI_MAGIC_VALUE_2) { \
         fprintf(stderr, "CFI Error: Function stack corruption detected\n"); \
         exit(EXIT_FAILURE); \
     }
 
 /* Assembly function declarations */
 extern void _cfi_function_enter(uint32_t function_id);
 extern void _cfi_function_exit(uint32_t expected_function_id);
 
 #endif /* RISCV_CFI_H */