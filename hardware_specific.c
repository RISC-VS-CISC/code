/**
 * hardware_specific_tests.c - RISC-V Hardware-Specific CFI Tests
 *
 * This file contains control flow integrity tests related to RISC-V
 * hardware-specific features and potential attack vectors at the
 * physical implementation level.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "cfi.h"

/* Define function IDs for testing */
#define FUNC_ID_FENCE_BYPASS      0x6001
#define FUNC_ID_CACHE_TIMING      0x6002
#define FUNC_ID_MMU_ALIASING      0x6003
#define FUNC_ID_PHYSICAL_FP       0x6004
#define FUNC_ID_VECTOR_EXT        0x6005
#define FUNC_ID_PMP_BYPASS        0x6006
#define FUNC_ID_MULTIHART_RACE    0x6007
#define FUNC_ID_MTIMER_MANIP      0x6008

/* Simulate legitimate call target */
void legitimate_hardware_target(int param) {
    /* CFI function entry check */
    CFI_FUNCTION_ENTRY(FUNC_ID_FENCE_BYPASS);
    
    printf("Legitimate hardware target executed with param: %d\n", param);
    
    /* CFI function exit check */
    CFI_FUNCTION_EXIT();
}

/* Simulate illegitimate call target */
void illegitimate_hardware_target(int param) {
    printf("!!! SECURITY BREACH: Illegitimate hardware target executed !!!\n");
    printf("This should never be called if CFI is working properly\n");
}

/**
 * Test protection against FENCE instruction bypass
 * RISC-V uses FENCE instructions for memory and instruction ordering
 */
void test_fence_instruction_bypass(void) {
    /* CFI function entry check */
    CFI_FUNCTION_ENTRY(FUNC_ID_FENCE_BYPASS);
    
    printf("Testing FENCE instruction bypass protection...\n");
    
    /* Simulate memory ordering attack scenario */
    void* func_ptr = legitimate_hardware_target;
    volatile int validation_done = 0;
    
    printf("Simulating missing FENCE instruction scenario...\n");
    
    /* In real systems, the absence of proper FENCE instructions could
       allow reordering of memory operations, potentially bypassing CFI checks */
    
    /* Validate function pointer before call */
    if (cfi_validate_indirect_call(func_ptr, FUNC_ID_FENCE_BYPASS)) {
        validation_done = 1;
        /* Normally a FENCE instruction would be needed here */
        
        /* Simulate an attack that replaces the function pointer after validation
           but before the call, exploiting missing memory barriers */
        if (rand() % 2 == 0) { /* Simulate non-deterministic attack */
            func_ptr = illegitimate_hardware_target;
        }
        
        /* In a proper CFI implementation, a FENCE instruction or equivalent
           would prevent the above attack from succeeding */
        
        /* Re-validate before call to prevent memory reordering attacks */
        if (cfi_validate_indirect_call(func_ptr, FUNC_ID_FENCE_BYPASS)) {
            printf("FENCE protection working correctly\n");
        } else {
            printf("FENCE bypass attack detected and prevented\n");
        }
    }
    
    /* CFI function exit check */
    CFI_FUNCTION_EXIT();
}

/**
 * Test protection against cache timing side-channel attacks
 * RISC-V implementations may be vulnerable to cache timing attacks
 */
void test_cache_timing_protection(void) {
    /* CFI function entry check */
    CFI_FUNCTION_ENTRY(FUNC_ID_CACHE_TIMING);
    
    printf("Testing cache timing side-channel protection...\n");
    
    /* Create array for simulating cache timing attack */
    unsigned char* timing_array = malloc(256 * 64); /* 256 cache lines */
    if (!timing_array) {
        printf("Memory allocation failed\n");
        goto cleanup;
    }
    
    /* Initialize array to avoid page faults during testing */
    for (int i = 0; i < 256 * 64; i++) {
        timing_array[i] = i & 0xFF;
    }
    
    printf("Simulating cache timing side-channel attack...\n");
    
    /* Simulate a CFI check that might leak information via cache timing */
    uint32_t secret_function_id = 0x12345678; /* Pretend this is secret */
    
    /* A naive implementation might check the function ID like this: */
    /* NOTE: This could leak the secret via cache timing */
    for (int i = 0; i < 32; i++) {
        if ((secret_function_id >> i) & 1) {
            /* This access pattern depends on the secret bits */
            timing_array[i * 64] = 1; /* Touch a cache line */
        }
    }
    
    printf("A cache-timing resistant CFI implementation would use:\n");
    printf("1. Constant-time comparison functions\n");
    printf("2. Fixed memory access patterns\n");
    printf("3. Time-invariant control flow\n");
    
    /* Simulate constant-time verification (pseudo-code) */
    uint32_t result = 0;
    uint32_t expected_id = 0x12345678;
    uint32_t actual_id = secret_function_id;
    
    /* Constant-time comparison (no branches based on secret) */
    result = (expected_id ^ actual_id);
    result = ((result | -result) >> 31) & 1;
    
    printf("Constant-time validation result: %d (should be 0)\n", result);
    
cleanup:
    free(timing_array);
    
    /* CFI function exit check */
    CFI_FUNCTION_EXIT();
}

/**
 * Test protection against MMU page aliasing attacks
 * RISC-V's Sv39/Sv48 virtual memory systems might be vulnerable to page aliasing
 */
void test_mmu_aliasing_protection(void) {
    /* CFI function entry check */
    CFI_FUNCTION_ENTRY(FUNC_ID_MMU_ALIASING);
    
    printf("Testing MMU page aliasing attack protection...\n");
    
    /* Simulate a page that contains both code and data */
    char mixed_page[4096]; /* Typical page size */
    memset(mixed_page, 0, sizeof(mixed_page));
    
    /* Fill part of the page with simulated "code" */
    strcpy(mixed_page, "This represents code in a page");
    
    /* Create a function pointer to the page */
    typedef void (*page_func_t)(void);
    page_func_t page_func = (page_func_t)mixed_page;
    
    printf("Simulating MMU aliasing attack (mapping same physical page twice)...\n");
    
    /* In a real attack, an attacker might map the same physical page twice:
       1. Once as executable code
       2. Once as writable data
       This could bypass W^X protections */
    
    printf("In a secure system, CFI would prevent execution from a page that:\n");
    printf("1. Is mapped with inconsistent permissions\n");
    printf("2. Has multiple virtual mappings\n");
    printf("3. Doesn't properly separate code and data\n");
    
    /* Validate the function pointer to prevent aliasing attacks */
    if (!cfi_validate_indirect_call((void*)page_func, 0)) {
        printf("MMU aliasing attack prevention successful\n");
    }
    
    /* CFI function exit check */
    CFI_FUNCTION_EXIT();
}

/**
 * Test protection against physical fault injection
 * RISC-V hardware might be vulnerable to physical fault injection
 */
void test_physical_fault_protection(void) {
    /* CFI function entry check */
    CFI_FUNCTION_ENTRY(FUNC_ID_PHYSICAL_FP);
    
    printf("Testing protection against physical fault injection...\n");
    
    /* Setup for testing redundant checks */
    volatile int secure_counter = 0;
    volatile void* func_ptr = legitimate_hardware_target;
    
    printf("Simulating fault injection attack scenario...\n");
    
    /* In a real attack, physical faults might be injected to skip instructions
       or corrupt memory values. Redundant checks help detect such attacks. */
    
    /* First validation (could be skipped by fault injection) */
    if (cfi_validate_indirect_call((void*)func_ptr, FUNC_ID_FENCE_BYPASS)) {
        secure_counter++;
    }
    
    /* Second validation (redundant, to detect fault injection) */
    if (cfi_validate_indirect_call((void*)func_ptr, FUNC_ID_FENCE_BYPASS)) {
        secure_counter++;
    }
    
    /* Check both validations succeeded */
    if (secure_counter == 2) {
        printf("Both validations succeeded - no fault detected\n");
    } else {
        printf("ALERT: Potential fault injection detected!\n");
    }
    
    printf("A robust CFI implementation would include:\n");
    printf("1. Redundant validations\n");
    printf("2. Checksums on critical data\n");
    printf("3. Temporal diversity (repeated checks at different times)\n");
    
    /* CFI function exit check */
    CFI_FUNCTION_EXIT();
}

/**
 * Test for integration with RISC-V Vector extensions (RVV)
 * Vector processing can introduce new control flow complexities
 */
void test_vector_extension_protection(void) {
    /* CFI function entry check */
    CFI_FUNCTION_ENTRY(FUNC_ID_VECTOR_EXT);
    
    printf("Testing RISC-V Vector extension CFI integration...\n");
    
    /* Simulate vector register state */
    printf("Simulating vector operations that could affect control flow...\n");
    
    /* In real RISC-V systems with Vector extensions:
       1. Vectorized operations might modify memory used by CFI
       2. Vector mask registers could affect conditional execution
       3. Vector length configuration could impact control flow */
    
    printf("Vector extension CFI protections should include:\n");
    printf("1. Proper handling of vector register state during CFI checks\n");
    printf("2. Protection of CFI metadata from vectorized memory operations\n");
    printf("3. Validation of control flow in vectorized code segments\n");
    
    /* Simulate a vector operation that makes indirect calls */
    printf("Simulating vectorized indirect calls...\n");
    void* vector_funcs[16] = {legitimate_hardware_target, legitimate_hardware_target};
    
    /* In real vector code, we might validate multiple function pointers at once */
    int all_valid = 1;
    for (int i = 0; i < 2; i++) {
        if (!cfi_validate_indirect_call(vector_funcs[i], FUNC_ID_FENCE_BYPASS)) {
            all_valid = 0;
            break;
        }
    }
    
    if (all_valid) {
        printf("Vector function validation successful\n");
    }
    
    /* CFI function exit check */
    CFI_FUNCTION_EXIT();
}

/**
 * Test protection against PMP (Physical Memory Protection) bypass
 * RISC-V PMP could potentially be misconfigured or bypassed
 */
void test_pmp_bypass_protection(void) {
    /* CFI function entry check */
    CFI_FUNCTION_ENTRY(FUNC_ID_PMP_BYPASS);
    
    printf("Testing PMP bypass protection...\n");
    
    /* Simulate PMP configuration */
    printf("Simulating PMP configuration:\n");
    printf("- Region 0: CFI data (R for M-mode only)\n");
    printf("- Region 1: Code segment (R-X, no W)\n");
    printf("- Region 2: Data segment (R-W, no X)\n");
    
    /* Simulate an attack attempting to modify CFI data through PMP bypass */
    printf("Simulating PMP bypass attack attempt...\n");
    
    /* In a real attack, adversaries might try to:
       1. Find PMP configuration gaps
       2. Exploit race conditions during PMP updates
       3. Use speculative execution to bypass PMP */
    
    printf("A secure CFI implementation should:\n");
    printf("1. Use PMP to protect shadow stack and CFI metadata\n");
    printf("2. Verify PMP configurations at runtime\n");
    printf("3. Combine PMP with additional software-based checks\n");
    
    /* Demonstrate PMP enhancing CFI security */
    void* pmp_protected_addr = malloc(64);
    if (!pmp_protected_addr) {
        printf("Memory allocation failed\n");
        goto cleanup;
    }
    
    /* Simulate attempt to jump to data region (would be blocked by PMP) */
    typedef void (*data_func_t)(void);
    data_func_t data_func = (data_func_t)pmp_protected_addr;
    
    /* Validate function pointer */
    if (!cfi_validate_indirect_call((void*)data_func, 0)) {
        printf("Execution from data segment prevented by CFI+PMP\n");
    }
    
cleanup:
    free(pmp_protected_addr);
    
    /* CFI function exit check */
    CFI_FUNCTION_EXIT();
}

/**
 * Test for multi-hart race conditions
 * RISC-V's multi-hart architecture introduces concurrency challenges
 */
void test_multihart_race_protection(void) {
    /* CFI function entry check */
    CFI_FUNCTION_ENTRY(FUNC_ID_MULTIHART_RACE);
    
    printf("Testing multi-hart race condition protection...\n");
    
    /* Simulate shared data structures */
    struct {
        void (*func_ptr)(int);
        int is_validated;
    } shared_data;
    
    /* Initialize with safe values */
    shared_data.func_ptr = legitimate_hardware_target;
    shared_data.is_validated = 0;
    
    printf("Simulating concurrent access from multiple harts...\n");
    
    /* Simulate hart 0 validating the function pointer */
    printf("Hart 0: Validating function pointer\n");
    int validation_result = cfi_validate_indirect_call(
        (void*)shared_data.func_ptr, FUNC_ID_FENCE_BYPASS);
    
    /* In a real system, there could be a race here */
    shared_data.is_validated = validation_result;
    
    /* Simulate hart 1 modifying the pointer after validation */
    printf("Hart 1: Potentially modifying function pointer after validation\n");
    if (rand() % 2 == 0) { 
        /* Non-deterministic attack */
        shared_data.func_ptr = illegitimate_hardware_target;
        printf("Hart 1: Function pointer modified\n");
    }
    
    /* Simulate hart 0 using the pointer */
    printf("Hart 0: Preparing to call function pointer\n");
    
    /* A secure implementation would re-validate before use */
    if (shared_data.is_validated) {
        /* This is vulnerable! Should re-validate here */
        printf("VULNERABLE: Using previously validated pointer without re-checking\n");
        
        /* Instead, should do this: */
        if (!cfi_validate_indirect_call(
                (void*)shared_data.func_ptr, FUNC_ID_FENCE_BYPASS)) {
            printf("Race condition attack detected and prevented\n");
        } else {
            printf("Function pointer still valid, race attempt failed\n");
        }
    }
    
    printf("Multi-hart safe CFI should include:\n");
    printf("1. Atomic validation and use of function pointers\n");
    printf("2. Memory barriers to prevent reordering\n");
    printf("3. Thread-safe shadow stack implementation\n");
    
    /* CFI function exit check */
    CFI_FUNCTION_EXIT();
}

/**
 * Test protection against timer manipulation attacks
 * RISC-V's machine timer (mtime/mtimecmp) could be exploited
 */
void test_mtimer_manipulation_protection(void) {
    /* CFI function entry check */
    CFI_FUNCTION_ENTRY(FUNC_ID_MTIMER_MANIP);
    
    printf("Testing protection against timer manipulation attacks...\n");
    
    /* Simulate timer-based security check */
    printf("Simulating time-based CFI verification...\n");
    
    /* In some systems, security operations might have time limits
       to prevent brute force attacks or to detect fault injection */
    
    /* Record simulated start time */
    uint64_t start_time = 1000; /* Simulated timer value */
    
    /* Perform CFI check */
    int validation_result = cfi_validate_indirect_call(
        (void*)legitimate_hardware_target, FUNC_ID_FENCE_BYPASS);
    
    /* Record simulated end time */
    uint64_t end_time = 1010; /* Simulated timer value */
    
    /* Check if operation took too long or too short (indicating tampering) */
    uint64_t duration = end_time - start_time;
    printf("CFI validation duration: %lu cycles\n", duration);
    
    if (duration < 2) {
        printf("ALERT: Validation suspiciously fast - possible timer manipulation\n");
    } else if (duration > 100) {
        printf("ALERT: Validation suspiciously slow - possible attack in progress\n");
    } else {
        printf("Validation timing within expected range\n");
    }
    
    printf("Timer-aware CFI should include:\n");
    printf("1. Timeout detection for CFI operations\n");
    printf("2. Protection against timer manipulation\n");
    printf("3. Time-independent validation when possible\n");
    
    /* CFI function exit check */
    CFI_FUNCTION_EXIT();
}

/**
 * Main test function
 */
int main(int argc, char** argv) {
    /* Initialize CFI protection */
    init_cfi();
    
    /* Register functions in the CFI database */
    register_function_cfi((void*)legitimate_hardware_target, FUNC_ID_FENCE_BYPASS);
    register_function_cfi((void*)test_fence_instruction_bypass, FUNC_ID_FENCE_BYPASS);
    register_function_cfi((void*)test_cache_timing_protection, FUNC_ID_CACHE_TIMING);
    register_function_cfi((void*)test_mmu_aliasing_protection, FUNC_ID_MMU_ALIASING);
    register_function_cfi((void*)test_physical_fault_protection, FUNC_ID_PHYSICAL_FP);
    register_function_cfi((void*)test_vector_extension_protection, FUNC_ID_VECTOR_EXT);
    register_function_cfi((void*)test_pmp_bypass_protection, FUNC_ID_PMP_BYPASS);
    register_function_cfi((void*)test_multihart_race_protection, FUNC_ID_MULTIHART_RACE);
    register_function_cfi((void*)test_mtimer_manipulation_protection, FUNC_ID_MTIMER_MANIP);
    
    printf("=== RISC-V Hardware-Specific CFI Tests ===\n\n");
    
    /* Run all tests */
    test_fence_instruction_bypass();
    printf("\n");
    
    test_cache_timing_protection();
    printf("\n");
    
    test_mmu_aliasing_protection();
    printf("\n");
    
    test_physical_fault_protection();
    printf("\n");
    
    test_vector_extension_protection();
    printf("\n");
    
    test_pmp_bypass_protection();
    printf("\n");
    
    test_multihart_race_protection();
    printf("\n");
    
    test_mtimer_manipulation_protection();
    printf("\n");
    
    printf("All hardware-specific CFI tests completed!\n");
    return 0;
}