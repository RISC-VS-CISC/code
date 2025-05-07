/**
 * concurrency_tests.c - RISC-V Concurrency and Multi-Hart CFI Tests
 *
 * This file contains tests focused on multi-hart concurrency issues
 * related to CFI implementation on RISC-V processors.
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <stdint.h>
 #include <unistd.h>
 #include <pthread.h>
 #include "cfi.h"
 
 /* Define function IDs for testing */
 #define FUNC_ID_ATOMIC_CHECK      0x7001
 #define FUNC_ID_SHARED_SHADOW     0x7002
 #define FUNC_ID_LOCK_FREE         0x7003
 #define FUNC_ID_HART_SYNC         0x7004
 #define FUNC_ID_MEMORY_BARRIER    0x7005
 
 /* Thread-safe counter for synchronization */
 static volatile int thread_counter = 0;
 static pthread_mutex_t counter_mutex = PTHREAD_MUTEX_INITIALIZER;
 
 /* Shared function pointer for concurrency tests */
 static void (*shared_func_ptr)(int) = NULL;
 
 /* Legitimate function target */
 void legitimate_concurrent_target(int param) {
     /* CFI Function entry check */
     CFI_FUNCTION_ENTRY(FUNC_ID_ATOMIC_CHECK);
     
     printf("Legitimate concurrent target executed with param: %d\n", param);
     
     /* CFI Function exit check */
     CFI_FUNCTION_EXIT();
 }
 
 /* Illegitimate function target */
 void illegitimate_concurrent_target(int param) {
     printf("!!! SECURITY BREACH: Illegitimate concurrent target executed !!!\n");
     printf("This should never be called if CFI is working properly\n");
 }
 
 /**
  * Simulated hart (thread) function for testing atomic CFI checks
  */
 void* hart_atomic_check_thread(void* arg) {
     int hart_id = *((int*)arg);
     
     printf("Hart %d: Starting atomic CFI check test\n", hart_id);
     
     /* Simulate intensive concurrent access to shared function pointer */
     for (int i = 0; i < 100; i++) {
         /* Simulate race condition by attempting to modify shared pointer */
         if (hart_id == 1 && i == 50) {
             /* Attempt to replace with malicious pointer */
             shared_func_ptr = illegitimate_concurrent_target;
             printf("Hart %d: Attempted to modify shared function pointer\n", hart_id);
         }
         
         /* Validate function pointer atomically before use */
         if (cfi_validate_indirect_call((void*)shared_func_ptr, FUNC_ID_ATOMIC_CHECK)) {
             /* Atomic validation should prevent time-of-check to time-of-use vulnerabilities */
             printf("Hart %d: Successfully validated function pointer (iteration %d)\n", 
                    hart_id, i);
             
             /* Simulate delay between validation and use to amplify potential race condition */
             if (i % 25 == 0) {
                 usleep(10); /* Small delay */
             }
             
             /* Re-check before use to handle race conditions */
             if (cfi_validate_indirect_call((void*)shared_func_ptr, FUNC_ID_ATOMIC_CHECK)) {
                 /* Safe to call */
                 printf("Hart %d: Re-validation succeeded\n", hart_id);
             } else {
                 printf("Hart %d: Race condition detected! Function pointer was modified after validation\n", 
                        hart_id);
             }
         } else {
             printf("Hart %d: Function pointer validation failed (iteration %d)\n", 
                    hart_id, i);
         }
     }
     
     /* Signal completion */
     pthread_mutex_lock(&counter_mutex);
     thread_counter++;
     pthread_mutex_unlock(&counter_mutex);
     
     return NULL;
 }
 
 /**
  * Test atomic execution of CFI validation
  */
 void test_atomic_cfi_check(void) {
     /* CFI Function entry check */
     CFI_FUNCTION_ENTRY(FUNC_ID_ATOMIC_CHECK);
     
     printf("Testing atomic CFI check execution...\n");
     
     /* Initialize shared function pointer */
     shared_func_ptr = legitimate_concurrent_target;
     
     /* Create simulated harts (threads) */
     pthread_t harts[2];
     int hart_ids[2] = {0, 1};
     thread_counter = 0;
     
     printf("Launching 2 concurrent harts for testing atomic operations...\n");
     
     /* Start threads */
     for (int i = 0; i < 2; i++) {
         pthread_create(&harts[i], NULL, hart_atomic_check_thread, &hart_ids[i]);
     }
     
     /* Wait for threads to complete */
     for (int i = 0; i < 2; i++) {
         pthread_join(harts[i], NULL);
     }
     
     printf("Atomic CFI check test completed with %d harts\n", thread_counter);
     
     /* CFI Function exit check */
     CFI_FUNCTION_EXIT();
 }
 
 /**
  * Simulated hart (thread) function for testing shared shadow stack
  */
 void* hart_shadow_stack_thread(void* arg) {
     int hart_id = *((int*)arg);
     int call_depth = 0;
     
     printf("Hart %d: Starting shared shadow stack test\n", hart_id);
     
     /* Simulate function call stack operations */
     for (int i = 0; i < 10; i++) {
         /* Simulate function entry */
         printf("Hart %d: Simulating function entry (depth %d)\n", hart_id, call_depth);
         
         /* Push return address to shadow stack */
         void* ret_addr = (void*)((uintptr_t)0x10000000 + (hart_id * 0x1000) + i);
         cfi_push_return_address(ret_addr, FUNC_ID_SHARED_SHADOW + i);
         call_depth++;
         
         /* Simulate some work */
         usleep(hart_id * 5);
         
         /* Every few iterations, simulate function exit */
         if (i % 3 == 2 || i == 9) {
             printf("Hart %d: Simulating function exit (depth %d)\n", hart_id, call_depth);
             
             /* Pop and validate return address */
             void* popped_addr = cfi_pop_return_address(FUNC_ID_SHARED_SHADOW + i);
             
             /* Verify correct address was popped */
             if (popped_addr == ret_addr) {
                 printf("Hart %d: Shadow stack pop successful\n", hart_id);
             } else {
                 printf("Hart %d: ERROR - Shadow stack corruption detected!\n", hart_id);
                 printf("  Expected: %p, Got: %p\n", ret_addr, popped_addr);
             }
             
             call_depth--;
         }
     }
     
     /* Signal completion */
     pthread_mutex_lock(&counter_mutex);
     thread_counter++;
     pthread_mutex_unlock(&counter_mutex);
     
     return NULL;
 }
 
 /**
  * Test thread-safety of shadow stack implementation
  */
 void test_shared_shadow_stack(void) {
     /* CFI Function entry check */
     CFI_FUNCTION_ENTRY(FUNC_ID_SHARED_SHADOW);
     
     printf("Testing shared shadow stack thread safety...\n");
     
     /* Create simulated harts (threads) */
     pthread_t harts[4];
     int hart_ids[4] = {0, 1, 2, 3};
     thread_counter = 0;
     
     printf("Launching 4 concurrent harts for testing shadow stack operations...\n");
     
     /* Start threads */
     for (int i = 0; i < 4; i++) {
         pthread_create(&harts[i], NULL, hart_shadow_stack_thread, &hart_ids[i]);
     }
     
     /* Wait for threads to complete */
     for (int i = 0; i < 4; i++) {
         pthread_join(harts[i], NULL);
     }
     
     printf("Shared shadow stack test completed with %d harts\n", thread_counter);
     
     /* CFI Function exit check */
     CFI_FUNCTION_EXIT();
 }
 
 /**
  * Thread function for testing lock-free CFI validation
  */
 void* hart_lock_free_thread(void* arg) {
     int hart_id = *((int*)arg);
     int success_count = 0;
     
     printf("Hart %d: Starting lock-free CFI validation test\n", hart_id);
     
     /* Simulate high-frequency CFI validations */
     for (int i = 0; i < 1000; i++) {
         /* Create function pointer for validation */
         void* func_ptr = (hart_id % 2 == 0) ? 
                          (void*)legitimate_concurrent_target : 
                          (void*)illegitimate_concurrent_target;
         
         /* Perform lock-free validation */
         int result = cfi_validate_indirect_call(
             func_ptr, 
             (hart_id % 2 == 0) ? FUNC_ID_ATOMIC_CHECK : 0
         );
         
         /* Track successful validations */
         if (result) {
             success_count++;
         }
         
         /* Occasionally yield to increase concurrency */
         if (i % 100 == 0) {
             sched_yield();
         }
     }
     
     printf("Hart %d: Completed with %d successful validations out of 1000\n", 
            hart_id, success_count);
     
     /* Signal completion */
     pthread_mutex_lock(&counter_mutex);
     thread_counter++;
     pthread_mutex_unlock(&counter_mutex);
     
     return NULL;
 }
 
 /**
  * Test lock-free CFI validation performance
  */
 void test_lock_free_validation(void) {
     /* CFI Function entry check */
     CFI_FUNCTION_ENTRY(FUNC_ID_LOCK_FREE);
     
     printf("Testing lock-free CFI validation performance...\n");
     
     /* Create simulated harts (threads) */
     pthread_t harts[8];
     int hart_ids[8] = {0, 1, 2, 3, 4, 5, 6, 7};
     thread_counter = 0;
     
     printf("Launching 8 concurrent harts for testing lock-free validation...\n");
     
     /* Start threads */
     for (int i = 0; i < 8; i++) {
         pthread_create(&harts[i], NULL, hart_lock_free_thread, &hart_ids[i]);
     }
     
     /* Wait for threads to complete */
     for (int i = 0; i < 8; i++) {
         pthread_join(harts[i], NULL);
     }
     
     printf("Lock-free CFI validation test completed with %d harts\n", thread_counter);
     
     /* CFI Function exit check */
     CFI_FUNCTION_EXIT();
 }
 
 /**
  * Thread function for testing hart synchronization during CFI operations
  */
 void* hart_sync_thread(void* arg) {
     int hart_id = *((int*)arg);
     
     printf("Hart %d: Starting synchronization test\n", hart_id);
     
     /* Simulate a multi-phase CFI operation that requires synchronization */
     
     /* Phase 1: Initialize thread-local CFI state */
     printf("Hart %d: Phase 1 - Initializing thread-local CFI state\n", hart_id);
     usleep(10 * hart_id); /* Simulate different initialization times */
     
     /* Synchronize after phase 1 */
     pthread_mutex_lock(&counter_mutex);
     thread_counter++;
     pthread_mutex_unlock(&counter_mutex);
     
     /* Wait for all threads to complete phase 1 */
     while (1) {
         pthread_mutex_lock(&counter_mutex);
         int current = thread_counter;
         pthread_mutex_unlock(&counter_mutex);
         
         if (current >= 6) { /* 6 threads total */
             break;
         }
         usleep(5);
     }
     
     /* Phase 2: Perform CFI validation with inter-hart dependency */
     printf("Hart %d: Phase 2 - Performing synchronized CFI validation\n", hart_id);
     
     /* Simulate inter-hart dependency by assigning different roles */
     if (hart_id == 0) {
         /* This hart validates function pointers */
         printf("Hart %d: Validating shared function pointer\n", hart_id);
         int valid = cfi_validate_indirect_call(
             (void*)legitimate_concurrent_target, FUNC_ID_HART_SYNC);
         
         /* Share result with other harts through global state */
         if (valid) {
             shared_func_ptr = legitimate_concurrent_target;
         } else {
             shared_func_ptr = NULL;
         }
     } else {
         /* These harts wait for validation and then use the pointer */
         usleep(20); /* Wait for hart 0 to complete validation */
         
         printf("Hart %d: Using validated function pointer\n", hart_id);
         if (shared_func_ptr != NULL) {
             /* In a real system, we would make the call here */
             printf("Hart %d: Function pointer is valid\n", hart_id);
         } else {
             printf("Hart %d: Function pointer validation failed\n", hart_id);
         }
     }
     
     /* Reset counter for next phase */
     pthread_mutex_lock(&counter_mutex);
     thread_counter = 0;
     pthread_mutex_unlock(&counter_mutex);
     
     return NULL;
 }
 
 /**
  * Test inter-hart synchronization during CFI operations
  */
 void test_hart_synchronization(void) {
     /* CFI Function entry check */
     CFI_FUNCTION_ENTRY(FUNC_ID_HART_SYNC);
     
     printf("Testing inter-hart synchronization during CFI operations...\n");
     
     /* Create simulated harts (threads) */
     pthread_t harts[6];
     int hart_ids[6] = {0, 1, 2, 3, 4, 5};
     thread_counter = 0;
     
     printf("Launching 6 concurrent harts for testing synchronization...\n");
     
     /* Start threads */
     for (int i = 0; i < 6; i++) {
         pthread_create(&harts[i], NULL, hart_sync_thread, &hart_ids[i]);
     }
     
     /* Wait for threads to complete */
     for (int i = 0; i < 6; i++) {
         pthread_join(harts[i], NULL);
     }
     
     printf("Hart synchronization test completed\n");
     
     /* CFI Function exit check */
     CFI_FUNCTION_EXIT();
 }
 
 /**
  * Thread function for testing memory barriers in CFI
  */
 void* hart_memory_barrier_thread(void* arg) {
     int hart_id = *((int*)arg);
     
     printf("Hart %d: Starting memory barrier test\n", hart_id);
     
     /* Create a shared value for testing */
     static volatile int shared_value = 0;
     static volatile void* func_ptr = legitimate_concurrent_target;
     
     /* Simulate memory reordering scenario */
     if (hart_id == 0) {
         /* This hart updates the function pointer and then signals completion */
         printf("Hart 0: Updating function pointer...\n");
         func_ptr = legitimate_concurrent_target;
         
         /* Memory barrier would be needed here */
         __sync_synchronize(); /* Full memory barrier */
         
         /* Signal that update is complete */
         shared_value = 1;
     } else {
         /* This hart waits for the signal and then uses the function pointer */
         printf("Hart 1: Waiting for signal...\n");
         
         /* Spin until shared_value is updated */
         while (shared_value == 0) {
             /* This would be vulnerable to memory reordering without barriers */
             __sync_synchronize(); /* Full memory barrier */
         }
         
         /* Memory barrier would be needed here */
         __sync_synchronize(); /* Full memory barrier */
         
         printf("Hart 1: Signal received, validating function pointer\n");
         
         /* Validate function pointer */
         if (cfi_validate_indirect_call((void*)func_ptr, FUNC_ID_MEMORY_BARRIER)) {
             printf("Hart 1: Function pointer validation successful\n");
         } else {
             printf("Hart 1: Function pointer validation failed\n");
         }
     }
     
     /* Signal completion */
     pthread_mutex_lock(&counter_mutex);
     thread_counter++;
     pthread_mutex_unlock(&counter_mutex);
     
     return NULL;
 }
 
 /**
  * Test memory barriers in CFI implementation
  */
 void test_memory_barriers(void) {
     /* CFI Function entry check */
     CFI_FUNCTION_ENTRY(FUNC_ID_MEMORY_BARRIER);
     
     printf("Testing memory barriers in CFI implementation...\n");
     
     /* Create simulated harts (threads) */
     pthread_t harts[2];
     int hart_ids[2] = {0, 1};
     thread_counter = 0;
     
     printf("Launching 2 concurrent harts for testing memory barriers...\n");
     
     /* Start threads */
     for (int i = 0; i < 2; i++) {
         pthread_create(&harts[i], NULL, hart_memory_barrier_thread, &hart_ids[i]);
     }
     
     /* Wait for threads to complete */
     for (int i = 0; i < 2; i++) {
         pthread_join(harts[i], NULL);
     }
     
     printf("Memory barrier test completed with %d harts\n", thread_counter);
     
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
     register_function_cfi((void*)legitimate_concurrent_target, FUNC_ID_ATOMIC_CHECK);
     register_function_cfi((void*)test_atomic_cfi_check, FUNC_ID_ATOMIC_CHECK);
     register_function_cfi((void*)test_shared_shadow_stack, FUNC_ID_SHARED_SHADOW);
     register_function_cfi((void*)test_lock_free_validation, FUNC_ID_LOCK_FREE);
     register_function_cfi((void*)test_hart_synchronization, FUNC_ID_HART_SYNC);
     register_function_cfi((void*)test_memory_barriers, FUNC_ID_MEMORY_BARRIER);
     
     printf("=== RISC-V Concurrency and Multi-Hart CFI Tests ===\n\n");
     
     /* Run all tests */
     test_atomic_cfi_check();
     printf("\n");
     
     test_shared_shadow_stack();
     printf("\n");
     
     test_lock_free_validation();
     printf("\n");
     
     test_hart_synchronization();
     printf("\n");
     
     test_memory_barriers();
     printf("\n");
     
     printf("All concurrency and multi-hart CFI tests completed!\n");
     return 0;
 }