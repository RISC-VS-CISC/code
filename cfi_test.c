#include "uart.h"
//#include <stdlib.h>
// Main function to run tests
void safe_function();
void malicious_function();
void test_function_pointer_attack();
void test_invalid_function_pointer();
void return_address_attack();
int main() {
    setup_uart(115200);
    printf("\n==========RISC-V Security Test: Control Flow Integrity (CFI)=========\n\r");
    // Test 1: Function pointer overwrite
    test_function_pointer_attack();

    // Test 2: Invalid function pointer execution
    test_invalid_function_pointer();

    // Test 3: Return address overwrite attack
    return_address_attack();
    printf("\nAll tests completed.\n\r");
    while(1)
    {
    }
    return 0;
}
// Safe function - should be executed under normal conditions
void safe_function() {
    printf("[INFO] Executing safe function: Secure Execution\n\r");
}

// Malicious function - should never be executed if CFI is working
void malicious_function() {
    printf("[ALERT] Security Breach: Malicious function executed!\n\r");
    printf("[WARNING] Possible Control Flow Integrity (CFI) violation detected.\n\r");
}

// Test 1: Function Pointer Overwrite Attack (Zicfilp)
void test_function_pointer_attack() {
    printf("===== [TEST] Function Pointer Overwrite Attack (Zicfilp) =====\n\r");

    void (*function_ptr)() = safe_function;
    printf("[INFO] Function pointer initially set to safe_function\n\r");

    // Simulate attack: Overwriting function pointer
    printf("[ATTACK] Overwriting function pointer...\n\r");
    function_ptr = malicious_function;

    // Attempt to execute overwritten function pointer
    printf("[INFO] Calling function pointer:\n\r");
    function_ptr();  // Should trap if Zicfilp is active
}

// Test 2: Invalid Indirect Function Call (Zicfilp)
void test_invalid_function_pointer() {
    printf("===== [TEST] Invalid Function Pointer Call (Zicfilp) =====\n\r");

    void (*invalid_ptr)() = (void (*)()) malicious_function + 4;  // Invalid function address
    printf("[INFO] Calling invalid function pointer:\n\r");

    // Attempting to execute an invalid address
    invalid_ptr();  // Should trap if Zicfilp blocks invalid jumps
}

// Test 3: Return Address Overwrite Attack (Zicfiss)
void return_address_attack() {
    printf("\n===== [TEST] Return Address Overwrite Attack (Zicfiss) =====\n\r");

    void (*ret_ptr)() = safe_function;

    // Simulate stack corruption to overwrite return address
    __asm__ volatile (
        "addi sp, sp, -8\n"  // Move stack pointer (simulating overflow)
        "sw %0, 0(sp)\n"     // Overwrite return address
        :
        : "r"(malicious_function)
    );

    printf("[INFO] Returning from function:\n\r");
}

