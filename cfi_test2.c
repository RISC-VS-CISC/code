//#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Function executed normally
void secure_function() {
    printf("[INFO] Secure function executed successfully.\n");
}

// Malicious function (should never execute if Zicfiss/Zicfilp are enforced)
void hijacked_function() {
    printf("[ALERT] Security Breach: Malicious function executed!\n");
}

// Function that attempts return address manipulation
void return_address_attack() {
    void *return_address;
    
    printf("\n[TEST] Return Address Attack (Zicfiss Protection)\n");

    // Save return address (this is typically protected by Zicfiss)
    __asm__("mv %0, ra" : "=r"(return_address));

    printf("[INFO] Original return address: %p\n", return_address);

    // Attempting to overwrite return address (simulated exploit)
    void *fake_address = (void *)hijacked_function;
    __asm__("mv ra, %0" : : "r"(fake_address));

    printf("[ATTACK] Overwritten return address: %p\n", fake_address);

    // If Zicfiss works, execution should NOT jump to hijacked_function
}

// Function pointer overwrite attempt
void function_pointer_attack() {
    void (*func_ptr)() = secure_function;

    printf("\n[TEST] Function Pointer Hijack (Zicfilp Protection)\n");
    printf("[INFO] Function pointer initially set to secure_function.\n");

    // Simulated attacker overwriting the function pointer
    func_ptr = hijacked_function;

    printf("[ATTACK] Function pointer overwritten!\n");
    printf("[INFO] Calling function pointer...\n");

    // If Zicfilp works, execution should be blocked when calling hijacked_function
    func_ptr();
}

int main() {
    printf("\n===== RISC-V Security Test: Zicfiss & Zicfilp =====\n");

    // Normal function execution
    printf("\n[TEST] Normal Function Execution\n");
    secure_function();

    // Attempt return address overwrite attack
    return_address_attack();

    // Attempt function pointer hijack
    function_pointer_attack();

    return 0;
}
