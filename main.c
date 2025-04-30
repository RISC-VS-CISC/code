#include "uart.h"
#include <stdlib.h>

int main()
{
    setup_uart(115200);
    printf("\n========== RISC-V Security Test: Control Flow Integrity (CFI) =========\r");
    printf("\n===== [TEST] Function Pointer Overwrite Attack (Zicfilp) =====\r");
    while (1)
    {
        /* int* test = (int *)malloc(20);*/
        /* printf("Malloc pointer location: %p \n\r", &test);  */
        
    }
    return 0;
}
