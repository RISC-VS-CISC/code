#include "uart.h"

int main()
{
    setup_uart(115200);
    while (1)
    {
        printf("Hello world!");   
        return 1;
    }
    return 0;
}
