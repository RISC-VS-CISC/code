//# include <stdint.h>
typedef unsigned int uint32_t;
# define UART_BASE_ADDR 0xff900000 //0xfc001000
# define CLOCK_FREQUENCY 40000000
# define BUFF_FULL 0x200

typedef struct UART 
{
    uint32_t data;
    uint32_t status;
    uint32_t control;
    uint32_t baud;
} uart;

void setup_uart(int baud);
int _print_char(char cha);
int _read_char(char *cha);
void _print_word(char* word);
int printf(const char* format, ...);
