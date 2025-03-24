# define UART_BASE_ADDR 0xfc001000
# define CLOCK_FREQUENCY 40000000
# define BUFF_FULL 0x200

void setup_uart(int baud);
int _print_char(char cha);
void _print_word(char* word);
int printf(const char* format, ...);