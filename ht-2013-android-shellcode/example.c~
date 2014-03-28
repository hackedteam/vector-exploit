void function_f( void )
{
  asm volatile
    (
    ".balign 4             \n\t"
    "mov     r0, pc        \n\t"
    "bx      r0            \n\t"
    ".code 32              \n\t"
    "mrs     r0, cpsr      \n\t"
    "msr     cpsr_c, r0    \n\t"
    "add     r0, pc, #1    \n\t"
    "bx      r0            \n\t"
    ".code 16              \n\t"
     );
}

int main() {
  function_f();
  return 1;
}
