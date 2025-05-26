void X64_Start ();

void X64_End ();

// int main() {
//     X64_Start();
//     X64_End();
//     return 0;
// }
//
void
X64_Start ()
{
  __asm__ ("push $0x33\n\t"
           "call (%eip)\n\t"
           "addl $0x5, (%esp)\n\t"
           "retf\n\t");
}

void
X64_End ()
{
  __asm__ ("call (%rip)\n\t"
           "movl $0x23, 4(%rsp)\n\t"
           "addl $0xd, (%rsp)\n\t"
           "lret");
}
