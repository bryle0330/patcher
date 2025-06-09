injects a new .istub section (marked executable+readable) and, for each imported function, 
emits a tiny XOR-decrypt stub that preserves registers (pushad/popad on x86, push rax/pop rax on x64), 
loads the encrypted function RVA into EAX/RAX, 
xors the low byte with a compile-time key, 
writes the result back into the original IAT slot on the stack, 
and then jmps through that slot—adding a random padding byte at the end for misalignment. 
then scans every code section for indirect IAT calls (FF 15 <imm32>) 
and replaces each 6-byte sequence with a 5-byte relative call into the matching stub plus a single-byte pad (usually NOP, 
optionally randomized). 
An optional second pass also rewrites direct E8 <rel32> calls targeting the import directory. 
The patched binary behaves identically, 
but all imports are hidden behind encrypted pointers and custom stubs, 
defeating static disassembly and import-table enumeration.

COMPILE PATCHER/TESTER:
at root dir do 

cmake -S . -B build `
>>       -DCMAKE_POSITION_INDEPENDENT_CODE=ON `
>>       -DICO_VERBOSE=ON

then 

cmake --build build

then go to build/debug and its there

---

in src dir do

nasm -f win32 main.asm -o test.obj 

then in x86 native cmd prompt

link test.obj user32.lib kernel32.lib /SUBSYSTEM:CONSOLE /MACHINE:X86 /ENTRY:main /OUT:test32.exe

DISCLAIMERS:

this is funky got bored so i stopped x64 PE binaries do NOT work, patcher patches x86 but wont be able to run yes ik frick me!
but whoever wants to fork and fix it be my guest i just cba anymore