### Conditional jumps with same target

Radare has one additional edge
IDA counts two function beginnings

### Conditional jump with constant condition

Radare has one additional edge
IDA counts two function beginnings

### Impossible disassembly

Radare's script breaks when reading the FF opcode
IDA doesn't get any BB regarding the technique
Ghidra recognizes until 0x153a, as soon as it reads the FF opcode finds nothing until 0x15be 

### Register reassignment

All the tools agree

### Disassembly desynchronization

All the tools agree

### Dynamically computed target address

All the tools agree

### Return pointer abuse

Angr has two more nodes: 0x11c6b and 0x11c69, and two more edges. REP instruction causes this difference.
Radare doesn't consider the function beginning.
Ghidra considers 2 direct calls and 2 indirect calls, the other instead 3 direct and 1 indirect.
The different call is given by `call $ + 5`, because it is recognized as an UNCONDITIONAL_JUMP.

### Structured exception handler misuse

