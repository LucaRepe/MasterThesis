### Conditional jumps with same target

Radare has one additional edge
IDA counts two function beginnings

### Conditional jump with constant condition

Radare has one additional edge
IDA counts two function beginnings

### Impossible disassembly

IDA and Angr agree
Radare misses one BB at and doesn't find any function beginning
Ghidra misses three BB's, doesn't find anything after the technique

### Register reassignment

All the tools agree

### Disassembly desynchronization

All the tools agree

### Dynamically computed target address

All the tools agree

### Return pointer abuse

IDA and Angr agree
Radare doesn't consider the function beginning.
Ghidra considers 2 direct calls and 2 indirect calls, the other instead 3 direct and 1 indirect.
The different call is given by `call $ + 5`, because it is recognized as an UNCONDITIONAL_JUMP.

### Structured exception handler misuse

IDA recognizes a BB at 0x11e09 that isn't a BB.
Radare misses two BBs.
Angr finds one additional direct call at '0x11e09' that doesn't exist and counts two function beginning at '0x11e09' and '0x11e03'
