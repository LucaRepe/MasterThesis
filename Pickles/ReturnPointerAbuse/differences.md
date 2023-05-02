# Return pointer abuse

IDA and Angr agree
Radare doesn't consider the function beginning.
Ghidra considers 2 direct calls and 2 indirect calls, the other instead 3 direct and 1 indirect.
The different call is given by `call $ + 5`, because it is recognized as an UNCONDITIONAL_JUMP.