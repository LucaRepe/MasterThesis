# MasterThesis

Repository containing the files for the Master Thesis, being developed at Eurecom.

## Pickles

In this folder are present the pickle files containing the networkx graphs obtained by the scripts for each disassembler.

Each node in the graph represents a basic block and contains as attributes: 

    - start_addr: starting address of the basic block
    - bytes: list of opcode bytes of the instructions 
    - instr: list of instructions
    - addr: list of addresses
    - edges: list of edges
    - edge_attr: list of attributes of edges' types
    - func_beg: boolean flag that indicates whether the basic block is at the beginning of a function
    - dir_call: boolean flag that indicates if the basic block has a direct function call
    - indir_call: boolean flag that indicates if the basic block has an indirect function call
    - cond_jump: boolean flag that indicates if the basic block has a conditional jump
    - dir_jump: boolean flag that indicates if the basic block has a direct jump
    - indir_jump: boolean flag that indicates if the basic block has an indirect jump
    - has_return: boolean flag that indicates if the basic block has a RET instruction
    - unique_hash_identifier: identifier obtained with xxhash32, using as input all the mnemonics present in the basic block

## Headless_scripts

In this folder are present the python scripts for the chosen tools: Ghidra, IDA Pro, Radare and Angr.

## MainComplete

In the root are present both the .c and .exe files, the executable has been compiled as x86.
This file will be used as input for the python scripts, in order to produce Interprocedural Control Flow Graphs and evaluate how each tool will disassemble different anti-disassembly techniques.
