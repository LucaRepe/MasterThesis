# MasterThesis

Repository containing the files for the Master Thesis, developed at Eurecom.

## Common

Folder containing the basic_block module and the python scripts for the chosen tools: Angr, Ghidra, IDA Pro and Radare2.

## Docker

Folder containing the dockerfiles that build the image for each disassembler.

## Graphs

Folder containing the image representation of the graphs for each anti-disassembly technique.

## Pickles

Folder containing either the pickle files obtained by orchestrator and the purged ones.
Each node in the graphs represents a basic block and contains as attributes: 

    - start_addr: starting address of the basic block
    - bytes: list of opcode bytes of the instructions 
    - instr: list of instructions
    - instr_norm: list of normalized instructions
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

## Sources

Folder containing the .c sources, mainComplete.c is the base script containing function calls, loops and conditional statements, mainTechniques.c adds also one anti-disassembly technique at a time. 
This file will be used as input for the orchestrator, in order to produce Interprocedural Control Flow Graphs and evaluate how each tool will disassemble different anti-disassembly techniques.

### fullAnalysis.py

This python script:
    - purges the graphs considering the minimum and maximum addresses present inside the Pin trace
    - checks the Pin subset over the original addresses
    - checks the addresses present on the Pin trace that are missing in the graphs
    - purges again considering the addresses of the function containing the technique 
    - compares the attributes of the differences subgraphs
    - creates the agreement graph and the differences subgraphs
    - checks the Jaccard similarity on nodes
    - checks the Jaccard similarity on edges
    - checks the graph edit distance on differences subgraphs

### orchestrator.py

This python script runs a Docker container at a time, takes as input the file(s) from the folder and returns as output the graphs obtained by the disassemblers.

### printGraphs.py

This python script creates a .png representation for the agreement graph and the differences graphs.