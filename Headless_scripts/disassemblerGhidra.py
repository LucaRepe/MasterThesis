from __future__ import print_function, division

from typing import List

import logging
import site
import sys
import os

# `currentProgram` or `getScriptArgs` function is contained in `__main__`
# actually you don't need to import by yourself, but it makes much "explicit"


class BasicBlock:
    start_addr: int
    list_bytes: List[List]
    list_instr: List[str]
    list_addr: List[int]
    list_edges: List[int]
    list_edge_attr: List[str]
    function_beginning: bool
    direct_fun_call: bool
    indirect_fun_call: bool
    conditional_jump: bool
    direct_jump: bool
    indirect_jump: bool
    has_return: bool
    unique_hash_identifier: int

# distance from address to byte
# |<---------->|
# 00401000      89 c8      MOV EAX, this
DISTANCE_FROM_ADDRESS_TO_BYTE = 15

# distance from byte to instruction
#               |<------->|
# 00401000      89 c8      MOV EAX, this
DISTANCE_FROM_BYTE_TO_INST = 15

# output format of instructions
MSG_FORMAT = '{{byte:<{1}}} {{inst}}\n'.format(
    DISTANCE_FROM_ADDRESS_TO_BYTE,
    DISTANCE_FROM_ADDRESS_TO_BYTE+DISTANCE_FROM_BYTE_TO_INST 
)


def unoverflow(x):
    return (abs(x) ^ 0xff) + 1


def to_hex(integer):
    return '{:02x}'.format(integer)


def _get_instructions(func):
    instructions = ''

    # get instructions in function
    func_addr = func.getEntryPoint()
    insts = currentProgram.getListing().getInstructions(func_addr, True)

    # process each instruction
    for inst in insts:
        if getFunctionContaining(inst.getAddress()) != func:
            break

        instructions += MSG_FORMAT.format(
            byte=' '.join([to_hex(b) if b >= 0 else to_hex(unoverflow(b)) for b in inst.getBytes()]),
            inst=inst
        )

    return instructions.upper()


def disassemble_func(func):
    '''disassemble given function, and returns as string.
    Args:
        func (program.model.listing.Function): function to be disassembled
    Returns:
        string: disassembled function with function signature and instructions
    '''

    return  _get_instructions(func)


def disassemble(program):
    '''disassemble given program.
    Args:
        program (program.model.listing.Program): program to be disassembled
    Returns:
        string: all disassembled functions 
    '''

    disasm_result = ''

    # enum functions and disassemble
    funcs = program.getListing().getFunctions(True)
    for func in funcs:
        disasm_result += disassemble_func(func)

    return disasm_result


def run():
    args = getScriptArgs()
    if len(args) > 1:
        print('[!] need output path, see following\n\
            Usage: ./analyzeHeadless <PATH_TO_GHIDRA_PROJECT> <PROJECT_NAME> \
            -process|-import <TARGET_FILE> [-scriptPath <PATH_TO_SCRIPT_DIR>] \
            -postScript|-preScript disassemble.py <PATH_TO_OUTPUT_FILE>')
        return

    # if no output path given, 
    # <CURRENT_PROGRAM>.asm will be saved in current dir
    if len(args) == 0:
        cur_program_name = currentProgram.getName()
        output = '{}.asm'.format(''.join(cur_program_name.split('.')[:-1]))
    else:
        output = args[0]
    
    disassembled = disassemble(currentProgram)
    # save to file
    with open(output, 'w') as fw:
        fw.write(disassembled)
        print('[*] success. save to -> {}'.format(output))
            

if __name__ == '__main__':
    run()



    