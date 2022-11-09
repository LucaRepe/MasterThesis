from __future__ import print_function

# `currentProgram` or `getScriptArgs` function is contained in `__main__`
# actually you don't need to import by yourself, but it makes much "explicit"
import __main__ as ghidra_app

# distance from address to byte
# |<---------->|
# 00401000      89 c8      MOV EAX, this
DISTANCE_FROM_ADDRESS_TO_BYTE = 15

# output format of instructions
MSG_FORMAT = '{{byte:<{0}}}\n'.format(
    DISTANCE_FROM_ADDRESS_TO_BYTE
)


def unoverflow(x):
    return (abs(x) ^ 0xff) + 1


def to_hex(integer):
    return '{:02x}'.format(integer)


def _get_instructions(func):
    instructions = ''

    # get instructions in function
    func_addr = func.getEntryPoint()
    insts = ghidra_app.currentProgram.getListing().getInstructions(func_addr, True)

    # process each instruction
    for inst in insts:
        if ghidra_app.getFunctionContaining(inst.getAddress()) != func:
            break

        instructions += MSG_FORMAT.format(
            byte=' '.join([to_hex(b) if b >= 0 else to_hex(unoverflow(b)) for b in inst.getBytes()]),
            inst=inst
        )

    return instructions


def disassemble_func(func):
    '''disassemble given function, and returns as string.
    Args:
        func (ghidra.program.model.listing.Function): function to be disassembled
    Returns:
        string: disassembled function with function signature and instructions
    '''

    return _get_instructions(func)


def disassemble(program):
    '''disassemble given program.
    Args:
        program (ghidra.program.model.listing.Program): program to be disassembled
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
    args = ghidra_app.getScriptArgs()
    if len(args) > 1:
        print('[!] need output path, see following\n\
Usage: ./analyzeHeadless <PATH_TO_GHIDRA_PROJECT> <PROJECT_NAME> \
-process|-import <TARGET_FILE> [-scriptPath <PATH_TO_SCRIPT_DIR>] \
-postScript|-preScript disassemble.py <PATH_TO_OUTPUT_FILE>')
        return

    # if no output path given, <CURRENT_PROGRAM>.asm will be saved in current dir
    if len(args) == 0:
        cur_program_name = ghidra_app.currentProgram.getName()
        output = '{}.asm'.format(''.join(cur_program_name.split('.')[:-1]))
    else:
        output = args[0]
    
    disassembled = disassemble(ghidra_app.currentProgram)
    # save to file
    with open(output, 'w') as fw:
        fw.write(disassembled)
        print('[*] success. save to -> {}'.format(output))
    

if __name__ == '__main__':
    run()



    