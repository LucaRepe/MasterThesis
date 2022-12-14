from __future__ import print_function, division

from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.block import CodeBlockIterator
from ghidra.program.model.block import CodeBlockReference 
from ghidra.program.model.block import CodeBlockReferenceIterator 
from ghidra.program.model.listing import CodeUnitIterator;
from ghidra.program.model.listing import Function;
from ghidra.program.model.listing import FunctionManager;
from ghidra.program.model.listing import Listing;
from ghidra.program.database.code import InstructionDB


import logging
import site
import sys
import os

# `currentProgram` or `getScriptArgs` function is contained in `__main__`
# actually you don't need to import by yourself, but it makes much "explicit"
import __main__ as ghidra_app

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


def _get_function_signature(func):
    # get function signature
    calling_conv = func.getDefaultCallingConventionName()
    params = func.getParameters()

    return '\n{calling_conv} {func_name}({params})\n'.format(
        calling_conv=calling_conv,
        func_name=func.getName(),
        params=', '.join([str(param).replace('[', '').replace(']', '').split('@')[0] for param in params]))


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

    return instructions.upper()


def disassemble_func(func):
    '''disassemble given function, and returns as string.
    Args:
        func (ghidra.program.model.listing.Function): function to be disassembled
    Returns:
        string: disassembled function with function signature and instructions
    '''

    return  _get_instructions(func)


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

    # if no output path given, 
    # <CURRENT_PROGRAM>.asm will be saved in current dir
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


def addBB(bb, G, bb_func_map):
    listing = currentProgram.getListing();
    # iter over the instructions
    codeUnits = listing.getCodeUnits(bb, True)
    lastInstStart = 0x0
    lastInstEnd = 0x0

    bb_tbl_rows = ''
    i = 0
    while codeUnits.hasNext():
        codeUnit = codeUnits.next()
        # check if the code unit is the instruction
        if not isinstance(codeUnit, InstructionDB):
            continue
        # Record address of first instruction
        if i == 0:
            firstInstStart = codeUnit.getAddress().getOffset()

        lastInstStart = codeUnit.getAddress().getOffset()
        lastInstEnd = lastInstStart + codeUnit.getLength()

        bb_tbl_rows += ('''
      <TR>
        <TD PORT="insn_%x" ALIGN="RIGHT"><FONT FACE="monospace">%x: </FONT></TD>
        <TD ALIGN="LEFT"><FONT FACE="monospace">%s</FONT></TD>
        <TD>&nbsp;&nbsp;&nbsp;</TD> // for spacing
      </TR>''' % (lastInstStart, lastInstStart, str(codeUnit)))
        i += 1 # Bump Counter

    bb_tbl_node = ('''  bb_%x [shape=plaintext label=<
    <TABLE BORDER="1" CELLBORDER="0" CELLSPACING="0">%s
    </TABLE>>];\n''' % (bb.getMinAddress().getOffset(), bb_tbl_rows))

    bb_func_map[bb.getMinAddress().getOffset()] = \
        'bb_%x:insn_%x' % (bb.getMinAddress().getOffset(), firstInstStart)

    # add node
    G += bb_tbl_node

    return G

def addSuccessors(bb_func_set, bb_func_map, G):


    listing = currentProgram.getListing();
    for bb in bb_func_set:
        codeUnits = listing.getCodeUnits(bb, True)
        lastInstStart = 0x0
        lastInstEnd = 0x0

        cur_bb_str = bb_func_map[bb.getMinAddress().getOffset()]

        while codeUnits.hasNext():
            codeUnit = codeUnits.next()

            if not isinstance(codeUnit, InstructionDB):
                continue

            lastInstStart = codeUnit.getAddress().getOffset()
            lastInstEnd = lastInstStart + codeUnit.getLength()
            successors = bb.getDestinations(monitor)

        idx = 0
        sucSet = set()
        while successors.hasNext():
            sucBBRef = successors.next()
            sucBBRefAddr = sucBBRef.getReferent().getOffset()
            # the reference is not in the last instruction
            if sucBBRefAddr < lastInstStart or sucBBRefAddr >= lastInstEnd:
                continue

            sucBB = sucBBRef.getDestinationBlock()
            sucOffset = sucBB.getFirstStartAddress().getOffset()
            if sucOffset in sucSet:
                continue

            if sucOffset not in bb_func_map:
                continue

            idx += 1

            currInsnAddr = sucBBRef.getReferent().getOffset()
            currBBAddr = bb.getMinAddress().getOffset()
            flowType = sucBBRef.getFlowType()

            if (flowType.isJump() and flowType.isUnConditional()) or flowType.isFallthrough():
                edgeAttrs = 'color=gray style=dashed'
            elif flowType.isCall() and flowType.isUnConditional():
                edgeAttrs = 'color=cyan4 style=dashed'
            elif flowType.isJump() and flowType.isConditional():
                edgeAttrs = 'color=gray style=solid'
            elif flowType.isCall() and flowType.isConditional():
                edgeAttrs = 'color=cyan4 style=solid'
            else:
                edgeAttrs = 'color=gray style=dotted'

            edgeAttrs += ' tooltip="%s"' % str(flowType)
            G += (('  bb_%x:insn_%x -> %s [%s];\n') \
                    % (currBBAddr, currInsnAddr, bb_func_map[sucOffset], 
                       edgeAttrs))

            sucSet.add(sucOffset)

    return G

def dumpBlocks():
    bbModel = BasicBlockModel(currentProgram)
    functionManager = currentProgram.getFunctionManager()

    # record the basic block that has been added by functions
    bb_set = set()
    # get all functions
    funcs_set = set()
    for func in functionManager.getFunctions(True):
        # we skip external functions
        if func.isExternal():
            continue

        func_va = func.getEntryPoint().getOffset()
        if func_va in funcs_set:
            continue

        G = ('''digraph "func 0x%x" {
  newrank=true;
  // Flow Type Legend
  subgraph cluster_01 { 
    rank=same;
    node [shape=plaintext]
    label = "Legend";
    key [label=<<table border="0" cellpadding="2" cellspacing="0" cellborder="0">
                  <tr><td align="right" port="i1">Jump/Fallthrough</td></tr>
                  <tr><td align="right" port="i2">Call</td></tr>
                  <tr><td align="right" port="i3">Conditional Jump</td></tr>
                  <tr><td align="right" port="i4">Conditional Call</td></tr>
                  <tr><td align="right" port="i5">Other</td></tr>
               </table>>];
    key2 [label=<<table border="0" cellpadding="2" cellspacing="0" cellborder="0">
                   <tr><td port="i1">&nbsp;</td></tr>
                   <tr><td port="i2">&nbsp;</td></tr>
                   <tr><td port="i3">&nbsp;</td></tr>
                   <tr><td port="i4">&nbsp;</td></tr>
                   <tr><td port="i5">&nbsp;</td></tr>
                </table>>];
    key:i1:e -> key2:i1:w [color=gray style=dashed];
    key:i2:e -> key2:i2:w [color=cyan4 style=dashed];
    key:i3:e -> key2:i3:w [color=gray];
    key:i4:e -> key2:i4:w [color=cyan4];
    key:i5:e -> key2:i5:w [color=gray style=dotted];
  }
''' % func_va)

        funcs_set.add(func_va)
        codeBlockIterator = bbModel.getCodeBlocksContaining(func.getBody(), monitor);


        # iter over the basic blocks
        bb_func_map = dict()
        bb_func_set = set()
        while codeBlockIterator.hasNext(): 
            bb = codeBlockIterator.next()
            bb_set.add(bb.getMinAddress().getOffset())
            bb_func_set.add(bb)
            G = addBB(bb, G, bb_func_map)

        G = addSuccessors(bb_func_set, bb_func_map, G)

        G += '}'

        with open('/home/luca/Scrivania/MasterThesis/%s.dot' % func.getName(), 'w') as dot_output:
            dot_output.write(G)
            

if __name__ == '__main__':
    run()
    dumpBlocks()



    