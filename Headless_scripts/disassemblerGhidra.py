from __future__ import print_function, division
from typing import List
import re

from ghidra.util.task import TaskMonitor
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.block import CodeBlockIterator
from ghidra.program.model.block import CodeBlockReference 
from ghidra.program.model.block import CodeBlockReferenceIterator 
from ghidra.program.model.listing import CodeUnitIterator
from ghidra.program.model.listing import Function
from ghidra.program.model.listing import FunctionManager
from ghidra.program.model.listing import Listing
from ghidra.program.database.code import InstructionDB
from ghidra.program.model.address import Address
from ghidra.program.model.lang import OperandType

import networkx as nx
import pickle
import xxhash
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D


class BasicBlock:
    start_addr: int
    list_bytes: List[List]
    list_instr: List[str]
    list_instr_norm: List[str]
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

    def __repr__(self):
        return f'{self.start_addr} {self.list_bytes} {self.list_instr} {self.list_addr} {self.list_edges} ' \
                f'{self.list_edge_attr} '

def unoverflow(x):
    return (abs(x) ^ 0xff) + 1


def to_hex(integer):
    return '{:02x}'.format(integer)


def run():
    f = open("/home/luca/Scrivania/MasterThesis/analysisGhidra.txt", 'w')
    currentProgram.setImageBase(currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress('0x0000'), False)
    cond_jump_instructions = ['JE', 'JNE', 'JBE', 'JLE', 'JA', 'JB', 'JG', 'JGE', 'JZ', 'JNZ', \
     'JNBE', 'JAE', 'JNB', 'JNAE', 'JNA', 'JL', 'JC', 'JNC', 'JO', 'JNO', 'JS', 'JNS', 'JP', 'JPE', \
     'JNP', 'JPO', 'JCXZ', 'JECXZ', 'JNLE', 'JNL', 'JNGE', 'JNG']
    g = nx.DiGraph()
    listing = currentProgram.getListing()
    bbm = BasicBlockModel(currentProgram)
    blocks = bbm.getCodeBlocks(TaskMonitor.DUMMY)
    block = blocks.next()

    while block:
        functionManager = currentProgram.getFunctionManager()
        listing = currentProgram.getListing()
        ins_iter = listing.getInstructions(block, True)

        list_bytes = list()
        list_instr = list()
        list_instr_norm = list()
        list_addr = list()
        list_edges = list()
        list_edge_attr = list()
        func_beg = False
        dir_call = False
        indir_call = False
        conditional_jump = False
        dir_jump = False
        indir_jump = False
        has_return = False
        x = xxhash.xxh32()
        split_bb = False
        skip_adding = False

        for func in functionManager.getFunctions(True):
            func_addr = func.getEntryPoint()
            if func_addr == block.getMinAddress():
                func_beg = True

        while ins_iter.hasNext():
            instr = ins_iter.next()
            skip_adding = False
            f.write(' '.join([to_hex(b) if b >= 0 else to_hex(unoverflow(b)) for b in instr.getBytes()]).upper() + '\t\t' + instr.toString() + '\n')
            list_bytes.append(f' '.join([to_hex(b) if b >= 0 else to_hex(unoverflow(b)) for b in instr.getBytes()]).upper())
            mnemonic = instr.toString().split(' ')[0]
            norm_instr = instr.toString()
            if mnemonic in cond_jump_instructions:
                norm_instr = 'JZ ' + instr.toString().split(' ')[1]
            elif 'RETN' in mnemonic:
                norm_instr = 'RET'
            list_instr.append(f'{instr}')
            list_instr_norm.append(f'{norm_instr}')
            list_addr.append(f'{hex(instr.getAddress().getOffset())}')
            x.update(bytes(norm_instr.split(' ')[0].upper().strip(), 'UTF-8'))

            if mnemonic in cond_jump_instructions:
                conditional_jump = True
                jump_addr = instr.toString().split(' ')[-1]
                if instr.getFlowType().toString() == 'CONDITIONAL_JUMP' or \
                    instr.getFlowType().toString() == 'CALL_TERMINATOR':
                    dir_jump = True
                    jump_addr = jump_addr[2:]
                    real_jump_addr = '0x' + jump_addr.lstrip("0")
                    list_edges.append(real_jump_addr)
                else:
                    indir_jump = True
                    list_edges.append("UnresolvableJumpTarget")
                list_edge_attr.append("Jump")
            if 'JMP' in instr.toString():
                conditional_jump = False
                jump_addr = instr.toString().split(' ')[-1]
                if instr.getFlowType().toString() == 'UNCONDITIONAL_JUMP' or \
                    instr.getFlowType().toString() == 'CALL_TERMINATOR':
                    dir_jump = True
                    jump_addr = jump_addr[2:]
                    real_jump_addr = '0x' + jump_addr.lstrip("0")
                    list_edges.append(real_jump_addr)
                else:
                    indir_jump = True
                    list_edges.append("UnresolvableJumpTarget")
                list_edge_attr.append("Jump")
            if 'CALL' in instr.toString():
                split_bb = True
                call_addr = instr.toString().split(' ')[1]
                if instr.getFlowType().toString() == 'UNCONDITIONAL_CALL' or \
                    instr.getFlowType().toString() == 'CALL_TERMINATOR':
                    dir_call = True
                    call_addr = call_addr[2:]
                    real_call_addr = '0x' + call_addr.lstrip("0")
                    list_edges.append(real_call_addr)
                else:
                    indir_call = True
                    list_edges.append("UnresolvableCallTarget")
                list_edge_attr.append("Call")
            if 'RET' in instr.toString() or 'RETN' in instr.toString():
                has_return = True

            if split_bb:
                bb = BasicBlock()
                func_beg_copy = func_beg
                dir_call_copy = dir_call
                indir_call_copy = indir_call
                conditional_jump_copy = conditional_jump
                dir_jump_copy = dir_jump
                indir_jump_copy = indir_jump
                has_return_copy = has_return
                bb.start_addr = hex(int(list_addr[0], 16))
                bb.list_bytes = list_bytes.copy()
                bb.list_instr = list_instr.copy()
                bb.list_instr_norm = list_instr_norm.copy()
                bb.list_addr = list_addr.copy()
                bb.list_edges = list_edges.copy()
                bb.list_edge_attr = list_edge_attr.copy()
                bb.function_beginning = func_beg_copy
                bb.direct_fun_call = dir_call_copy
                bb.indirect_fun_call = indir_call_copy
                bb.conditional_jump = conditional_jump_copy
                bb.direct_jump = dir_jump_copy
                bb.indirect_jump = indir_jump_copy
                bb.has_return = has_return_copy
                bb.unique_hash_identifier = x.intdigest()
                if len(list_instr) != 0:
                    g.add_node(bb.start_addr, instr=bb.list_instr, instr_norm=bb.list_instr_norm, bytes=bb.list_bytes,
                            addr=bb.list_addr, edges=bb.list_edges, edge_attr=bb.list_edge_attr, func_beg=bb.function_beginning,
                            dir_call=bb.direct_fun_call, indir_call=bb.indirect_fun_call, cond_jump=bb.conditional_jump,
                            dir_jump=bb.direct_jump, indir_jump=bb.indirect_jump, has_return=bb.has_return,
                            unique_hash_identifier=bb.unique_hash_identifier)

                    list_bytes.clear()
                    list_instr.clear()
                    list_instr_norm.clear()
                    list_addr.clear()
                    list_edges.clear()
                    list_edge_attr.clear()
                    func_beg = False
                    dir_call = False
                    indir_call = False
                    conditional_jump = False
                    dir_jump = False
                    indir_jump = False
                    has_return = False
                    x = xxhash.xxh32()
                    split_bb = False
                    skip_adding = True

        if not skip_adding:
            skip_adding = False
            bb_not_splitted = BasicBlock()
            bb_not_splitted.start_addr = hex(int(list_addr[0], 16))
            bb_not_splitted.list_bytes = list_bytes
            bb_not_splitted.list_instr = list_instr
            bb_not_splitted.list_instr_norm = list_instr_norm
            bb_not_splitted.list_addr = list_addr
            bb_not_splitted.list_edges = list_edges
            bb_not_splitted.list_edge_attr = list_edge_attr
            bb_not_splitted.function_beginning = func_beg
            bb_not_splitted.direct_fun_call = dir_call
            bb_not_splitted.indirect_fun_call = indir_call
            bb_not_splitted.conditional_jump = conditional_jump
            bb_not_splitted.direct_jump = dir_jump
            bb_not_splitted.indirect_jump = indir_jump
            bb_not_splitted.has_return = has_return
            bb_not_splitted.unique_hash_identifier = x.intdigest()
            if len(list_instr) != 0:
                g.add_node(bb_not_splitted.start_addr, instr=bb_not_splitted.list_instr, instr_norm=bb_not_splitted.list_instr_norm,
                        bytes=bb_not_splitted.list_bytes, addr=bb_not_splitted.list_addr,edges=bb_not_splitted.list_edges,
                        edge_attr=bb_not_splitted.list_edge_attr, func_beg=bb_not_splitted.function_beginning,
                        dir_call=bb_not_splitted.direct_fun_call, indir_call=bb_not_splitted.indirect_fun_call,
                        cond_jump=bb_not_splitted.conditional_jump, dir_jump=bb_not_splitted.direct_jump,
                        indir_jump=bb_not_splitted.indirect_jump, has_return=bb_not_splitted.has_return,
                        unique_hash_identifier=bb_not_splitted.unique_hash_identifier)

        block = blocks.next()

    list_sorted = sorted(list(g.nodes))[1:]
    for node in sorted(list(g.nodes)):
        if list_sorted:
            if g.nodes[node]['has_return']:
                list_sorted.pop(0)
                for edge, attr in zip(g.nodes[node]['edges'], g.nodes[node]['edge_attr']):
                    if attr == 'Call':
                        g.add_edge(node, edge, color='r')
                    if attr == 'Fallthrough':
                        g.add_edge(node, edge, color='g')
                    if attr == 'Jump':
                        g.add_edge(node, edge, color='b')
            elif g.nodes[node]['dir_jump'] or g.nodes[node]['indir_jump']:
                if not g.nodes[node]['cond_jump']:
                    list_sorted.pop(0)
                    for edge, attr in zip(g.nodes[node]['edges'], g.nodes[node]['edge_attr']):
                        if attr == 'Call':
                            g.add_edge(node, edge, color='r')
                        if attr == 'Fallthrough':
                            g.add_edge(node, edge, color='g')
                        if attr == 'Jump':
                            g.add_edge(node, edge, color='b')
                else:
                    g.nodes[node]['edges'].append(list_sorted.pop(0))
                    g.nodes[node]['edge_attr'].append("Fallthrough")
                    for edge, attr in zip(g.nodes[node]['edges'], g.nodes[node]['edge_attr']):
                        if attr == 'Call':
                            g.add_edge(node, edge, color='r')
                        if attr == 'Fallthrough':
                            g.add_edge(node, edge, color='g')
                        if attr == 'Jump':
                            g.add_edge(node, edge, color='b')
            else:
                g.nodes[node]['edges'].append(list_sorted.pop(0))
                g.nodes[node]['edge_attr'].append("Fallthrough")
                for edge, attr in zip(g.nodes[node]['edges'], g.nodes[node]['edge_attr']):
                    if attr == 'Call':
                        g.add_edge(node, edge, color='r')
                    if attr == 'Fallthrough':
                        g.add_edge(node, edge, color='g')
                    if attr == 'Jump':
                        g.add_edge(node, edge, color='b')

    # legend_elements = [
        # Line2D([0], [0], marker='_', color='r', label='Call', markerfacecolor='r', markersize=10),
        # Line2D([0], [0], marker='_', color='g', label='Fallthrough', markerfacecolor='g', markersize=10),
        # Line2D([0], [0], marker='_', color='b', label='Jump', markerfacecolor='b', markersize=10)
    # ]

    # colors = nx.get_edge_attributes(g, 'color').values()
    # nx.draw_networkx(g, edge_color=colors, arrows=True)
    # plt.legend(handles=legend_elements, loc='upper right')
    # plt.show()
    pickle.dump(g, open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/ghidra.p", "wb"))

    
if __name__ == '__main__':
    run()

