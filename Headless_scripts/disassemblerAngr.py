import angr
import sys
import re
import networkx as nx
import pickle
import xxhash
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
import scipy as sp

from typing import List


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

    def __repr__(self):
        return f'{self.start_addr} {self.list_bytes} {self.list_instr} {self.list_addr} {self.list_edges} ' \
               f'{self.list_edge_attr} '


def run():
    f = open(sys.argv[2], 'w')
    p = angr.Project(sys.argv[1], auto_load_libs=False)
    cfg = p.analyses.CFGFast()
    cfg.normalize()

    g = nx.DiGraph()
    for func_node in cfg.functions.values():
        for block in func_node.blocks:
            c = block.capstone
            list_bytes = list()
            list_instr = list()
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

            if c.addr == func_node.addr:
                func_beg = True

            for i in c.insns:
                f.write(' '.join(re.findall(r'.{1,2}', i.insn.bytes.hex())).upper() + '\t\t' + i.mnemonic.upper() +
                        " " + i.op_str.upper() + '\n')
                list_bytes.append(f' '.join(re.findall(r'.{1,2}', i.insn.bytes.hex())).upper())
                list_instr.append(f'{i.mnemonic} {i.op_str}'.upper())
                x.update(bytes(i.mnemonic.upper().strip(), 'UTF-8'))
                list_addr.append(f'{hex(i.address)}')

            for instr in list_instr:
                if 'JE' in instr or 'JNE' in instr or 'JBE' in instr or 'JLE' in instr or \
                        'JA' in instr or 'JB' in instr or 'JG' in instr or 'JGE' in instr or \
                        'JZ' in instr or 'JNZ' in instr or 'JNBE' in instr or 'JAE' in instr or \
                        'JNB' in instr or 'JNAE' in instr or 'JNA' in instr:
                    conditional_jump = True
                    jump_addr = instr.split(' ')[-1]
                    if jump_addr[-1] == ']':
                        indir_jump = True
                        list_edges.append("UnresolvableJumpTarget")
                    elif '0X' in jump_addr:
                        dir_jump = True
                        list_edges.append(jump_addr.lower())
                    else:
                        indir_jump = True
                        list_edges.append("UnresolvableJumpTarget")
                    list_edge_attr.append("Jump")
                if 'JMP' in instr:
                    conditional_jump = False
                    jump_addr = instr.split(' ')[-1]
                    if jump_addr[-1] == ']':
                        indir_jump = True
                        list_edges.append("UnresolvableJumpTarget")
                    elif '0X' in jump_addr:
                        dir_jump = True
                        list_edges.append(jump_addr.lower())
                    else:
                        indir_jump = True
                        list_edges.append("UnresolvableJumpTarget")
                    list_edge_attr.append("Jump")
                if 'CALL' in instr:
                    call_addr = instr.split(' ')[1]
                    if call_addr[-1] == ']':
                        indir_call = True
                        list_edges.append("UnresolvableCallTarget")
                    elif '0X' in call_addr:
                        dir_call = True
                        list_edges.append(call_addr.lower())
                    else:
                        indir_call = True
                        list_edges.append("UnresolvableCallTarget")
                    list_edge_attr.append("Call")
                if 'RET' in instr:
                    has_return = True

            bb = BasicBlock()
            bb.start_addr = hex(block.addr)
            bb.list_bytes = list_bytes
            bb.list_instr = list_instr
            bb.list_addr = list_addr
            bb.list_edges = list_edges
            bb.list_edge_attr = list_edge_attr
            bb.function_beginning = func_beg
            bb.direct_fun_call = dir_call
            bb.indirect_fun_call = indir_call
            bb.conditional_jump = conditional_jump
            bb.direct_jump = dir_jump
            bb.indirect_jump = indir_jump
            bb.has_return = has_return
            bb.unique_hash_identifier = x.intdigest()
            if len(list_instr) != 0:
                g.add_node(bb.start_addr, instr=bb.list_instr, bytes=bb.list_bytes, addr=bb.list_addr,
                           edges=bb.list_edges, edge_attr=bb.list_edge_attr, func_beg=bb.function_beginning,
                           dir_call=bb.direct_fun_call, indir_call=bb.indirect_fun_call,
                           cond_jump=bb.conditional_jump, dir_jump=bb.direct_jump,
                           indir_jump=bb.indirect_jump, has_return=bb.has_return,
                           unique_hash_identifier=bb.unique_hash_identifier)

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

    legend_elements = [
        Line2D([0], [0], marker='_', color='r', label='Call', markerfacecolor='r', markersize=10),
        Line2D([0], [0], marker='_', color='g', label='Fallthrough', markerfacecolor='g', markersize=10),
        Line2D([0], [0], marker='_', color='b', label='Jump', markerfacecolor='b', markersize=10)
    ]

    colors = nx.get_edge_attributes(g, 'color').values()
    nx.draw_networkx(g, edge_color=colors, arrows=True)
    plt.legend(handles=legend_elements, loc='upper right')
    # plt.show()
    pickle.dump(g, open("/home/luca/Scrivania/MasterThesis/Pickles/angr.p", "wb"))


if __name__ == '__main__':
    run()
