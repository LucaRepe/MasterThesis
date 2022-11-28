import angr
import sys
import re
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D

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
    direct_jump: bool
    indirect_jump: bool
    has_return: bool

    def __repr__(self):
        return f'{self.start_addr} {self.list_bytes} {self.list_instr} {self.list_addr} {self.list_edges} ' \
               f'{self.list_edge_attr} '


def run():
    f = open(sys.argv[2], 'w')
    base_addr = 0x100000
    p = angr.Project(sys.argv[1], auto_load_libs=False,
            load_options={'main_opts': {'base_addr': base_addr}})
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
            dir_jump = False
            indir_jump = False
            has_return = False
            if c.addr == func_node.addr:
                func_beg = True

            for i in c.insns:
                f.write(' '.join(re.findall(r'.{1,2}', i.insn.bytes.hex())).upper() + '\t\t' + i.mnemonic.upper() +
                        " " + i.op_str.upper() + '\n')
                list_bytes.append(f' '.join(re.findall(r'.{1,2}', i.insn.bytes.hex())).upper())
                list_instr.append(f'{i.mnemonic} {i.op_str}'.upper())
                list_addr.append(f'{hex(i.address)}')
            # print(list_instr)

            for instr in list_instr:
                if 'JE' in instr or 'JNE' in instr or 'JMP' in instr:
                    jump_addr = instr.split(' ')[-1]
                    if jump_addr[-1] == ']':
                        # jump_addr = jump_addr.rstrip(jump_addr[-1])
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
                        # call_addr = call_addr.rstrip(jump_addr[-1])
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
            bb.direct_jump = dir_jump
            bb.indirect_jump = indir_jump
            bb.has_return = has_return
            if len(list_instr) != 0:
                g.add_node(bb.start_addr, instr=bb.list_instr, bytes=bb.list_bytes, addr=bb.list_addr,
                           edges=bb.list_edges, edge_attr=bb.list_edge_attr, func_beg=bb.function_beginning,
                           dir_call=bb.direct_fun_call, indir_call=bb.indirect_fun_call, dir_jump=bb.direct_jump,
                           indir_jump=bb.indirect_jump, has_return=bb.has_return)

    list_sorted = sorted(list(g.nodes))[1:]
    for node in sorted(list(g.nodes)):
        # print(g.nodes[node]['instr'])
        # print(g.nodes[node]['addr'])
        if list_sorted:
            if g.nodes[node]['has_return']:
                list_sorted.pop(0)
            else:
                g.nodes[node]['edges'].append(list_sorted.pop(0))
                g.nodes[node]['edge_attr'].append("Fallthrough")
                for edge in g.nodes[node]['edges']:
                    for attr in g.nodes[node]['edge_attr']:
                        if attr == 'Jump':
                            g.add_edge(node, edge, color='r')
                        if attr == 'Call':
                            g.add_edge(node, edge, color='b')
                        if attr == 'Fallthrough':
                            g.add_edge(node, edge, color='g')

    colors = ['r', 'g', 'b']
    nx.draw_networkx(g, edge_color=colors, arrows=True)

    legend_elements = [
        Line2D([0], [0], marker='o', color='r', label='Jump',markerfacecolor='r', markersize=15),
        Line2D([0], [0], marker='o', color='b', label='Call',markerfacecolor='b', markersize=15),
        Line2D([0], [0], marker='o', color='g', label='Fallthrough',markerfacecolor='g', markersize=15)        
    ]
    plt.legend(handles=legend_elements, loc='upper right')
    plt.show()


if __name__ == '__main__':
    run()



if __name__ == '__main__':
    run()
