import angr
import sys
import re
import networkx as nx
import matplotlib.pyplot as plt

from typing import List, Tuple


class BasicBlock:
    start_addr: int
    list_bytes: List[List]
    list_instr: List[str]
    list_addr: List[int]

    def __repr__(self):
        return f'{self.start_addr} {self.list_bytes} {self.list_instr} {self.list_addr}'


def run():
    f = open(sys.argv[2], 'w')
    base_addr = 0x100000
    p = angr.Project(sys.argv[1], auto_load_libs=False,
                     load_options={'main_opts': {'base_addr': base_addr}})
    cfg = p.analyses.CFGFast()
    cfg.normalize()
    g = nx.DiGraph()
    idx = 0
    for func_node in cfg.functions.values():
        for block in func_node.blocks:
            idx += 1
            c = block.capstone
            list_bytes = list()
            list_instr = list()
            list_addr = list()
            for i in c.insns:
                f.write(' '.join(re.findall(r'.{1,2}', i.insn.bytes.hex())).upper() + '\t\t' + i.mnemonic.upper() +
                        " " + i.op_str.upper() + '\n')
                list_bytes.append(f' '.join(re.findall(r'.{1,2}', i.insn.bytes.hex())).upper())
                list_instr.append(f'{i.mnemonic} {i.op_str}'.upper())
                list_addr.append(f'{hex(i.address)}')

            bb = BasicBlock()
            bb.start_addr = hex(block.addr)
            bb.list_bytes = list_bytes
            bb.list_instr = list_instr
            bb.list_addr = list_addr
            g.add_node(bb.start_addr, instr=bb.list_instr, bytes=bb.list_bytes, addr=bb.list_addr)

    list_sort = sorted(list(g.nodes))[1:]
    for node in sorted(list(g.nodes)):
        print(g.nodes[node]['instr'])
        print(g.nodes[node]['addr'])
        for instr in list(g.nodes[node]['instr']):
            if 'JE' in instr:
                jump_addr = instr.split(' ')[1]
                print(jump_addr.lower())
                g.add_edge(node, jump_addr.lower())
            if 'BND JMP' in instr:
                length = len(instr)
                if length == 16:
                    jump_addr = instr.split(' ')[2]
                    print(jump_addr.lower())
                    g.add_edge(node, jump_addr.lower())
            if 'CALL' in instr:
                length = len(instr)
                if length == 13:
                    call_addr = instr.split(' ')[1]
                    print(call_addr.lower())
                    g.add_edge(node, call_addr.lower())
        if list_sort:
            g.add_edge(node, list_sort.pop(0))

    print(g)
    options = {
        'node_color': 'blue',
        'node_size': 50,
        'width': 3,
        'arrowstyle': '-|>',
        'arrowsize': 12,
    }
    nx.draw_networkx(g, arrows=True)
    plt.show()


if __name__ == '__main__':
    run()
