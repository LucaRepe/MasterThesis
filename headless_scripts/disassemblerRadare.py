import sys
import re
import r2pipe
import networkx as nx
from typing import Tuple, List
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D

if (sys.version_info.major, sys.version_info.minor) < (3, 6):
    exit("Run me with Python3.6 (or above) please.")


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


class FunctionDescriptor(dict):
    """ A wrapper for functions in executables, with additions for blocks binary and disassembly and properties
    for important stuff """

    class Keys:
        name = "name"
        address = "offset"
        size = "size"

    @property
    def name(self) -> str:
        return self[self.Keys.name]

    @property
    def address(self) -> int:
        return int(self[self.Keys.address])

    @property
    def size(self) -> int:
        return int(self[self.Keys.size])


class BlockDescriptor(dict):
    """ A wrapper for blocks, with additions and properties for important stuff """

    class Keys:
        address = "addr"
        size = "size"
        dsm = "dsm"
        binary = "binary"

    @property
    def address(self) -> int:
        return int(self[self.Keys.address])

    @property
    def size(self) -> int:
        return int(self[self.Keys.size])

    @property
    def dsm(self) -> List[Tuple[int, str, int]]:
        return self[self.Keys.dsm]

    @dsm.setter
    def dsm(self, value):
        self[self.Keys.dsm] = value

    @property
    def binary(self) -> List[int]:
        return self[self.Keys.binary]

    @binary.setter
    def binary(self, value):
        self[self.Keys.binary] = value


def run(filepath):
    """ Disassembles an exe using radare2, :returns A dict {function address} -> {block address} """
    r2 = r2pipe.open(filepath)
    f = open(sys.argv[2], 'w')
    # r2.cmd("B 1048576")
    r2.cmd("aaaa")  # do an analysis to find functions
    functions = r2.cmdj("aflj")  # get all functions

    print(f"Disassembling {len(functions)} functions in {filepath}")

    g = nx.DiGraph()
    for function in functions:
        function = FunctionDescriptor(function)
        nome = function.name
        print(nome)
        basic_blocks_list = r2.cmdj("afbj " + str(function.address))

        for block in basic_blocks_list:
            block_info = r2.cmdj("pdbj@" + str(block['addr']))
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

            if block['addr'] == function.address:
                func_beg = True

            for block_instr in block_info:
                f.write(' '.join(re.findall(r'.{1,2}', str(block_instr["bytes"]).upper())) + '\t' +
                        block_instr['opcode'].upper() + '\n')
                list_instr.append(block_instr['opcode'].upper())
                list_bytes.append(' '.join(re.findall(r'.{1,2}', str(block_instr["bytes"]).upper())))
                list_addr.append(hex(block_instr['offset']))

            # print(list_instr)
            # print(list_bytes)
            # print(list_addr)

            for instr in list_instr:
                if 'JE' in instr or 'JNE' in instr or 'JMP' in instr:
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
            bb.start_addr = hex(block['addr'])
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
        if list_sorted:
            if g.nodes[node]['has_return']:
                list_sorted.pop(0)
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
    plt.show()
    print(g)


if __name__ == '__main__':
    run(sys.argv[1])
