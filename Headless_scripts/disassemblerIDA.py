import idaapi
import idautils
import idc
import sys
import networkx as nx
import pickle
import xxhash
from typing import List
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D


def unoverflow(x):
    return (abs(x) ^ 0xff) + 1


def to_hex(integer):
    return '{:02x}'.format(integer)


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
    conditional_jump = bool
    direct_jump: bool
    indirect_jump: bool
    has_return: bool
    unique_hash_identifier: int

    def __repr__(self):
        return f'{self.start_addr} {self.list_bytes} {self.list_instr} {self.list_addr} {self.list_edges} ' \
               f'{self.list_edge_attr} '


def run():
    f = open(idc.ARGV[1], 'w') if len(idc.ARGV) > 1 else sys.stdout
    log = f.write
    log(idc.ARGV[2] + '\n')

    idc.auto_wait()
    g = nx.DiGraph()
    for func in idautils.Functions():
        flowchart = idaapi.FlowChart(idaapi.get_func(func))
        for bb in flowchart:
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
            split_bb = False
            skip_adding = False
            start = bb.start_ea
            end = bb.end_ea
            cur_addr = start

            if bb.start_ea == idc.get_func_attr(func, idc.FUNCATTR_START):
                func_beg = True

            while cur_addr <= end:
                skip_adding = False
                log(' '.join([to_hex(b) if b >= 0 else to_hex(unoverflow(b)) for b in idc.get_bytes(cur_addr, idc.get_item_size(cur_addr))]).upper() + '\t\t' + idc.GetDisasm(cur_addr).upper() + '\n')
                list_instr.append(idc.GetDisasm(cur_addr).upper())
                x.update(bytes(idc.GetDisasm(cur_addr).split(' ')[0].upper().strip(), 'UTF-8'))
                list_bytes.append(' '.join([to_hex(b) if b >= 0 else to_hex(unoverflow(b)) for b in idc.get_bytes(cur_addr, idc.get_item_size(cur_addr))]).upper())
                list_addr.append(hex(cur_addr))


                if 'JE' in idc.GetDisasm(cur_addr).upper() or 'JNE' in idc.GetDisasm(cur_addr).upper() or \
                        'JBE' in idc.GetDisasm(cur_addr).upper() or 'JLE' in idc.GetDisasm(cur_addr).upper() or \
                        'JA' in idc.GetDisasm(cur_addr).upper() or 'JB' in idc.GetDisasm(cur_addr).upper() or \
                        'JG' in idc.GetDisasm(cur_addr).upper() or 'JGE' in idc.GetDisasm(cur_addr).upper() or \
                        'JZ' in idc.GetDisasm(cur_addr).upper() or 'JNZ' in idc.GetDisasm(cur_addr).upper() or \
                        'JNBE' in idc.GetDisasm(cur_addr).upper() or 'JAE' in idc.GetDisasm(cur_addr).upper() or \
                        'JNB' in idc.GetDisasm(cur_addr).upper() or 'JNAE' in idc.GetDisasm(cur_addr).upper() or \
                        'JNA' in idc.GetDisasm(cur_addr).upper():
                    conditional_jump = True
                    jump_addr = idc.GetDisasm(cur_addr).upper().split(' ')[-1]
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
                if 'JMP' in idc.GetDisasm(cur_addr).upper():
                    conditional_jump = False
                    jump_addr = idc.GetDisasm(cur_addr).upper().split(' ')[-1]
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
                if 'CALL' in idc.GetDisasm(cur_addr).upper():
                    if 'CALLBACK' in idc.GetDisasm(cur_addr).upper():
                        cur_addr = idc.next_head(cur_addr, end)
                        continue
                    split_bb = True
                    call_addr = idc.GetDisasm(cur_addr).upper().split(' ')[-1]
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
                if 'RETN' in idc.GetDisasm(cur_addr).upper():
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
                        g.add_node(bb.start_addr, instr=bb.list_instr, bytes=bb.list_bytes, addr=bb.list_addr,
                                   edges=bb.list_edges, edge_attr=bb.list_edge_attr, func_beg=bb.function_beginning,
                                   dir_call=bb.direct_fun_call, indir_call=bb.indirect_fun_call,
                                   cond_jump=bb.conditional_jump, dir_jump=bb.direct_jump,
                                   indir_jump=bb.indirect_jump, has_return=bb.has_return,
                                   unique_hash_identifier=bb.unique_hash_identifier)

                        list_bytes.clear()
                        list_instr.clear()
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

                cur_addr = idc.next_head(cur_addr, end)

            if not skip_adding:
                skip_adding = False
                bb_not_splitted = BasicBlock()
                bb_not_splitted.start_addr = hex(int(list_addr[0], 16))
                bb_not_splitted.list_bytes = list_bytes
                bb_not_splitted.list_instr = list_instr
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
                    g.add_node(bb_not_splitted.start_addr, instr=bb_not_splitted.list_instr, bytes=bb_not_splitted.list_bytes, addr=bb_not_splitted.list_addr,
                            edges=bb_not_splitted.list_edges, edge_attr=bb_not_splitted.list_edge_attr, func_beg=bb_not_splitted.function_beginning,
                            dir_call=bb_not_splitted.direct_fun_call, indir_call=bb_not_splitted.indirect_fun_call,
                            cond_jump=bb_not_splitted.conditional_jump, dir_jump=bb_not_splitted.direct_jump,
                            indir_jump=bb_not_splitted.indirect_jump, has_return=bb_not_splitted.has_return,
                            unique_hash_identifier=bb_not_splitted.unique_hash_identifier)
                skip_adding = False

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
    pickle.dump(g, open(idc.ARGV[2], "wb"))

    if f != sys.stdout:
        f.close()
        idc.qexit(0)
    

if __name__ == "__main__":
    run()