import angr
import sys
import re
import networkx as nx
import pickle
import xxhash

from basic_block import BasicBlock


def run():
    f = open(sys.argv[2], 'w')
    p = angr.Project(sys.argv[1], auto_load_libs=False, main_opts={'base_addr': 0, 'force_rebase': True} )
    cfg = p.analyses.CFGFast()
    cfg.normalize()

    cond_jump_instructions = ['JE', 'JNE', 'JBE', 'JLE', 'JA', 'JB', 'JG', 'JGE', 'JZ', 'JNZ', \
     'JNBE', 'JAE', 'JNB', 'JNAE', 'JNA', 'JL', 'JC', 'JNC', 'JO', 'JNO', 'JS', 'JNS', 'JP', 'JPE', \
     'JNP', 'JPO', 'JCXZ', 'JECXZ', 'JNLE', 'JNL', 'JNGE', 'JNG']
    g = nx.DiGraph()
    for func_node in cfg.functions.values():
        rep_flag = False
        merge_bb = False
        for block in func_node.blocks:
            c = block.capstone
            if c.insns:
                if 'rep' in c.insns[0].mnemonic:
                    continue
            
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
            if not merge_bb:
                x = xxhash.xxh32()

            if c.addr == func_node.addr:
                func_beg = True

            for i in c.insns:
                f.write(' '.join(re.findall(r'.{1,2}', i.insn.bytes.hex())).upper() + '\t\t' + i.mnemonic.upper() +
                        " " + i.op_str.upper() + '\n')
                list_bytes.append(f' '.join(re.findall(r'.{1,2}', i.insn.bytes.hex())).upper())
                norm_instr = i.mnemonic.upper() + ' ' + i.op_str.upper()    
                if i.mnemonic.upper() in cond_jump_instructions:
                    norm_instr = 'JZ ' + i.op_str.upper()
                elif 'RETN' in i.mnemonic.upper():
                    norm_instr = 'RET'
                list_instr.append(f'{i.mnemonic} {i.op_str}'.upper())
                list_instr_norm.append(f'{norm_instr}'.upper())
                x.update(bytes(norm_instr.split(' ')[0].upper().strip(), 'UTF-8'))
                list_addr.append(f'{hex(i.address)}')

                if i.mnemonic.upper() in cond_jump_instructions:
                    conditional_jump = True
                    jump_addr = i.op_str.upper()
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
                if 'JMP' in i.mnemonic.upper():
                    conditional_jump = False
                    jump_addr = i.op_str.upper()
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
                if 'CALL' in i.mnemonic.upper():
                    call_addr = i.op_str.upper()
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
                if 'RET' in i.mnemonic.upper() or 'RETN' in i.mnemonic.upper():
                    has_return = True
                if 'REP' in i.mnemonic.upper():
                    rep_flag = True

            if rep_flag:
                rep_flag = False
                merge_bb = True
                start_addr = hex(block.addr)
                list_bytes_old = list_bytes.copy()
                list_instr_old = list_instr.copy()
                list_instr_norm_old = list_instr_norm.copy()
                list_addr_old = list_addr.copy()
                list_edges_old = list_edges.copy()
                list_edge_attr_old = list_edge_attr.copy()
                func_beg_old = func_beg
                dir_call_old = dir_call
                indir_call_old = indir_call
                conditional_jump_old = conditional_jump
                dir_jump_old = dir_jump
                indir_jump_old = indir_jump
                has_return_old = has_return
                continue

            if merge_bb:
                merge_bb = False
                list_bytes = list_bytes_old + list_bytes
                list_instr = list_instr_old + list_instr
                list_instr_norm = list_instr_norm_old + list_instr_norm
                list_addr = list_addr_old + list_addr
                list_edges = list_edges_old + list_edges
                list_edge_attr = list_edge_attr_old + list_edge_attr
                func_beg = func_beg_old or func_beg_old
                dir_call = dir_call_old or dir_call
                indir_call = indir_call_old or indir_call
                conditional_jump = conditional_jump_old or conditional_jump
                dir_jump = dir_jump_old or dir_jump
                indir_jump = indir_jump_old or indir_jump
                has_return = has_return_old or has_return
            else:
                start_addr = hex(block.addr)
                
            bb = BasicBlock()
            bb.start_addr = start_addr
            bb.list_bytes = list_bytes
            bb.list_instr = list_instr
            bb.list_instr_norm = list_instr_norm
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
                g.add_node(bb.start_addr, instr=bb.list_instr, instr_norm=bb.list_instr_norm, bytes=bb.list_bytes,
                        addr=bb.list_addr, edges=bb.list_edges, edge_attr=bb.list_edge_attr,
                        func_beg=bb.function_beginning, dir_call=bb.direct_fun_call,
                        indir_call=bb.indirect_fun_call, cond_jump=bb.conditional_jump,
                        dir_jump=bb.direct_jump, indir_jump=bb.indirect_jump, has_return=bb.has_return,
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

    # legend_elements = [
        # Line2D([0], [0], marker='_', color='r', label='Call', markerfacecolor='r', markersize=10),
        # Line2D([0], [0], marker='_', color='g', label='Fallthrough', markerfacecolor='g', markersize=10),
        # Line2D([0], [0], marker='_', color='b', label='Jump', markerfacecolor='b', markersize=10)
    # ]

    # colors = nx.get_edge_attributes(g, 'color').values()
    # nx.draw_networkx(g, edge_color=colors, arrows=True)
    # plt.legend(handles=legend_elements, loc='upper right')
    # plt.show()
    pickle.dump(g, open(sys.argv[3], "wb"))


if __name__ == '__main__':
    run()
