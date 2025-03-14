import idaapi
import idautils
import idc
import ida_funcs
import ida_ua
import sys
import networkx as nx
import pickle
import xxhash
from basic_block import BasicBlock


def unoverflow(x):
    return (abs(x) ^ 0xff) + 1


def to_hex(integer):
    return '{:02x}'.format(integer)


def main():
    f = open(idc.ARGV[1], 'w') if len(idc.ARGV) > 1 else sys.stdout
    log = f.write

    idc.auto_wait()
    idaapi.rebase_program(-1 * idaapi.get_imagebase(), idc.MSF_FIXONCE)

    segm = idaapi.get_segm_by_name(".text")
    start = segm.start_ea
    end = segm.end_ea
    while start < end:
        start = idaapi.find_not_func(start, 1)
        ida_funcs.add_func(start)

    cond_jump_instructions = ['JE', 'JNE', 'JBE', 'JLE', 'JA', 'JB', 'JG', 'JGE', 'JZ', 'JNZ', \
                              'JNBE', 'JAE', 'JNB', 'JNAE', 'JNA', 'JL', 'JC', 'JNC', 'JO', 'JNO', 'JS', 'JNS', 'JP', \
                              'JPE',  'JNP', 'JPO', 'JCXZ', 'JECXZ', 'JNLE', 'JNL', 'JNGE', 'JNG']
    
    g = nx.DiGraph()
    idc.auto_wait()
    for func in idautils.Functions():
        flowchart = idaapi.FlowChart(idaapi.get_func(func), flags=idaapi.FC_NOEXT | idaapi.FC_CALL_ENDS)
        for bb in flowchart:

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
            start = bb.start_ea
            end = bb.end_ea
            cur_addr = start

            if bb.start_ea == idc.get_func_attr(func, idc.FUNCATTR_START):
                func_beg = True

            while cur_addr <= end:
                log(' '.join([to_hex(b) if b >= 0 else to_hex(unoverflow(b)) for b in idc.get_bytes(cur_addr, idc.get_item_size(cur_addr))]).upper() + '\t\t' + idc.GetDisasm(cur_addr).upper() + '\t' + hex(cur_addr) + '\n')
                mnemonic = idc.GetDisasm(cur_addr).upper().split(' ')[0]
                norm_instr = idc.GetDisasm(cur_addr).upper()
                if mnemonic in cond_jump_instructions:
                    norm_instr = 'JZ ' + hex(idc.get_operand_value(cur_addr, 0))
                elif 'RETN' in mnemonic:
                    norm_instr = 'RET'
                list_instr.append(idc.GetDisasm(cur_addr).upper())
                list_instr_norm.append(norm_instr)
                x.update(bytes(norm_instr.split(' ')[0].upper().strip(), 'UTF-8'))
                list_bytes.append(' '.join([to_hex(b) if b >= 0 else to_hex(unoverflow(b)) for b in
                                            idc.get_bytes(cur_addr, idc.get_item_size(cur_addr))]).upper())
                list_addr.append(hex(cur_addr))

                if mnemonic in cond_jump_instructions:
                    conditional_jump = True
                    arg_addr = idc.get_operand_value(cur_addr, 0)
                    if idc.get_operand_type(cur_addr, 0) == idc.o_far or \
                            idc.get_operand_type(cur_addr, 0) == idc.o_near:
                        dir_jump = True
                        list_edges.append(hex(arg_addr))
                    else:
                        indir_jump = True
                        list_edges.append("UnresolvableJumpTarget")
                    list_edge_attr.append("Jump")
                if 'JMP' in mnemonic:
                    conditional_jump = False
                    arg_addr = idc.get_operand_value(cur_addr, 0)
                    if idc.get_operand_type(cur_addr, 0) == idc.o_far or \
                            idc.get_operand_type(cur_addr, 0) == idc.o_near:
                        dir_jump = True
                        list_edges.append(hex(arg_addr))
                    else:
                        indir_jump = True
                        list_edges.append("UnresolvableJumpTarget")
                    list_edge_attr.append("Jump")
                if 'CALL' in mnemonic:
                    arg_addr = idc.get_operand_value(cur_addr, 0)
                    if idc.get_operand_type(cur_addr, 0) == idc.o_far or \
                            idc.get_operand_type(cur_addr, 0) == idc.o_near:
                        dir_call = True
                        list_edges.append(hex(arg_addr))
                    else:
                        indir_call = True
                        list_edges.append("UnresolvableCallTarget")
                    list_edge_attr.append("Call")
                if 'RET' in mnemonic or 'RETN' in mnemonic:
                    has_return = True

                cur_addr = idc.next_head(cur_addr, end)

            bb = BasicBlock()
            bb.start_addr = hex(int(list_addr[0], 16))
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
                g.add_node(bb.start_addr, instr=bb.list_instr,
                            instr_norm=bb.list_instr_norm,
                            bytes=bb.list_bytes, addr=bb.list_addr,
                            edges=bb.list_edges,
                            edge_attr=bb.list_edge_attr, func_beg=bb.function_beginning,
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

    pickle.dump(g, open(idc.ARGV[2], "wb"))

    if f != sys.stdout:
        f.close()
        idc.qexit(0)


if __name__ == "__main__":
    main()