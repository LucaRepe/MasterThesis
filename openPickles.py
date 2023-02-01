import re
import pickle
import networkx as nx


def run():
    ghidra = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/ghidra.p", "rb"))
    radare = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/radare.p", "rb"))
    angr = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/angr.p", "rb"))
    ida = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/ida.p", "rb"))

    base_address = 0x5e0000
    bbl_string = open('/home/luca/Scrivania/MasterThesis/testmain-14268.bbl').read()
    bbl_list = re.findall('.{1,8}', bbl_string)
    ground_truth = set()
    for addr in bbl_list:
        real_address = int(addr, 16) - base_address
        if real_address < 0:
            continue
        ground_truth.add(hex(real_address))

    ghidra_purged = nx.DiGraph()
    for addr in ground_truth:
        for node in ghidra:
            if addr == node:
                ghidra_purged.add_node(node, instr=ghidra.nodes[node].get('instr'),
                                       bytes=ghidra.nodes[node].get('bytes'), addr=ghidra.nodes[node].get('addr'),
                                       edges=ghidra.nodes[node].get('edges'), edge_attr=ghidra.nodes[node].get('edge_attr'),
                                       func_beg=ghidra.nodes[node].get('func_beg'), dir_call=ghidra.nodes[node].get('dir_call'),
                                       indir_call=ghidra.nodes[node].get('indir_call'), cond_jump=ghidra.nodes[node].get('cond_jump'),
                                       dir_jump=ghidra.nodes[node].get('dir_jump'), indir_jump=ghidra.nodes[node].get('indir_jump'),
                                       has_return=ghidra.nodes[node].get('has_return'), unique_hash_identifier=ghidra.nodes[node].get('unique_hash_identifier'))

    list_sorted = sorted(list(ghidra_purged.nodes))[1:]
    for node in sorted(list(ghidra_purged.nodes)):
        if list_sorted:
            if ghidra_purged.nodes[node]['has_return']:
                list_sorted.pop(0)
                for edge, attr in zip(ghidra_purged.nodes[node]['edges'], ghidra_purged.nodes[node]['edge_attr']):
                    if attr == 'Call':
                        ghidra_purged.add_edge(node, edge, color='r')
                    if attr == 'Fallthrough':
                        ghidra_purged.add_edge(node, edge, color='g')
                    if attr == 'Jump':
                        ghidra_purged.add_edge(node, edge, color='b')
            elif ghidra_purged.nodes[node]['dir_jump'] or ghidra_purged.nodes[node]['indir_jump']:
                if not ghidra_purged.nodes[node]['cond_jump']:
                    list_sorted.pop(0)
                    for edge, attr in zip(ghidra_purged.nodes[node]['edges'], ghidra_purged.nodes[node]['edge_attr']):
                        if attr == 'Call':
                            ghidra_purged.add_edge(node, edge, color='r')
                        if attr == 'Fallthrough':
                            ghidra_purged.add_edge(node, edge, color='g')
                        if attr == 'Jump':
                            ghidra_purged.add_edge(node, edge, color='b')
                else:
                    ghidra_purged.nodes[node]['edges'].append(list_sorted.pop(0))
                    ghidra_purged.nodes[node]['edge_attr'].append("Fallthrough")
                    for edge, attr in zip(ghidra_purged.nodes[node]['edges'], ghidra_purged.nodes[node]['edge_attr']):
                        if attr == 'Call':
                            ghidra_purged.add_edge(node, edge, color='r')
                        if attr == 'Fallthrough':
                            ghidra_purged.add_edge(node, edge, color='g')
                        if attr == 'Jump':
                            ghidra_purged.add_edge(node, edge, color='b')
            else:
                ghidra_purged.nodes[node]['edges'].append(list_sorted.pop(0))
                ghidra_purged.nodes[node]['edge_attr'].append("Fallthrough")
                for edge, attr in zip(ghidra_purged.nodes[node]['edges'], ghidra_purged.nodes[node]['edge_attr']):
                    if attr == 'Call':
                        ghidra_purged.add_edge(node, edge, color='r')
                    if attr == 'Fallthrough':
                        ghidra_purged.add_edge(node, edge, color='g')
                    if attr == 'Jump':
                        ghidra_purged.add_edge(node, edge, color='b')

    radare_purged = nx.DiGraph()
    for addr in ground_truth:
        for node in radare:
            if addr == node:
                radare_purged.add_node(node, instr=radare.nodes[node].get('instr'),
                                       bytes=radare.nodes[node].get('bytes'), addr=radare.nodes[node].get('addr'),
                                       edges=radare.nodes[node].get('edges'),
                                       edge_attr=radare.nodes[node].get('edge_attr'),
                                       func_beg=radare.nodes[node].get('func_beg'),
                                       dir_call=radare.nodes[node].get('dir_call'),
                                       indir_call=radare.nodes[node].get('indir_call'),
                                       cond_jump=radare.nodes[node].get('cond_jump'),
                                       dir_jump=radare.nodes[node].get('dir_jump'),
                                       indir_jump=radare.nodes[node].get('indir_jump'),
                                       has_return=radare.nodes[node].get('has_return'),
                                       unique_hash_identifier=radare.nodes[node].get('unique_hash_identifier'))

    list_sorted = sorted(list(radare_purged.nodes))[1:]
    for node in sorted(list(radare_purged.nodes)):
        if list_sorted:
            if radare_purged.nodes[node]['has_return']:
                list_sorted.pop(0)
                for edge, attr in zip(radare_purged.nodes[node]['edges'], radare_purged.nodes[node]['edge_attr']):
                    if attr == 'Call':
                        radare_purged.add_edge(node, edge, color='r')
                    if attr == 'Fallthrough':
                        radare_purged.add_edge(node, edge, color='g')
                    if attr == 'Jump':
                        radare_purged.add_edge(node, edge, color='b')
            elif radare_purged.nodes[node]['dir_jump'] or radare_purged.nodes[node]['indir_jump']:
                if not radare_purged.nodes[node]['cond_jump']:
                    list_sorted.pop(0)
                    for edge, attr in zip(radare_purged.nodes[node]['edges'], radare_purged.nodes[node]['edge_attr']):
                        if attr == 'Call':
                            radare_purged.add_edge(node, edge, color='r')
                        if attr == 'Fallthrough':
                            radare_purged.add_edge(node, edge, color='g')
                        if attr == 'Jump':
                            radare_purged.add_edge(node, edge, color='b')
                else:
                    radare_purged.nodes[node]['edges'].append(list_sorted.pop(0))
                    radare_purged.nodes[node]['edge_attr'].append("Fallthrough")
                    for edge, attr in zip(radare_purged.nodes[node]['edges'], radare_purged.nodes[node]['edge_attr']):
                        if attr == 'Call':
                            radare_purged.add_edge(node, edge, color='r')
                        if attr == 'Fallthrough':
                            radare_purged.add_edge(node, edge, color='g')
                        if attr == 'Jump':
                            radare_purged.add_edge(node, edge, color='b')
            else:
                radare_purged.nodes[node]['edges'].append(list_sorted.pop(0))
                radare_purged.nodes[node]['edge_attr'].append("Fallthrough")
                for edge, attr in zip(radare_purged.nodes[node]['edges'], radare_purged.nodes[node]['edge_attr']):
                    if attr == 'Call':
                        radare_purged.add_edge(node, edge, color='r')
                    if attr == 'Fallthrough':
                        radare_purged.add_edge(node, edge, color='g')
                    if attr == 'Jump':
                        radare_purged.add_edge(node, edge, color='b')

    angr_purged = nx.DiGraph()
    for addr in ground_truth:
        for node in angr:
            if addr == node:
                print("Si")
                angr_purged.add_node(node, instr=angr.nodes[node].get('instr'),
                                       bytes=angr.nodes[node].get('bytes'), addr=angr.nodes[node].get('addr'),
                                       edges=angr.nodes[node].get('edges'),
                                       edge_attr=angr.nodes[node].get('edge_attr'),
                                       func_beg=angr.nodes[node].get('func_beg'),
                                       dir_call=angr.nodes[node].get('dir_call'),
                                       indir_call=angr.nodes[node].get('indir_call'),
                                       cond_jump=angr.nodes[node].get('cond_jump'),
                                       dir_jump=angr.nodes[node].get('dir_jump'),
                                       indir_jump=angr.nodes[node].get('indir_jump'),
                                       has_return=angr.nodes[node].get('has_return'),
                                       unique_hash_identifier=angr.nodes[node].get('unique_hash_identifier'))

    list_sorted = sorted(list(angr_purged.nodes))[1:]
    for node in sorted(list(angr_purged.nodes)):
        if list_sorted:
            if angr_purged.nodes[node]['has_return']:
                list_sorted.pop(0)
                for edge, attr in zip(angr_purged.nodes[node]['edges'], angr_purged.nodes[node]['edge_attr']):
                    if attr == 'Call':
                        angr_purged.add_edge(node, edge, color='r')
                    if attr == 'Fallthrough':
                        angr_purged.add_edge(node, edge, color='g')
                    if attr == 'Jump':
                        angr_purged.add_edge(node, edge, color='b')
            elif angr_purged.nodes[node]['dir_jump'] or angr_purged.nodes[node]['indir_jump']:
                if not angr_purged.nodes[node]['cond_jump']:
                    list_sorted.pop(0)
                    for edge, attr in zip(angr_purged.nodes[node]['edges'], angr_purged.nodes[node]['edge_attr']):
                        if attr == 'Call':
                            angr_purged.add_edge(node, edge, color='r')
                        if attr == 'Fallthrough':
                            angr_purged.add_edge(node, edge, color='g')
                        if attr == 'Jump':
                            angr_purged.add_edge(node, edge, color='b')
                else:
                    angr_purged.nodes[node]['edges'].append(list_sorted.pop(0))
                    angr_purged.nodes[node]['edge_attr'].append("Fallthrough")
                    for edge, attr in zip(angr_purged.nodes[node]['edges'], angr_purged.nodes[node]['edge_attr']):
                        if attr == 'Call':
                            angr_purged.add_edge(node, edge, color='r')
                        if attr == 'Fallthrough':
                            angr_purged.add_edge(node, edge, color='g')
                        if attr == 'Jump':
                            angr_purged.add_edge(node, edge, color='b')
            else:
                angr_purged.nodes[node]['edges'].append(list_sorted.pop(0))
                angr_purged.nodes[node]['edge_attr'].append("Fallthrough")
                for edge, attr in zip(angr_purged.nodes[node]['edges'], angr_purged.nodes[node]['edge_attr']):
                    if attr == 'Call':
                        angr_purged.add_edge(node, edge, color='r')
                    if attr == 'Fallthrough':
                        angr_purged.add_edge(node, edge, color='g')
                    if attr == 'Jump':
                        angr_purged.add_edge(node, edge, color='b')

    ida_purged = nx.DiGraph()
    for addr in ground_truth:
        for node in ida:
            if addr == node:
                print("Si")
                ida_purged.add_node(node, instr=ida.nodes[node].get('instr'),
                                     bytes=ida.nodes[node].get('bytes'), addr=ida.nodes[node].get('addr'),
                                     edges=ida.nodes[node].get('edges'),
                                     edge_attr=ida.nodes[node].get('edge_attr'),
                                     func_beg=ida.nodes[node].get('func_beg'),
                                     dir_call=ida.nodes[node].get('dir_call'),
                                     indir_call=ida.nodes[node].get('indir_call'),
                                     cond_jump=ida.nodes[node].get('cond_jump'),
                                     dir_jump=ida.nodes[node].get('dir_jump'),
                                     indir_jump=ida.nodes[node].get('indir_jump'),
                                     has_return=ida.nodes[node].get('has_return'),
                                     unique_hash_identifier=ida.nodes[node].get('unique_hash_identifier'))

    list_sorted = sorted(list(ida_purged.nodes))[1:]
    for node in sorted(list(ida_purged.nodes)):
        if list_sorted:
            if ida_purged.nodes[node]['has_return']:
                list_sorted.pop(0)
                for edge, attr in zip(ida_purged.nodes[node]['edges'], ida_purged.nodes[node]['edge_attr']):
                    if attr == 'Call':
                        ida_purged.add_edge(node, edge, color='r')
                    if attr == 'Fallthrough':
                        ida_purged.add_edge(node, edge, color='g')
                    if attr == 'Jump':
                        ida_purged.add_edge(node, edge, color='b')
            elif ida_purged.nodes[node]['dir_jump'] or ida_purged.nodes[node]['indir_jump']:
                if not ida_purged.nodes[node]['cond_jump']:
                    list_sorted.pop(0)
                    for edge, attr in zip(ida_purged.nodes[node]['edges'], ida_purged.nodes[node]['edge_attr']):
                        if attr == 'Call':
                            ida_purged.add_edge(node, edge, color='r')
                        if attr == 'Fallthrough':
                            ida_purged.add_edge(node, edge, color='g')
                        if attr == 'Jump':
                            ida_purged.add_edge(node, edge, color='b')
                else:
                    ida_purged.nodes[node]['edges'].append(list_sorted.pop(0))
                    ida_purged.nodes[node]['edge_attr'].append("Fallthrough")
                    for edge, attr in zip(ida_purged.nodes[node]['edges'], ida_purged.nodes[node]['edge_attr']):
                        if attr == 'Call':
                            ida_purged.add_edge(node, edge, color='r')
                        if attr == 'Fallthrough':
                            ida_purged.add_edge(node, edge, color='g')
                        if attr == 'Jump':
                            ida_purged.add_edge(node, edge, color='b')
            else:
                ida_purged.nodes[node]['edges'].append(list_sorted.pop(0))
                ida_purged.nodes[node]['edge_attr'].append("Fallthrough")
                for edge, attr in zip(ida_purged.nodes[node]['edges'], ida_purged.nodes[node]['edge_attr']):
                    if attr == 'Call':
                        ida_purged.add_edge(node, edge, color='r')
                    if attr == 'Fallthrough':
                        ida_purged.add_edge(node, edge, color='g')
                    if attr == 'Jump':
                        ida_purged.add_edge(node, edge, color='b')

    # print(ghidra)
    # print(radare)
    # print(angr)
    # print(ida)

    G = angr.nodes() - ida.nodes()

    # for node in G:
        # print(node)
        # print(f"{'instr'} {angr.nodes[node].get('instr')}")
        # print(f"{'edges'} {angr.nodes[node].get('edges')}")
        # print(f"{'edge_attr'} {angr.nodes[node].get('edge_attr')}")
        # print(f"{'func_beg'} {angr.nodes[node].get('func_beg')}")
        # print(f"{'dir_call'} {angr.nodes[node].get('dir_call')}")
        # print(f"{'indir_call'} {angr.nodes[node].get('indir_call')}")
        # print(f"{'cond_jump'} {angr.nodes[node].get('cond_jump')}")
        # print(f"{'dir_jump'} {angr.nodes[node].get('dir_jump')}")
        # print(f"{'indir_jump'} {angr.nodes[node].get('indir_jump')}")
        # print(f"{'has_return'} {angr.nodes[node].get('has_return')}")
        # print('\n')

    # print(G)


if __name__ == '__main__':
    run()
