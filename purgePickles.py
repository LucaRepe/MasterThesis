import re
import pickle
import networkx as nx


def purge(graph_purged):
    list_sorted = sorted(list(graph_purged.nodes))[1:]
    for node in sorted(list(graph_purged.nodes)):
        if list_sorted:
            if graph_purged.nodes[node]['has_return']:
                list_sorted.pop(0)
                for edge, attr in zip(graph_purged.nodes[node]['edges'], graph_purged.nodes[node]['edge_attr']):
                    if attr == 'Call':
                        graph_purged.add_edge(node, edge, color='r')
                    if attr == 'Fallthrough':
                        graph_purged.add_edge(node, edge, color='g')
                    if attr == 'Jump':
                        graph_purged.add_edge(node, edge, color='b')
            elif graph_purged.nodes[node]['dir_jump'] or graph_purged.nodes[node]['indir_jump']:
                if not graph_purged.nodes[node]['cond_jump']:
                    list_sorted.pop(0)
                    for edge, attr in zip(graph_purged.nodes[node]['edges'], graph_purged.nodes[node]['edge_attr']):
                        if attr == 'Call':
                            graph_purged.add_edge(node, edge, color='r')
                        if attr == 'Fallthrough':
                            graph_purged.add_edge(node, edge, color='g')
                        if attr == 'Jump':
                            graph_purged.add_edge(node, edge, color='b')
                else:
                    for edge, attr in zip(graph_purged.nodes[node]['edges'], graph_purged.nodes[node]['edge_attr']):
                        if attr == 'Call':
                            graph_purged.add_edge(node, edge, color='r')
                        if attr == 'Fallthrough':
                            graph_purged.add_edge(node, edge, color='g')
                        if attr == 'Jump':
                            graph_purged.add_edge(node, edge, color='b')
            else:
                for edge, attr in zip(graph_purged.nodes[node]['edges'], graph_purged.nodes[node]['edge_attr']):
                    if attr == 'Call':
                        graph_purged.add_edge(node, edge, color='r')
                    if attr == 'Fallthrough':
                        graph_purged.add_edge(node, edge, color='g')
                    if attr == 'Jump':
                        graph_purged.add_edge(node, edge, color='b')
    return graph_purged


def run():
    ghidra = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/ghidra.p", "rb"))
    radare = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/radare.p", "rb"))
    angr = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/angr.p", "rb"))
    ida = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/ida.p", "rb"))

    print(ida)

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

    ghidra_purged = purge(ghidra_purged)

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

    radare_purged = purge(radare_purged)

    angr_purged = nx.DiGraph()
    for addr in ground_truth:
        for node in angr:
            if addr == node:
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

    angr_purged = purge(angr_purged)

    ida_purged = nx.DiGraph()
    for addr in ground_truth:
        for node in ida:
            if addr == node:
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

    ida_purged = purge(ida_purged)

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

    pickle.dump(ghidra_purged, open("/home/luca/Scrivania/MasterThesis/Pickles/ghidra_purged.p", "wb"))
    pickle.dump(radare_purged, open("/home/luca/Scrivania/MasterThesis/Pickles/radare_purged.p", "wb"))
    pickle.dump(angr_purged, open("/home/luca/Scrivania/MasterThesis/Pickles/angr_purged.p", "wb"))
    pickle.dump(ida_purged, open("/home/luca/Scrivania/MasterThesis/Pickles/ida_purged.p", "wb"))


if __name__ == '__main__':
    run()
