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


def jaccard(s1, s2):
    return float(len(s1.intersection(s2)) / len(s1.union(s2)))


def run():
    ghidra = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/ghidra.p", "rb"))
    radare = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/radare.p", "rb"))
    angr = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/angr.p", "rb"))
    ida = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/ida.p", "rb"))
        
        
    base_address = 0x5e0000
    bbl_string = open('/home/luca/Scrivania/MasterThesis/testmainMinGW.bbl').read()
    bbl_list = re.findall('.{1,8}', bbl_string)
    pin_trace = set()
    for addr in bbl_list:
        real_address = int(addr, 16) - base_address
        if real_address < 0:
            continue
        pin_trace.add(hex(real_address))

    ghidra_purged = nx.DiGraph()
    set_addr_ghidra = set()
    set_nodes_ghidra = set()
    for addr in pin_trace:
        for node in ghidra:
            if ghidra.nodes[node].get('addr') is not None:
                set_addr_ghidra.update(ghidra.nodes[node].get('addr'))
            set_nodes_ghidra.add(node)
            if addr == node:
                ghidra_purged.add_node(node, instr=ghidra.nodes[node].get('instr'),
                                       bytes=ghidra.nodes[node].get('bytes'), addr=ghidra.nodes[node].get('addr'),
                                       edges=ghidra.nodes[node].get('edges'),
                                       edge_attr=ghidra.nodes[node].get('edge_attr'),
                                       func_beg=ghidra.nodes[node].get('func_beg'), 
                                       dir_call=ghidra.nodes[node].get('dir_call'),
                                       indir_call=ghidra.nodes[node].get('indir_call'), 
                                       cond_jump=ghidra.nodes[node].get('cond_jump'),
                                       dir_jump=ghidra.nodes[node].get('dir_jump'), 
                                       indir_jump=ghidra.nodes[node].get('indir_jump'),
                                       has_return=ghidra.nodes[node].get('has_return'), 
                                       unique_hash_identifier=ghidra.nodes[node].get('unique_hash_identifier'))

    
    ghidra_purged = purge(ghidra_purged)


    radare_purged = nx.DiGraph()
    set_addr_radare = set()
    set_nodes_radare = set()
    for addr in pin_trace:
        for node in radare:
            if radare.nodes[node].get('addr') is not None:
                set_addr_radare.update(radare.nodes[node].get('addr'))
            set_nodes_radare.add(node)
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
    set_addr_angr = set()
    set_nodes_angr = set()
    for addr in pin_trace:
        for node in angr:
            if angr.nodes[node].get('addr') is not None:
                set_addr_angr.update(angr.nodes[node].get('addr'))
            set_nodes_angr.add(node)
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
    set_addr_ida = set()
    set_nodes_ida = set()
    for addr in pin_trace:
        for node in ida:
            if ida.nodes[node].get('addr') is not None:
                set_addr_ida.update(ida.nodes[node].get('addr'))
            set_nodes_ida.add(node)
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

    pickle.dump(ghidra_purged, open("/home/luca/Scrivania/MasterThesis/Pickles/ghidra_purged.p", "wb"))
    pickle.dump(radare_purged, open("/home/luca/Scrivania/MasterThesis/Pickles/radare_purged.p", "wb"))
    pickle.dump(angr_purged, open("/home/luca/Scrivania/MasterThesis/Pickles/angr_purged.p", "wb"))
    pickle.dump(ida_purged, open("/home/luca/Scrivania/MasterThesis/Pickles/ida_purged.p", "wb"))

    print(f'{"--- Pin subset check on original addresses ---"}')
    print('\n')
    print(f'{"Ghidra is"} {pin_trace.issubset(set_addr_ghidra)} {"- addresses:"} {len(set_addr_ghidra)}')
    print(f'{"Radare is"} {pin_trace.issubset(set_addr_radare)} {"- addresses:"} {len(set_addr_radare)}')
    print(f'{"Angr is"} {pin_trace.issubset(set_addr_angr)} {"- addresses:"} {len(set_addr_angr)}')
    print(f'{"Ida is"} {pin_trace.issubset(set_addr_ida)} {"- addresses:"} {len(set_addr_ida)}')
    print('\n')

    set_nodes_ghidra_purged = set()
    set_addr_ghidra_purged = set()
    set_edges_ghidra_purged = set()
    for node in ghidra_purged:
        set_nodes_ghidra_purged.add(node)
        if ghidra_purged.nodes[node].get('addr') is not None:
            set_addr_ghidra_purged.update(ghidra_purged.nodes[node].get('addr'))
        if ghidra_purged.nodes[node].get('edges') is not None:
            set_edges_ghidra_purged.update(ghidra_purged.nodes[node].get('edges'))
        
    set_nodes_radare_purged = set()
    set_addr_radare_purged = set()
    set_edges_radare_purged = set()
    for node in radare_purged:
        set_nodes_radare_purged.add(node)
        if radare_purged.nodes[node].get('addr') is not None:
            set_addr_radare_purged.update(radare_purged.nodes[node].get('addr'))
        if radare_purged.nodes[node].get('edges') is not None:
            set_edges_radare_purged.update(radare_purged.nodes[node].get('edges'))

    set_nodes_angr_purged = set()
    set_addr_angr_purged = set()
    set_edges_angr_purged = set()
    for node in angr_purged:
        set_nodes_angr_purged.add(node)
        if angr_purged.nodes[node].get('addr') is not None:
            set_addr_angr_purged.update(angr_purged.nodes[node].get('addr'))
        if angr_purged.nodes[node].get('edges') is not None:
            set_edges_angr_purged.update(angr_purged.nodes[node].get('edges'))

    set_nodes_ida_purged = set()
    set_addr_ida_purged = set()
    set_edges_ida_purged = set()
    for node in ida_purged:
        set_nodes_ida_purged.add(node)
        if ida_purged.nodes[node].get('addr') is not None:
            set_addr_ida_purged.update(ida_purged.nodes[node].get('addr'))
        if ida_purged.nodes[node].get('edges') is not None:
            set_edges_ida_purged.update(ida_purged.nodes[node].get('edges'))

    print(f'{"--- Jaccard similarity check on purged addresses ---"}')
    print('\n')
    print(f'{"Ghidra"} {jaccard(pin_trace, set_addr_ghidra_purged)}')
    print(f'{"Radare"} {jaccard(pin_trace, set_addr_radare_purged)}')
    print(f'{"Angr"} {jaccard(pin_trace, set_addr_angr_purged)}')
    print(f'{"Ida"} {jaccard(pin_trace, set_addr_ida_purged)}')
    print('\n')

    print(f'{"Addresses present on Pin that are missing in Ghidra: "} {len(pin_trace.difference(set_addr_ghidra))}')
    print(pin_trace.difference(set_addr_ghidra))
    print('\n')

    print(f'{"Addresses present on Pin that are missing in Radare: "} {len(pin_trace.difference(set_addr_radare))}')
    print(pin_trace.difference(set_addr_radare))
    print('\n')

    print(f'{"Addresses present on Pin that are missing in Angr: "} {len(pin_trace.difference(set_addr_angr))}')
    print(pin_trace.difference(set_addr_angr))
    print('\n')

    print(f'{"Addresses present on Pin that are missing in Ida: "} {len(pin_trace.difference(set_addr_ida))}')
    print(pin_trace.difference(set_addr_ida))
    print('\n')

    print(f'{"--- Jaccard similarity check on nodes ---"}')
    print('\n')
    print(f'{"Ghidra vs Radare"} {jaccard(set_nodes_ghidra_purged, set_nodes_radare_purged)}')
    print(f'{"Ghidra vs Angr"} {jaccard(set_nodes_ghidra_purged, set_nodes_angr_purged)}')
    print(f'{"Ghidra vs Ida"} {jaccard(set_nodes_ghidra_purged, set_nodes_ida_purged)}')
    print('\n')

    print(f'{"Radare vs Ghidra"} {jaccard(set_nodes_radare_purged, set_nodes_ghidra_purged)}')
    print(f'{"Radare vs Angr"} {jaccard(set_nodes_radare_purged, set_nodes_angr_purged)}')
    print(f'{"Radare vs Ida"} {jaccard(set_nodes_radare_purged, set_nodes_ida_purged)}')
    print('\n')

    print(f'{"Angr vs Ghidra"} {jaccard(set_nodes_angr_purged, set_nodes_ghidra_purged)}')
    print(f'{"Angr vs Radare"} {jaccard(set_nodes_angr_purged, set_nodes_radare_purged)}')
    print(f'{"Angr vs Ida"} {jaccard(set_nodes_angr_purged, set_nodes_ida_purged)}')
    print('\n')

    print(f'{"Ida vs Ghidra"} {jaccard(set_nodes_ida_purged, set_nodes_ghidra_purged)}')
    print(f'{"Ida vs Angr"} {jaccard(set_nodes_ida_purged, set_nodes_angr_purged)}')
    print(f'{"Ida vs Radare"} {jaccard(set_nodes_ida_purged, set_nodes_radare_purged)}')
    print('\n')

    print(f'{"--- Jaccard similarity check on edges ---"}')
    print('\n')
    print(f'{"Ghidra vs Radare"} {jaccard(set_edges_ghidra_purged, set_edges_radare_purged)}')
    print(f'{"Ghidra vs Angr"} {jaccard(set_edges_ghidra_purged, set_edges_angr_purged)}')
    print(f'{"Ghidra vs Ida"} {jaccard(set_edges_ghidra_purged, set_edges_ida_purged)}')
    print('\n')

    print(f'{"Radare vs Ghidra"} {jaccard(set_edges_radare_purged, set_edges_ghidra_purged)}')
    print(f'{"Radare vs Angr"} {jaccard(set_edges_radare_purged, set_edges_angr_purged)}')
    print(f'{"Radare vs Ida"} {jaccard(set_edges_radare_purged, set_edges_ida_purged)}')
    print('\n')


    print(f'{"Angr vs Ghidra"} {jaccard(set_edges_angr_purged, set_edges_ghidra_purged)}')
    print(f'{"Angr vs Radare"} {jaccard(set_edges_angr_purged, set_edges_radare_purged)}')
    print(f'{"Angr vs Ida"} {jaccard(set_edges_angr_purged, set_edges_ida_purged)}')
    print('\n')


    print(f'{"Ida vs Ghidra"} {jaccard(set_edges_ida_purged, set_edges_ghidra_purged)}')
    print(f'{"Ida vs Angr"} {jaccard(set_edges_ida_purged, set_edges_angr_purged)}')
    print(f'{"Ida vs Radare"} {jaccard(set_edges_ida_purged, set_edges_radare_purged)}')
    print('\n')


if __name__ == '__main__':
    run()
