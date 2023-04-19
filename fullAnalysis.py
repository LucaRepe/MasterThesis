import pickle
import re
import networkx as nx


def print_attributes(name, attributes):
    print(f"{name}")
    print(f"{'nodes_count'} {attributes['nodes_count']}")
    print(f"{'edges_count'} {attributes['edges_count']}")
    print(f"{'func_beg_count'} {attributes['func_beg_count']}")
    print(f"{'dir_call_count'} {attributes['dir_call_count']}")
    print(f"{'indir_call_count'} {attributes['indir_call_count']}")
    print(f"{'cond_jump_count'} {attributes['cond_jump_count']}")
    print(f"{'dir_jump_count'} {attributes['dir_jump_count']}")
    print(f"{'indir_jump_count'} {attributes['indir_jump_count']}")
    print(f"{'ret_count'} {attributes['ret_count']}" '\n')


def count_attributes(name, graph_purged):
    attributes = {
        "nodes_count": 0,
        "edges_count": 0,
        "func_beg_count": 0,
        "dir_call_count": 0,
        "indir_call_count": 0,
        "cond_jump_count": 0,
        "dir_jump_count": 0,
        "indir_jump_count": 0,
        "ret_count": 0
    }

    attributes['nodes_count'] = len(graph_purged.nodes())
    attributes['edges_count'] = len(graph_purged.edges())
    for node in graph_purged.nodes:
        if graph_purged.nodes[node].get('func_beg'):
            attributes['func_beg_count'] +=1
        if graph_purged.nodes[node].get('dir_call'):
            attributes['dir_call_count'] +=1
        if graph_purged.nodes[node].get('indir_call'):
            attributes['indir_call_count'] +=1
        if graph_purged.nodes[node].get('cond_jump'):
            attributes['cond_jump_count'] +=1
        if graph_purged.nodes[node].get('dir_jump'):
            attributes['dir_jump_count'] +=1
        if graph_purged.nodes[node].get('indir_jump'):
            attributes['indir_jump_count'] +=1
        if graph_purged.nodes[node].get('has_return'):
            attributes['ret_count'] +=1
    print_attributes(name, attributes)
    return attributes


def return_eq(node1, node2):
    return node1.get('unique_hash_identifier')==node2.get('unique_hash_identifier')


def jaccard(s1, s2):
    return float(len(s1.intersection(s2)) / len(s1.union(s2)))

def set_purged_edges(graph):
    set_edges_purged = set ()
    for edge in graph.edges():
        set_edges_purged.update(edge)
    return set_edges_purged


def set_purged_addresses(graph):
    set_addr_purged = set()
    for node in graph.nodes():
        if graph.nodes[node].get('addr') is not None:
            set_addr_purged.update(graph.nodes[node].get('addr'))
    return set_addr_purged


def set_original_addresses(graph):
    set_addr = set()
    for node in graph:
        if graph.nodes[node].get('addr') is not None:
            set_addr.update(graph.nodes[node].get('addr'))
    return set_addr


def purge(graph, max_addr, min_addr):
    for node in graph.copy():
        if node == 'UnresolvableCallTarget' or node == 'UnresolvableJumpTarget':
            graph.remove_node(node)
        elif int(node,16) < min_addr or int(node,16) > max_addr:
            graph.remove_node(node)
    return graph


def main():
    angr = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/angr.p", "rb"))
    ghidra = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/ghidra.p", "rb"))
    ida = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/ida.p", "rb"))
    radare = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/radare.p", "rb"))

    base_address = 0x400000
    bbl_string = open('/home/luca/Scrivania/MasterThesis/Lab15-01.bbl').read()
    bbl_list = re.findall('.{1,8}', bbl_string)
    pin_trace = set()
    for addr in bbl_list:
        real_address = int(addr, 16) - base_address
        if real_address < 0:
            continue
        pin_trace.add(hex(real_address))

    min_pin_addr = min(pin_trace)
    max_pin_addr = max(pin_trace)
    int_min = int(min_pin_addr,16)
    int_max = int(max_pin_addr,16)

    set_addr_angr = set_original_addresses(angr)
    angr_purged = purge(angr, int_max, int_min)

    set_addr_ghidra = set_original_addresses(ghidra)
    ghidra_purged = purge(ghidra, int_max, int_min)

    set_addr_ida = set_original_addresses(ida)
    ida_purged = purge(ida, int_max, int_min)

    set_addr_radare = set_original_addresses(radare)
    radare_purged = purge(radare, int_max, int_min)

    pickle.dump(angr_purged, open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/angr_purged.p", "wb"))
    pickle.dump(ghidra_purged, open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/ghidra_purged.p", "wb"))
    pickle.dump(ida_purged, open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/ida_purged.p", "wb"))
    pickle.dump(radare_purged, open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/radare_purged.p", "wb"))

    count_attributes("Angr", angr_purged)
    count_attributes("Ghidra", ghidra_purged)
    count_attributes("Ida", ida_purged)
    count_attributes("Radare", radare_purged)

    print(f'{"--- Pin subset check on original addresses ---"}')
    print('\n')
    print(f'{"Pin trace addresses:"} {len(pin_trace)}')
    print(f'{"Angr is"} {pin_trace.issubset(set_addr_angr)} {"- addresses:"} {len(set_addr_angr)}')
    print(f'{"Ghidra is"} {pin_trace.issubset(set_addr_ghidra)} {"- addresses:"} {len(set_addr_ghidra)}')
    print(f'{"Ida is"} {pin_trace.issubset(set_addr_ida)} {"- addresses:"} {len(set_addr_ida)}')
    print(f'{"Radare is"} {pin_trace.issubset(set_addr_radare)} {"- addresses:"} {len(set_addr_radare)}')
    print('\n')

    set_nodes_angr_purged = set(angr_purged.nodes())
    set_addr_angr_purged = set_purged_addresses(angr_purged)
    set_edges_angr_purged = set_purged_edges(angr_purged)

    set_nodes_ghidra_purged = set(ghidra_purged.nodes())
    set_addr_ghidra_purged = set_purged_addresses(ghidra_purged)
    set_edges_ghidra_purged = set_purged_edges(ghidra_purged)

    set_nodes_ida_purged = set(ida_purged.nodes())
    set_addr_ida_purged = set_purged_addresses(ida_purged)
    set_edges_ida_purged = set_purged_edges(ida_purged)

    set_nodes_radare_purged = set(radare_purged.nodes())
    set_addr_radare_purged = set_purged_addresses(radare_purged)
    set_edges_radare_purged = set_purged_edges(radare_purged)

    print(f'{"Addresses present on Pin trace that are missing in Angr:"} {len(pin_trace.difference(set_addr_angr_purged))}')
    if len(pin_trace.difference(set_addr_angr_purged)): print(pin_trace.difference(set_addr_angr_purged))

    print(f'{"Addresses present on Pin trace that are missing in Ghidra:"} {len(pin_trace.difference(set_addr_ghidra_purged))}')
    if len(pin_trace.difference(set_addr_ghidra_purged)): print(pin_trace.difference(set_addr_ghidra_purged))

    print(f'{"Addresses present on Pin trace that are missing in Ida:"} {len(pin_trace.difference(set_addr_ida_purged))}')
    if len(pin_trace.difference(set_addr_ida_purged)): print(pin_trace.difference(set_addr_ida_purged))

    print(f'{"Addresses present on Pin trace that are missing in Radare:"} {len(pin_trace.difference(set_addr_radare_purged))}')
    if len(pin_trace.difference(set_addr_radare_purged)): print(pin_trace.difference(set_addr_radare_purged))
    print('\n')
    
    print(f'{"--- Jaccard similarity check on purged addresses ---"}')
    print('\n')
    print(f'{"Angr"} {jaccard(pin_trace, set_addr_angr_purged)}')
    print(f'{"Ghidra"} {jaccard(pin_trace, set_addr_ghidra_purged)}')
    print(f'{"Ida"} {jaccard(pin_trace, set_addr_ida_purged)}')
    print(f'{"Radare"} {jaccard(pin_trace, set_addr_radare_purged)}')
    print('\n')

    print(f'{"--- Jaccard similarity check on nodes ---"}')
    print('\n')
    print(f'{"Angr vs Ghidra"} {jaccard(set_nodes_angr_purged, set_nodes_ghidra_purged)}')
    print(f'{"Angr vs Radare"} {jaccard(set_nodes_angr_purged, set_nodes_radare_purged)}')
    print(f'{"Angr vs Ida"} {jaccard(set_nodes_angr_purged, set_nodes_ida_purged)}')
    print('\n')

    print(f'{"Ghidra vs Radare"} {jaccard(set_nodes_ghidra_purged, set_nodes_radare_purged)}')
    print(f'{"Ghidra vs Angr"} {jaccard(set_nodes_ghidra_purged, set_nodes_angr_purged)}')
    print(f'{"Ghidra vs Ida"} {jaccard(set_nodes_ghidra_purged, set_nodes_ida_purged)}')
    print('\n')

    print(f'{"Ida vs Ghidra"} {jaccard(set_nodes_ida_purged, set_nodes_ghidra_purged)}')
    print(f'{"Ida vs Angr"} {jaccard(set_nodes_ida_purged, set_nodes_angr_purged)}')
    print(f'{"Ida vs Radare"} {jaccard(set_nodes_ida_purged, set_nodes_radare_purged)}')
    print('\n')

    print(f'{"Radare vs Ghidra"} {jaccard(set_nodes_radare_purged, set_nodes_ghidra_purged)}')
    print(f'{"Radare vs Angr"} {jaccard(set_nodes_radare_purged, set_nodes_angr_purged)}')
    print(f'{"Radare vs Ida"} {jaccard(set_nodes_radare_purged, set_nodes_ida_purged)}')
    print('\n')

    print(f'{"--- Jaccard similarity check on edges ---"}')
    print('\n')
    print(f'{"Angr vs Ghidra"} {jaccard(set_edges_angr_purged, set_edges_ghidra_purged)}')
    print(f'{"Angr vs Radare"} {jaccard(set_edges_angr_purged, set_edges_radare_purged)}')
    print(f'{"Angr vs Ida"} {jaccard(set_edges_angr_purged, set_edges_ida_purged)}')
    print('\n')

    print(f'{"Ghidra vs Radare"} {jaccard(set_edges_ghidra_purged, set_edges_radare_purged)}')
    print(f'{"Ghidra vs Angr"} {jaccard(set_edges_ghidra_purged, set_edges_angr_purged)}')
    print(f'{"Ghidra vs Ida"} {jaccard(set_edges_ghidra_purged, set_edges_ida_purged)}')
    print('\n')

    print(f'{"Ida vs Ghidra"} {jaccard(set_edges_ida_purged, set_edges_ghidra_purged)}')
    print(f'{"Ida vs Angr"} {jaccard(set_edges_ida_purged, set_edges_angr_purged)}')
    print(f'{"Ida vs Radare"} {jaccard(set_edges_ida_purged, set_edges_radare_purged)}')
    print('\n')

    print(f'{"Radare vs Ghidra"} {jaccard(set_edges_radare_purged, set_edges_ghidra_purged)}')
    print(f'{"Radare vs Angr"} {jaccard(set_edges_radare_purged, set_edges_angr_purged)}')
    print(f'{"Radare vs Ida"} {jaccard(set_edges_radare_purged, set_edges_ida_purged)}')
    print('\n')

    angr_purged = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/angr_diff_maj.p", "rb"))
    ghidra_purged = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/ghidra_diff_maj.p", "rb"))
    ida_purged = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/ida_diff_maj.p", "rb"))
    radare_purged = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/radare_diff_maj.p", "rb"))

    print(f'{"--- Graph edit distance check ---"}')
    print('\n')
    print(f'{"Ghidra vs radare"} {nx.graph_edit_distance(ghidra_purged, radare_purged, node_match=return_eq)}')
    print(f'{"Ghidra vs angr"} {nx.graph_edit_distance(ghidra_purged, angr_purged, node_match=return_eq)}')
    print(f'{"Ghidra vs ida"} {nx.graph_edit_distance(ghidra_purged, ida_purged, node_match=return_eq)}')
    print('\n')
 
    print(f'{"Radare vs ghidra"} {nx.graph_edit_distance(radare_purged, ghidra_purged, node_match=return_eq)}')
    print(f'{"Radare vs angr"} {nx.graph_edit_distance(radare_purged, angr_purged, node_match=return_eq)}')
    print(f'{"Radare vs ida"} {nx.graph_edit_distance(radare_purged, ida_purged, node_match=return_eq)}')
    print('\n')
 
    print(f'{"Angr vs ghidra"} {nx.graph_edit_distance(angr_purged, ghidra_purged, node_match=return_eq)}')
    print(f'{"Angr vs radare"} {nx.graph_edit_distance(angr_purged, radare_purged, node_match=return_eq)}')
    print(f'{"Angr vs ida"} {nx.graph_edit_distance(angr_purged, ida_purged, node_match=return_eq)}')
    print('\n')
 
    print(f'{"Ida vs ghidra"} {nx.graph_edit_distance(ida_purged, ghidra_purged, node_match=return_eq)}')
    print(f'{"Ida vs radare"} {nx.graph_edit_distance(ida_purged, radare_purged, node_match=return_eq)}')
    print(f'{"Ida vs angr"} {nx.graph_edit_distance(ida_purged, angr_purged, node_match=return_eq)}')
    print('\n')


if __name__ == '__main__':
    main()