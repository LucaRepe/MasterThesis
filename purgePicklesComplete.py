import re
import pickle

def purge(graph, max_addr, min_addr):
    for node in graph.copy():
        if node == 'UnresolvableCallTarget' or node == 'UnresolvableJumpTarget':
            graph.remove_node(node)
        elif int(node,16) < min_addr or int(node,16) > max_addr:
            graph.remove_node(node)
    return graph


def jaccard(s1, s2):
    return float(len(s1.intersection(s2)) / len(s1.union(s2)))


def run():
    ghidra = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/ghidra.p", "rb"))
    radare = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/radare.p", "rb"))
    angr = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/angr.p", "rb"))
    ida = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/ida.p", "rb"))

    base_address = 0x2b0000
    bbl_string = open('/home/luca/Scrivania/MasterThesis/mainTechVS.bbl').read()
    bbl_list = re.findall('.{1,8}', bbl_string)
    pin_trace = set()
    for addr in bbl_list:
        real_address = int(addr, 16) - base_address
        if real_address < 0:
            continue
        pin_trace.add(hex(real_address))

    # min_pin_addr = min(pin_trace)
    # max_pin_addr = max(pin_trace)
    # int_min = int(min_pin_addr,16)
    # int_max = int(max_pin_addr,16)
    int_min = 0x11d60
    int_max = 0x11e5e
    ghidra_purged = ghidra.copy()
    set_addr_ghidra = set()
    for node in ghidra:
        if ghidra.nodes[node].get('addr') is not None:
            set_addr_ghidra.update(ghidra.nodes[node].get('addr'))

    ghidra_purged = purge(ghidra_purged, int_max, int_min)

    radare_purged = radare.copy()
    set_addr_radare = set()
    for node in radare:
        if radare.nodes[node].get('addr') is not None:
            set_addr_radare.update(radare.nodes[node].get('addr'))

    radare_purged = purge(radare_purged, int_max, int_min)
    

    angr_purged = angr.copy()
    set_addr_angr = set()
    for node in angr:
        if angr.nodes[node].get('addr') is not None:
                set_addr_angr.update(angr.nodes[node].get('addr'))

    angr_purged = purge(angr_purged, int_max, int_min)

    ida_purged = ida.copy()
    set_addr_ida = set()
    for node in ida:
        if ida.nodes[node].get('addr') is not None:
            set_addr_ida.update(ida.nodes[node].get('addr'))

    ida_purged = purge(ida_purged, int_max, int_min)

    pickle.dump(ghidra_purged, open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/ghidra_purged.p", "wb"))
    pickle.dump(radare_purged, open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/radare_purged.p", "wb"))
    pickle.dump(angr_purged, open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/angr_purged.p", "wb"))
    pickle.dump(ida_purged, open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/ida_purged.p", "wb"))

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

    print(f'{"Addresses present on Pin that are missing in Ghidra: "} {len(pin_trace.difference(set_addr_ghidra_purged))}')
    # print(pin_trace.difference(set_addr_ghidra_purged))
    print('\n')

    print(f'{"Addresses present on Pin that are missing in Radare: "} {len(pin_trace.difference(set_addr_radare_purged))}')
    # print(pin_trace.difference(set_addr_radare_purged))
    print('\n')

    print(f'{"Addresses present on Pin that are missing in Angr: "} {len(pin_trace.difference(set_addr_angr_purged))}')
    # print(pin_trace.difference(set_addr_angr_purged))
    print('\n')

    print(f'{"Addresses present on Pin that are missing in Ida: "} {len(pin_trace.difference(set_addr_ida_purged))}')
    # print(pin_trace.difference(set_addr_ida_purged))
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
