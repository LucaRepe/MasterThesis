import re
import pickle
import os
import json


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


def get_bbl_file(pickles_folder, files):
    bbl_file = [f for f in files if f.endswith(".bbl")]
    file_path = os.path.join(pickles_folder, bbl_file[0])
    bbl_string = open(file_path).read()
    pin_addrs_list = re.findall('.{1,8}', bbl_string)
    return pin_addrs_list


def get_base_address(pickles_folder, files):
    json_file = [f for f in files if f.endswith(".json")]
    file_path = os.path.join(pickles_folder, json_file[0])
    with open(file_path) as f:
        lines = f.readlines()
        data = json.loads(lines[2])
        return data.get('Desc')


def pin_trace_creation(pickles_folder):
    files = os.listdir(pickles_folder)
    base_address = get_base_address(pickles_folder, files)
    pin_addrs_list = get_bbl_file(pickles_folder, files)
    pin_trace = set()
    for addr in pin_addrs_list:
        real_address = int(addr, 16) - int(base_address, 16)
        if real_address < 0:
            continue
        pin_trace.add(hex(real_address))
    return pin_trace


def main():
    pickles_folder = "Pickles/Complete/"
    assert pickles_folder
    angr = pickle.load(open(pickles_folder + "angr.p", "rb"))
    ghidra = pickle.load(open(pickles_folder + "ghidra.p", "rb"))
    ida = pickle.load(open(pickles_folder + "ida.p", "rb"))
    radare = pickle.load(open(pickles_folder + "radare.p", "rb"))

    pin_trace = pin_trace_creation(pickles_folder)
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

    pickle.dump(angr_purged, open(pickles_folder + "angr_purged.p", "wb"))
    pickle.dump(ghidra_purged, open(pickles_folder + "ghidra_purged.p", "wb"))
    pickle.dump(ida_purged, open(pickles_folder + "ida_purged.p", "wb"))
    pickle.dump(radare_purged, open(pickles_folder + "radare_purged.p", "wb"))

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


if __name__ == '__main__':
    main()
