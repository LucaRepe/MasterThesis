import re
import pickle
import json
import os
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D


def diff_graph_construction(agreement, purged):
    graph_diff = nx.DiGraph()
    graph_diff.add_edges_from(purged.edges() - agreement.edges())
    for node in graph_diff.copy().nodes():
        graph_diff.add_node(node, **purged.nodes[node])
    for u, v, data in ((u, v, d) for u, v, d in purged.edges(data=True) if (u, v) not in agreement.edges()):
        graph_diff.add_edge(u, v, **data)
    return graph_diff


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

    angr_purged = purge(angr, int_max, int_min)
    ghidra_purged = purge(ghidra, int_max, int_min)
    ida_purged = purge(ida, int_max, int_min)
    radare_purged = purge(radare, int_max, int_min)    

    common_edges = set(angr_purged.edges()).intersection(set(ghidra_purged.edges()), set(ida_purged.edges()), set(radare_purged.edges()))
    for edge in common_edges.copy():
        node1, node2 = edge
        if not angr_purged.nodes[node1]["unique_hash_identifier"] == ghidra_purged.nodes[node1]["unique_hash_identifier"] == \
            ida_purged.nodes[node1]["unique_hash_identifier"] ==  radare_purged.nodes[node1]["unique_hash_identifier"]:
                print(edge)
                common_edges.remove(edge)
    
    agreement_graph = nx.DiGraph(common_edges)
    angr_diff = diff_graph_construction(agreement_graph, angr_purged)
    ghidra_diff = diff_graph_construction(agreement_graph, ghidra_purged)
    ida_diff = diff_graph_construction(agreement_graph, ida_purged)
    radare_diff = diff_graph_construction(agreement_graph, radare_purged)

    print(f"{'agreement'} {agreement_graph}")
    print(f"{'angr_diff'} {angr_diff}")
    print(f"{'ghidra_diff'} {ghidra_diff}")
    print(f"{'ida_diff'} {ida_diff}")
    print(f"{'radare_diff'} {radare_diff}")
    print('\n') 

    pickle.dump(agreement_graph, open(pickles_folder + "agreement.p", "wb"))
    pickle.dump(angr_diff, open(pickles_folder + "angr_diff.p", "wb"))
    pickle.dump(ghidra_diff, open(pickles_folder + "ghidra_diff.p", "wb"))
    pickle.dump(ida_diff, open(pickles_folder + "ida_diff.p", "wb"))
    pickle.dump(radare_diff, open(pickles_folder + "radare_diff.p", "wb"))
    
    common_edges_maj = set()
    common_edges_maj |= ((set(angr_purged.edges) & set(ghidra_purged.edges) & set(ida_purged.edges)) |
                 (set(angr_purged.edges) & set(ghidra_purged.edges) & set(radare_purged.edges)) |
                 (set(angr_purged.edges) & set(ida_purged.edges) & set(radare_purged.edges)) |
                 (set(ghidra_purged.edges) & set(ida_purged.edges) & set(radare_purged.edges)))

    majority_graph = nx.DiGraph(common_edges_maj)
    angr_diff_maj = diff_graph_construction(majority_graph, angr_purged)
    ghidra_diff_maj = diff_graph_construction(majority_graph, ghidra_purged)
    ida_diff_maj = diff_graph_construction(majority_graph, ida_purged)
    radare_diff_maj = diff_graph_construction(majority_graph, radare_purged)

    print(f"{'majority'} {majority_graph}")
    print(f"{'angr_diff_maj'} {angr_diff_maj}")
    print(f"{'ghidra_diff_maj'} {ghidra_diff_maj}")
    print(f"{'ida_diff_maj'} {ida_diff_maj}")
    print(f"{'radare_diff_maj'} {radare_diff_maj}")      

    pickle.dump(majority_graph, open(pickles_folder + "majority.p", "wb"))
    pickle.dump(angr_diff_maj, open(pickles_folder + "angr_diff_maj.p", "wb"))
    pickle.dump(ghidra_diff_maj, open(pickles_folder + "ghidra_diff_maj.p", "wb"))
    pickle.dump(ida_diff_maj, open(pickles_folder + "ida_diff_maj.p", "wb"))
    pickle.dump(radare_diff_maj, open(pickles_folder + "radare_diff_maj.p", "wb"))
    
    # nx.draw_networkx(agreement_graph, with_labels=True)
    # plt.show()


if __name__ == '__main__':
    main()
