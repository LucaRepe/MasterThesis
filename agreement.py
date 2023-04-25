import re
import pickle
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

    angr_purged = purge(angr, int_max, int_min)
    ghidra_purged = purge(ghidra, int_max, int_min)
    ida_purged = purge(ida, int_max, int_min)
    radare_purged = purge(radare, int_max, int_min)    

    common_edges = set(angr_purged.edges()).intersection(set(ghidra_purged.edges()), set(ida_purged.edges()), set(radare_purged.edges()))
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

    pickle.dump(agreement_graph, open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/agreement.p", "wb"))
    pickle.dump(angr_diff, open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/angr_diff.p", "wb"))
    pickle.dump(ghidra_diff, open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/ghidra_diff.p", "wb"))
    pickle.dump(ida_diff, open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/ida_diff.p", "wb"))
    pickle.dump(radare_diff, open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/radare_diff.p", "wb"))
    
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

    pickle.dump(majority_graph, open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/majority.p", "wb"))
    pickle.dump(angr_diff_maj, open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/angr_diff_maj.p", "wb"))
    pickle.dump(ghidra_diff_maj, open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/ghidra_diff_maj.p", "wb"))
    pickle.dump(ida_diff_maj, open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/ida_diff_maj.p", "wb"))
    pickle.dump(radare_diff_maj, open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/radare_diff_maj.p", "wb"))
    
    nx.draw_networkx(agreement_graph, with_labels=True)
    plt.show()


if __name__ == '__main__':
    main()
