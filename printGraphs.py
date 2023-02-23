import re
import pickle
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D

def purge(graph, max_addr, min_addr):
    for node in graph.copy():
        if node == 'UnresolvableCallTarget' or node == 'UnresolvableJumpTarget':
            continue
        if int(node,16) < min_addr or int(node,16) > max_addr:
            graph.remove_node(node)
    return graph


def run():
    ghidra = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/ghidra.p", "rb"))
    radare = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/radare.p", "rb"))
    angr = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/angr.p", "rb"))
    ida = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/ida.p", "rb"))
    
    int_min = 0x1410
    int_max = 0x1463

    ghidra_purged = ghidra.copy()
    ghidra_purged = purge(ghidra_purged, int_max, int_min)

    radare_purged = radare.copy()
    radare_purged = purge(radare_purged, int_max, int_min)

    angr_purged = angr.copy()
    angr_purged = purge(angr_purged, int_max, int_min)

    ida_purged = ida.copy()
    ida_purged = purge(ida_purged, int_max, int_min)

    pickle.dump(ghidra_purged, open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/ghidra_purged.p", "wb"))
    pickle.dump(radare_purged, open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/radare_purged.p", "wb"))
    pickle.dump(angr_purged, open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/angr_purged.p", "wb"))
    pickle.dump(ida_purged, open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/ida_purged.p", "wb"))

    legend_elements = [
        Line2D([0], [0], marker='_', color='r', label='Call', markerfacecolor='r', markersize=10),
        Line2D([0], [0], marker='_', color='g', label='Fallthrough', markerfacecolor='g', markersize=10),
        Line2D([0], [0], marker='_', color='b', label='Jump', markerfacecolor='b', markersize=10)
    ]

    colors = nx.get_edge_attributes(ghidra_purged, 'color').values()
    nx.draw_networkx(ghidra_purged, edge_color=colors, arrows=True)
    plt.legend(handles=legend_elements, loc='upper right')
    plt.show()



if __name__ == '__main__':
    run()
