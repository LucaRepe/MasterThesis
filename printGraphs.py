import pickle
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D


def print_graph(graph, legend_elements):
    colors = nx.get_edge_attributes(graph, 'color').values()
    nx.draw_networkx(graph, edge_color=colors, arrows=True)
    plt.legend(handles=legend_elements, loc='upper right')
    plt.show()


def main():
    pickles_folder = "Pickles/Complete/"
    assert pickles_folder
    angr = pickle.load(open(pickles_folder + "angr_diff.p", "rb"))
    ghidra = pickle.load(open(pickles_folder + "ghidra_diff.p", "rb"))
    ida = pickle.load(open(pickles_folder + "ida_diff.p", "rb"))
    radare = pickle.load(open(pickles_folder + "radare_diff.p", "rb"))

    legend_elements = [
        Line2D([0], [0], marker='_', color='r', label='Call', markerfacecolor='r', markersize=10),
        Line2D([0], [0], marker='_', color='g', label='Fallthrough', markerfacecolor='g', markersize=10),
        Line2D([0], [0], marker='_', color='b', label='Jump', markerfacecolor='b', markersize=10)
    ]

    for graph in [angr, ghidra, ida, radare]:
        print_graph(graph, legend_elements)


if __name__ == '__main__':
    main()
