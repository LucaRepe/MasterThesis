import pickle
import networkx as nx

def difference(S, R):
    DIF = nx.create_empty_copy(R)
    DIF.name = "Difference of (%s and %s)" % (S.name, R.name)
    if set(S) != set(R):
        raise nx.NetworkXError("Node sets of graphs is not equal")

    r_edges = set(R.edges_iter())
    s_edges = set(S.edges_iter())
    diff_edges = r_edges.symmetric_difference(s_edges)
    DIF.add_edges_from(diff_edges)

    return DIF

def run():
    radare = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/radare.p", "rb"))
    angr = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/angr.p", "rb"))
    ghidra = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/ghidra.p", "rb"))

    print(difference(ghidra, radare).edges())

if __name__ == '__main__':
    run()