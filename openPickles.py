import pickle


def run():
    ghidra = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/ghidra.p", "rb"))
    radare = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/radare.p", "rb"))
    angr = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/angr.p", "rb"))
    ida = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/ida.p", "rb"))
    print(ghidra)
    print(radare)
    print(angr)

    G = radare.nodes() - ghidra.nodes()
    E = ghidra.edges() - radare.edges()
    print(G)
    print(E)


if __name__ == '__main__':
    run()
