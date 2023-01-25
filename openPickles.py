import pickle


def run():
    ghidra = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/ghidra.p", "rb"))
    radare = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/radare.p", "rb"))
    angr = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/angr.p", "rb"))
    ida = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/ida.p", "rb"))
    print(ghidra)
    print(radare)
    print(angr)
    print(ida)

    G = ida.nodes() - ghidra.nodes()
    # E = angr.edges() - ida.edges()

    for node in G:
        print(node)
        print(f"{'instr'} {ida.nodes[node].get('instr')}")
        print(f"{'edges'} {ida.nodes[node].get('edges')}")
        print(f"{'edge_attr'} {ida.nodes[node].get('edge_attr')}")
        print(f"{'func_beg'} {ida.nodes[node].get('func_beg')}")
        print(f"{'dir_call'} {ida.nodes[node].get('dir_call')}")
        print(f"{'indir_call'} {ida.nodes[node].get('indir_call')}")
        print(f"{'cond_jump'} {ida.nodes[node].get('cond_jump')}")
        print(f"{'dir_jump'} {ida.nodes[node].get('dir_jump')}")
        print(f"{'indir_jump'} {ida.nodes[node].get('indir_jump')}")
        print(f"{'has_return'} {ida.nodes[node].get('has_return')}")
        print('\n')

    # print(G)
    # print(E)


if __name__ == '__main__':
    run()
