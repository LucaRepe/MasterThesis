import re
import pickle
import networkx as nx


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

    angr_common = nx.DiGraph()
    for edge in angr_purged.edges():
        if edge in common_edges:
            angr_common.add_edge(edge[0], edge[1])

    ghidra_common = nx.DiGraph()
    for edge in ghidra_purged.edges():
        if edge in common_edges:
            ghidra_common.add_edge(edge[0], edge[1])

    ida_common = nx.DiGraph()
    for edge in ida_purged.edges():
        if edge in common_edges:
            ida_common.add_edge(edge[0], edge[1])

    radare_common = nx.DiGraph()
    for edge in radare_purged.edges():
        if edge in common_edges:
            radare_common.add_edge(edge[0], edge[1])

    angr_diff = nx.DiGraph()
    for node in angr_purged:
        angr_diff.add_node(node, **angr_purged.nodes[node])
    angr_diff.remove_nodes_from(angr_common.nodes())
    angr_diff.add_edges_from([edge for edge in angr_purged.edges() if edge[0] in angr_diff.nodes() and edge[1] in angr_diff.nodes()])

    ghidra_diff = nx.DiGraph()
    for node in ghidra_purged:
        ghidra_diff.add_node(node, **ghidra_purged.nodes[node])
    ghidra_diff.remove_nodes_from(ghidra_common.nodes())
    ghidra_diff.add_edges_from([edge for edge in ghidra_purged.edges() if edge[0] in ghidra_diff.nodes() and edge[1] in ghidra_diff.nodes()])

    ida_diff = nx.DiGraph()
    for node in ida_purged:
        ida_diff.add_node(node, **ida_purged.nodes[node])
    ida_diff.remove_nodes_from(ida_common.nodes())
    ida_diff.add_edges_from([edge for edge in ida_purged.edges() if edge[0] in ida_diff.nodes() and edge[1] in ida_diff.nodes()])

    radare_diff = nx.DiGraph()
    for node in radare_purged:
        radare_diff.add_node(node, **radare_purged.nodes[node])
    radare_diff.remove_nodes_from(radare_common.nodes())
    radare_diff.add_edges_from([edge for edge in radare_purged.edges() if edge[0] in radare_diff.nodes() and edge[1] in radare_diff.nodes()])

    pickle.dump(ghidra_diff, open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/ghidra_diff.p", "wb"))
    pickle.dump(radare_diff, open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/radare_diff.p", "wb"))
    pickle.dump(angr_diff, open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/angr_diff.p", "wb"))
    pickle.dump(ida_diff, open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/ida_diff.p", "wb"))

    common_edges_avg = set()

    # Aggiungiamo gli archi comuni a tutti i grafi
    common_edges_avg |= set(angr_purged.edges()) & set(ghidra_purged.edges()) & set(ida_purged.edges()) & set(radare_purged.edges())

    print((common_edges_avg))
    print('\n')

    # Aggiungiamo gli archi comuni a tre dei quattro grafi
    common_edges_avg |= ((set(angr_purged.edges()) & set(ghidra_purged.edges()) & set(ida_purged.edges())) |
                    (set(angr_purged.edges()) & set(ghidra_purged.edges()) & set(radare_purged.edges())) |
                    (set(angr_purged.edges()) & set(ida_purged.edges()) & set(radare_purged.edges())) |
                    (set(ghidra_purged.edges()) & set(ida_purged.edges()) & set(radare_purged.edges())))

    print((common_edges_avg))
    print('\n')

    print(common_edges_avg - common_edges)

    # Rimuoviamo gli archi che non sono presenti in almeno tre dei quattro grafi
    common_edges_avg -= ((set(angr_purged.edges()) ^ set(ghidra_purged.edges()) ^ set(ida_purged.edges()) ^ set(radare_purged.edges())) &
                    (set(angr_purged.edges()) | set(ghidra_purged.edges()) | set(ida_purged.edges()) | set(radare_purged.edges())))
    

if __name__ == '__main__':
    main()
