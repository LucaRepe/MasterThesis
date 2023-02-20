import re
import pickle
import networkx as nx

def purge(graph, max_addr, min_addr):
    print(graph)
    for node in graph.copy():
        if node == 'UnresolvableCallTarget' or node == 'UnresolvableJumpTarget':
            continue
        if int(node,16) < min_addr or int(node,16) > max_addr:
            print(node)
            graph.remove_node(node)
    return graph


def jaccard(s1, s2):
    return float(len(s1.intersection(s2)) / len(s1.union(s2)))


def run():
    angr = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/HelloWorld/angr.p", "rb"))  
    base_address = 0x5e0000
    bbl_string = open('/home/luca/Scrivania/MasterThesis/testmainMinGW.bbl').read()
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
   
    angr_purged = nx.DiGraph()
    set_addr_angr = set()
    for node in angr:
        if angr.nodes[node].get('addr') is not None:
            set_addr_angr.update(angr.nodes[node].get('addr'))

    angr_purged = purge(angr, int_max, int_min)
    print(angr_purged)

    pickle.dump(angr_purged, open("/home/luca/Scrivania/MasterThesis/Pickles/HelloWorld/angr_purged.p", "wb"))

    print(f'{"--- Pin subset check on original addresses ---"}')
    print('\n')  
    print(f'{"Angr is"} {pin_trace.issubset(set_addr_angr)} {"- addresses:"} {len(set_addr_angr)}')
    print('\n')

    set_addr_angr_purged = set()
    set_edges_angr_purged = set()
    for node in angr_purged:
        if angr_purged.nodes[node].get('addr') is not None:
            set_addr_angr_purged.update(angr_purged.nodes[node].get('addr'))
        if angr_purged.nodes[node].get('edges') is not None:
            set_edges_angr_purged.update(angr_purged.nodes[node].get('edges'))

    print(f'{"--- Jaccard similarity check on purged addresses ---"}')
    print(f'{"Angr"} {jaccard(pin_trace, set_addr_angr_purged)} {len(pin_trace)} {len(set_addr_angr_purged)}')
    print('\n')

    print(f'{"Addresses present on Pin that are missing in Angr: "} {len(pin_trace.difference(set_addr_angr_purged))}')
    print(pin_trace.difference(set_addr_angr_purged))
    print('\n')


if __name__ == '__main__':
    run()
