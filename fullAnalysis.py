import pickle
import re
import os
import json
import networkx as nx


def print_attributes(name, attributes):
    print(f"{name}")
    print(f"{'nodes_count'} {attributes['nodes_count']}")
    print(f"{'edges_count'} {attributes['edges_count']}")
    print(f"{'func_beg_count'} {attributes['func_beg_count']}")
    print(f"{'dir_call_count'} {attributes['dir_call_count']}")
    print(f"{'indir_call_count'} {attributes['indir_call_count']}")
    print(f"{'cond_jump_count'} {attributes['cond_jump_count']}")
    print(f"{'dir_jump_count'} {attributes['dir_jump_count']}")
    print(f"{'indir_jump_count'} {attributes['indir_jump_count']}")
    print(f"{'ret_count'} {attributes['ret_count']}" '\n')


def count_attributes(name, graph_purged):
    attributes = {
        "nodes_count": 0,
        "edges_count": 0,
        "func_beg_count": 0,
        "dir_call_count": 0,
        "indir_call_count": 0,
        "cond_jump_count": 0,
        "dir_jump_count": 0,
        "indir_jump_count": 0,
        "ret_count": 0
    }

    attributes['nodes_count'] = len(graph_purged.nodes())
    attributes['edges_count'] = len(graph_purged.edges())
    for node in graph_purged.nodes:
        if graph_purged.nodes[node].get('func_beg'):
            attributes['func_beg_count'] +=1
        if graph_purged.nodes[node].get('dir_call'):
            attributes['dir_call_count'] +=1
        if graph_purged.nodes[node].get('indir_call'):
            attributes['indir_call_count'] +=1
        if graph_purged.nodes[node].get('cond_jump'):
            attributes['cond_jump_count'] +=1
        if graph_purged.nodes[node].get('dir_jump'):
            attributes['dir_jump_count'] +=1
        if graph_purged.nodes[node].get('indir_jump'):
            attributes['indir_jump_count'] +=1
        if graph_purged.nodes[node].get('has_return'):
            attributes['ret_count'] +=1
    print_attributes(name, attributes)
    return attributes


def return_eq(node1, node2):
    return node1.get('unique_hash_identifier')==node2.get('unique_hash_identifier')


def diff_graph_construction(agreement, purged):
    graph_diff = nx.DiGraph()
    graph_diff.add_edges_from(purged.edges() - agreement.edges())
    for node in graph_diff.copy().nodes():
        graph_diff.add_node(node, **purged.nodes[node])
    for u, v, data in ((u, v, d) for u, v, d in purged.edges(data=True) if (u, v) not in agreement.edges()):
        graph_diff.add_edge(u, v, **data)
    return graph_diff


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


def color_edges_agreement(agreement, ida):
    for edgeAgr in agreement.copy().edges():
        for edgeIDA in ida.edges(data=True):
            if edgeAgr[0] == edgeIDA[0] and edgeAgr[1] == edgeIDA[1]:
                attr = ida.get_edge_data(edgeIDA[0], edgeIDA[1])
                agreement.add_edge(edgeAgr[0], edgeAgr[1], **attr)
    return agreement


def purge_technique(graph):
    min_addr = 0x12e3
    max_addr = 0x12f1
    for node in graph.copy():
        if node == 'UnresolvableCallTarget' or node == 'UnresolvableJumpTarget':
            graph.remove_node(node)
        elif int(node,16) < min_addr or int(node,16) > max_addr:
            graph.remove_node(node)
    for node in graph.copy().nodes():
        if graph.nodes[node].get('edges'):
            for edge, attr in zip(graph.nodes[node].get('edges'), graph.nodes[node].get('edge_attr')):
                if attr == 'Call':
                    graph.add_edge(node, edge, color='r')
                if attr == 'Fallthrough':
                    graph.add_edge(node, edge, color='g')
                if attr == 'Jump':
                    graph.add_edge(node, edge, color='b')
    return graph


def purge(graph, max_addr, min_addr):
    for node in graph.copy():
        if node == 'UnresolvableCallTarget' or node == 'UnresolvableJumpTarget':
            graph.remove_node(node)
        elif int(node,16) < min_addr or int(node,16) > max_addr:
            graph.remove_node(node)
    return graph


def get_bbl_file(pickles_folder, files):
    bbl_file = [f for f in files if f.endswith(".bbl")]
    assert bbl_file
    file_path = os.path.join(pickles_folder, bbl_file[0])
    bbl_string = open(file_path).read()
    pin_addrs_list = re.findall('.{1,8}', bbl_string)
    return pin_addrs_list


def get_base_address(pickles_folder, files):
    json_file = [f for f in files if f.endswith(".json")]
    assert json_file
    file_path = os.path.join(pickles_folder, json_file[0])
    with open(file_path, 'r', encoding='iso-8859-1') as f:
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


def RPA_check(graph):
    list_nodes = list(graph.nodes())
    for node in list_nodes:
        if graph.nodes()[node]:
            for bytes in graph.nodes()[node]['bytes']:
                #  ADD DWORD PTR [esp], xxx - MOV DWORD PTR [ebp+4],EAX (EBX, ECX)
                if "83 04 24" in bytes or "89 45 04" in bytes or "89 5D 04" in bytes or "89 4D 04" in bytes:
                    print(f"{'In BB'} {node} {'there might be a RPA technique'}")


def ID_check(graph):
    list_nodes = list(graph.nodes())
    for node in list_nodes:
        if graph.nodes()[node]:
            for bytes in graph.nodes()[node]['bytes']:
                # JMP -1
                if "EB FF" in bytes:
                    print(f"{'In BB'} {node} {'there might be a ID technique'}")
                # JMP - JZ - JNZ
                elif "EB" in bytes or "74" in bytes or "75" in bytes:
                    min_bb_addr = graph.nodes()[node]['addr'][0]
                    max_bb_addr = graph.nodes()[node]['addr'][-1]
                    if graph.nodes()[node]['edges']:
                        for edge, attr in zip(graph.nodes[node].get('edges'), graph.nodes[node].get('edge_attr')):
                            if attr == 'Jump' and edge > min_bb_addr and edge < max_bb_addr:
                                print(f"{'In BB'} {node} {'there might be a ID technique'}")                            


def CJWCC_check(graph):
    list_nodes = list(graph.nodes())
    for node in list_nodes:
        if graph.nodes()[node]:
            for bytes in graph.nodes()[node]['bytes']:
                # XOR EAX, EAX (EBX, ECX, EDX)
                if "33 C0" in bytes or "33 DB" in bytes or "33 C9" in bytes or "33 D2" in bytes: 
                    list_bytes = graph.nodes()[node]['bytes']
                    index = list_bytes.index(bytes)
                    if index < len(list_bytes) - 1:
                        if "74" in list_bytes[index+1] or "0F 84" in list_bytes[index+1]:
                            print(f"{'In BB'} {node} {'there might be a CJWCC technique'}")
                # XOR EAX, EAX (EBX, ECX, EDX)
                if "31 C0" in bytes or "31 DB" in bytes or "31 C9" in bytes or "31 D2" in bytes: 
                    list_bytes = graph.nodes()[node]['bytes']
                    index = list_bytes.index(bytes)
                    if index < len(list_bytes) - 1:
                        if "74" in list_bytes[index+1] or "0F 84" in list_bytes[index+1]:
                            print(f"{'In BB'} {node} {'there might be a CJWCC technique'}")
                # TEST ESP, ESP
                if "85 E4" in bytes:
                    list_bytes = graph.nodes()[node]['bytes']
                    index = list_bytes.index(bytes)
                    if index < len(list_bytes) - 1:
                        if "75" in list_bytes[index+1] or "0F 85" in list_bytes[index+1]:
                            print(f"{'In BB'} {node} {'there might be a CJWCC technique'}")


def CJWST_check(graph):
    list_nodes = list(graph.nodes())
    for node in list_nodes:
        if graph.nodes()[node]:
            bytes = graph.nodes()[node]['bytes'][-1]
            # JZ
            if "74" in bytes or "0F 84" in bytes:
                index = list_nodes.index(node)
                target = graph.nodes()[node]['edges'][0]
                if index < len(list_nodes) - 1:
                    next = list_nodes[index + 1]
                    if graph.nodes()[next]:
                        bytes = graph.nodes()[next]['bytes'][0]
                        # JNZ
                        if "75" in bytes or "0F 85" in bytes:
                            if target == graph.nodes()[next]['edges'][0]:
                                print(f"{'In BBs'} {node} {next} {'there might be a CJWST technique'}")


def techniques_check(name, graph):
    print(f"{name}")
    CJWST_check(graph)
    CJWCC_check(graph)
    ID_check(graph)
    RPA_check(graph)
    print('\n')
            

def main():
    pickles_folder = "Pickles/Complete/"
    assert pickles_folder
    angr = pickle.load(open(pickles_folder + "angr.p", "rb"))
    ghidra = pickle.load(open(pickles_folder + "ghidra.p", "rb"))
    ida = pickle.load(open(pickles_folder + "ida.p", "rb"))
    radare = pickle.load(open(pickles_folder + "radare.p", "rb"))

    print(f"{'Anti-disassembly techniques check'}")
    print('\n')
    techniques_check("Angr", angr)
    techniques_check("Ghidra", ghidra)
    techniques_check("Ida", ida)
    techniques_check("Radare", radare)

    pin_trace = pin_trace_creation(pickles_folder)
    min_pin_addr = min(pin_trace)
    max_pin_addr = max(pin_trace)
    int_min = int(min_pin_addr,16)
    int_max = int(max_pin_addr,16)

    set_addr_angr = set_original_addresses(angr)
    set_addr_ghidra = set_original_addresses(ghidra)
    set_addr_ida = set_original_addresses(ida)
    set_addr_radare = set_original_addresses(radare)

    print(f'{"Pin subset check on original addresses"}')
    print('\n')
    print(f'{"Pin trace addresses:"} {len(pin_trace)}')
    print(f'{"Angr is"} {pin_trace.issubset(set_addr_angr)} {"- addresses:"} {len(set_addr_angr)}')
    print(f'{"Ghidra is"} {pin_trace.issubset(set_addr_ghidra)} {"- addresses:"} {len(set_addr_ghidra)}')
    print(f'{"Ida is"} {pin_trace.issubset(set_addr_ida)} {"- addresses:"} {len(set_addr_ida)}')
    print(f'{"Radare is"} {pin_trace.issubset(set_addr_radare)} {"- addresses:"} {len(set_addr_radare)}')
    print('\n')

    angr_purged = purge(angr, int_max, int_min)
    ghidra_purged = purge(ghidra, int_max, int_min)
    ida_purged = purge(ida, int_max, int_min)
    radare_purged = purge(radare, int_max, int_min)

    pickle.dump(angr_purged, open(pickles_folder + "angr_purged.p", "wb"))
    pickle.dump(ghidra_purged, open(pickles_folder + "ghidra_purged.p", "wb"))
    pickle.dump(ida_purged, open(pickles_folder + "ida_purged.p", "wb"))
    pickle.dump(radare_purged, open(pickles_folder + "radare_purged.p", "wb"))

    set_addr_angr_purged = set_purged_addresses(angr_purged)
    set_addr_ghidra_purged = set_purged_addresses(ghidra_purged)
    set_addr_ida_purged = set_purged_addresses(ida_purged)
    set_addr_radare_purged = set_purged_addresses(radare_purged)

    print(f'{"Addresses present on the Pin trace that are missing in Angr:"} {len(pin_trace.difference(set_addr_angr_purged))}')
    if len(pin_trace.difference(set_addr_angr_purged)): print(pin_trace.difference(set_addr_angr_purged))
    print(f'{"Addresses present on the Pin trace that are missing in Ghidra:"} {len(pin_trace.difference(set_addr_ghidra_purged))}')
    if len(pin_trace.difference(set_addr_ghidra_purged)): print(pin_trace.difference(set_addr_ghidra_purged))
    print(f'{"Addresses present on the Pin trace that are missing in Ida:"} {len(pin_trace.difference(set_addr_ida_purged))}')
    if len(pin_trace.difference(set_addr_ida_purged)): print(pin_trace.difference(set_addr_ida_purged))
    print(f'{"Addresses present on the Pin trace that are missing in Radare:"} {len(pin_trace.difference(set_addr_radare_purged))}')
    if len(pin_trace.difference(set_addr_radare_purged)): print(pin_trace.difference(set_addr_radare_purged))
    print('\n')

    angr_purged = purge_technique(angr)
    ghidra_purged = purge_technique(ghidra)
    ida_purged = purge_technique(ida)
    radare_purged = purge_technique(radare)

    pickle.dump(angr_purged, open(pickles_folder + "angr_technique.p", "wb"))
    pickle.dump(ghidra_purged, open(pickles_folder + "ghidra_technique.p", "wb"))
    pickle.dump(ida_purged, open(pickles_folder + "ida_technique.p", "wb"))
    pickle.dump(radare_purged, open(pickles_folder + "radare_technique.p", "wb"))

    print(f'{"Attributes comparison on function containing the technique"}')
    print('\n')
    count_attributes("Angr", angr_purged)
    count_attributes("Ghidra", ghidra_purged)
    count_attributes("Ida", ida_purged)
    count_attributes("Radare", radare_purged)

    common_edges = set(angr_purged.edges()).intersection(set(ghidra_purged.edges()), set(ida_purged.edges()), set(radare_purged.edges()))
    for edge in common_edges.copy():
        node1, node2 = edge
        if not angr_purged.nodes[node1]["unique_hash_identifier"] == ghidra_purged.nodes[node1]["unique_hash_identifier"] == \
            ida_purged.nodes[node1]["unique_hash_identifier"] ==  radare_purged.nodes[node1]["unique_hash_identifier"]:
                common_edges.remove(edge)
        if angr_purged.nodes[node2] and ghidra_purged.nodes[node2] and ida_purged.nodes[node2] and radare_purged.nodes[node2]:
            if not angr_purged.nodes[node2]["unique_hash_identifier"] == ghidra_purged.nodes[node2]["unique_hash_identifier"] == \
                ida_purged.nodes[node2]["unique_hash_identifier"] ==  radare_purged.nodes[node2]["unique_hash_identifier"]:
                    common_edges.remove(edge)
    
    agreement_graph = nx.DiGraph(common_edges)
    agreement_graph = color_edges_agreement(agreement_graph, ida_purged)
    angr_diff = diff_graph_construction(agreement_graph, angr_purged)
    ghidra_diff = diff_graph_construction(agreement_graph, ghidra_purged)
    ida_diff = diff_graph_construction(agreement_graph, ida_purged)
    radare_diff = diff_graph_construction(agreement_graph, radare_purged)

    pickle.dump(agreement_graph, open(pickles_folder + "agreement.p", "wb"))
    pickle.dump(angr_diff, open(pickles_folder + "angr_diff.p", "wb"))
    pickle.dump(ghidra_diff, open(pickles_folder + "ghidra_diff.p", "wb"))
    pickle.dump(ida_diff, open(pickles_folder + "ida_diff.p", "wb"))
    pickle.dump(radare_diff, open(pickles_folder + "radare_diff.p", "wb"))

    set_nodes_angr_diff = set(angr_diff.nodes())
    set_edges_angr_diff = set_purged_edges(angr_diff)
    set_nodes_ghidra_diff = set(ghidra_diff.nodes())
    set_edges_ghidra_diff = set_purged_edges(ghidra_diff)
    set_nodes_ida_diff = set(ida_diff.nodes())
    set_edges_ida_diff = set_purged_edges(ida_diff)
    set_nodes_radare_diff = set(radare_diff.nodes())
    set_edges_radare_diff = set_purged_edges(radare_diff)

    print(f'{"Jaccard similarity check on nodes"}')
    print('\n')
    print(f'{"Angr vs Ghidra"} {jaccard(set_nodes_angr_diff, set_nodes_ghidra_diff)}')
    print(f'{"Angr vs Radare"} {jaccard(set_nodes_angr_diff, set_nodes_radare_diff)}')
    print(f'{"Angr vs Ida"} {jaccard(set_nodes_angr_diff, set_nodes_ida_diff)}')
    print('\n')
    print(f'{"Ghidra vs Radare"} {jaccard(set_nodes_ghidra_diff, set_nodes_radare_diff)}')
    print(f'{"Ghidra vs Angr"} {jaccard(set_nodes_ghidra_diff, set_nodes_angr_diff)}')
    print(f'{"Ghidra vs Ida"} {jaccard(set_nodes_ghidra_diff, set_nodes_ida_diff)}')
    print('\n')
    print(f'{"Ida vs Ghidra"} {jaccard(set_nodes_ida_diff, set_nodes_ghidra_diff)}')
    print(f'{"Ida vs Angr"} {jaccard(set_nodes_ida_diff, set_nodes_angr_diff)}')
    print(f'{"Ida vs Radare"} {jaccard(set_nodes_ida_diff, set_nodes_radare_diff)}')
    print('\n')
    print(f'{"Radare vs Ghidra"} {jaccard(set_nodes_radare_diff, set_nodes_ghidra_diff)}')
    print(f'{"Radare vs Angr"} {jaccard(set_nodes_radare_diff, set_nodes_angr_diff)}')
    print(f'{"Radare vs Ida"} {jaccard(set_nodes_radare_diff, set_nodes_ida_diff)}')
    print('\n')

    print(f'{"Jaccard similarity check on edges"}')
    print('\n')
    print(f'{"Angr vs Ghidra"} {jaccard(set_edges_angr_diff, set_edges_ghidra_diff)}')
    print(f'{"Angr vs Radare"} {jaccard(set_edges_angr_diff, set_edges_radare_diff)}')
    print(f'{"Angr vs Ida"} {jaccard(set_edges_angr_diff, set_edges_ida_diff)}')
    print('\n')
    print(f'{"Ghidra vs Radare"} {jaccard(set_edges_ghidra_diff, set_edges_radare_diff)}')
    print(f'{"Ghidra vs Angr"} {jaccard(set_edges_ghidra_diff, set_edges_angr_diff)}')
    print(f'{"Ghidra vs Ida"} {jaccard(set_edges_ghidra_diff, set_edges_ida_diff)}')
    print('\n')
    print(f'{"Ida vs Ghidra"} {jaccard(set_edges_ida_diff, set_edges_ghidra_diff)}')
    print(f'{"Ida vs Angr"} {jaccard(set_edges_ida_diff, set_edges_angr_diff)}')
    print(f'{"Ida vs Radare"} {jaccard(set_edges_ida_diff, set_edges_radare_diff)}')
    print('\n')
    print(f'{"Radare vs Ghidra"} {jaccard(set_edges_radare_diff, set_edges_ghidra_diff)}')
    print(f'{"Radare vs Angr"} {jaccard(set_edges_radare_diff, set_edges_angr_diff)}')
    print(f'{"Radare vs Ida"} {jaccard(set_edges_radare_diff, set_edges_ida_diff)}')
    print('\n')

    print(f'{"Graph edit distance check on differences subgraphs"}')
    print('\n')
    print(f'{"Ghidra vs radare"} {nx.graph_edit_distance(ghidra_diff, radare_diff, node_match=return_eq)}')
    print(f'{"Ghidra vs angr"} {nx.graph_edit_distance(ghidra_diff, angr_diff, node_match=return_eq)}')
    print(f'{"Ghidra vs ida"} {nx.graph_edit_distance(ghidra_diff, ida_diff, node_match=return_eq)}')
    print('\n')
    print(f'{"Radare vs ghidra"} {nx.graph_edit_distance(radare_diff, ghidra_diff, node_match=return_eq)}')
    print(f'{"Radare vs angr"} {nx.graph_edit_distance(radare_diff, angr_diff, node_match=return_eq)}')
    print(f'{"Radare vs ida"} {nx.graph_edit_distance(radare_diff, ida_diff, node_match=return_eq)}')
    print('\n')
    print(f'{"Angr vs ghidra"} {nx.graph_edit_distance(angr_diff, ghidra_diff, node_match=return_eq)}')
    print(f'{"Angr vs radare"} {nx.graph_edit_distance(angr_diff, radare_diff, node_match=return_eq)}')
    print(f'{"Angr vs ida"} {nx.graph_edit_distance(angr_diff, ida_diff, node_match=return_eq)}')
    print('\n')
    print(f'{"Ida vs ghidra"} {nx.graph_edit_distance(ida_diff, ghidra_diff, node_match=return_eq)}')
    print(f'{"Ida vs radare"} {nx.graph_edit_distance(ida_diff, radare_diff, node_match=return_eq)}')
    print(f'{"Ida vs angr"} {nx.graph_edit_distance(ida_diff, angr_diff, node_match=return_eq)}')
    print('\n')


if __name__ == '__main__':
    main()
    