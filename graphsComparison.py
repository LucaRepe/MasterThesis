import pickle


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


def main():
    angr_purged = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/angr_purged.p", "rb"))
    ghidra_purged = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/ghidra_purged.p", "rb"))
    ida_purged = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/ida_purged.p", "rb"))
    radare_purged = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/radare_purged.p", "rb"))
    
    angr_attributes = count_attributes("Angr", angr_purged)
    ghidra_attributes = count_attributes("Ghidra", ghidra_purged)
    ida_attributes = count_attributes("Ida", ida_purged)
    radare_attributes = count_attributes("Radare", radare_purged)

    # print(f'{"Ghidra vs radare"} {nx.graph_edit_distance(ghidra_purged, radare_purged, node_match=return_eq)}')
    # print(f'{"Ghidra vs angr"} {nx.graph_edit_distance(ghidra_purged, angr_purged, node_match=return_eq)}')
    # print(f'{"Ghidra vs ida"} {nx.graph_edit_distance(ghidra_purged, ida_purged, node_match=return_eq)}')
    # print('\n')
# 
    # print(f'{"Radare vs ghidra"} {nx.graph_edit_distance(radare_purged, ghidra_purged, node_match=return_eq)}')
    # print(f'{"Radare vs angr"} {nx.graph_edit_distance(radare_purged, angr_purged, node_match=return_eq)}')
    # print(f'{"Radare vs ida"} {nx.graph_edit_distance(radare_purged, ida_purged, node_match=return_eq)}')
    # print('\n')
# 
    # print(f'{"Angr vs ghidra"} {nx.graph_edit_distance(angr_purged, ghidra_purged, node_match=return_eq)}')
    # print(f'{"Angr vs radare"} {nx.graph_edit_distance(angr_purged, radare_purged, node_match=return_eq)}')
    # print(f'{"Angr vs ida"} {nx.graph_edit_distance(angr_purged, ida_purged, node_match=return_eq)}')
    # print('\n')
# 
    # print(f'{"Ida vs ghidra"} {nx.graph_edit_distance(ida_purged, ghidra_purged, node_match=return_eq)}')
    # print(f'{"Ida vs radare"} {nx.graph_edit_distance(ida_purged, radare_purged, node_match=return_eq)}')
    # print(f'{"Ida vs angr"} {nx.graph_edit_distance(ida_purged, angr_purged, node_match=return_eq)}')
    # print('\n')


if __name__ == '__main__':
    main()