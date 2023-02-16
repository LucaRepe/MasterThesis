import pickle
import networkx as nx

def run():
    radare_purged = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/radare_purged.p", "rb"))
    angr_purged = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/angr_purged.p", "rb"))
    ida_purged = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/ida_purged.p", "rb"))
    ghidra_purged = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/Complete/ghidra_purged.p", "rb"))


    nodes_count = 0
    func_beg_count = 0
    dir_call_count = 0
    indir_call_count = 0
    cond_jump_count = 0
    dir_jump_count = 0
    indir_jump_count = 0
    ret_count = 0

    for node in ghidra_purged.nodes:
        nodes_count += 1
        if ghidra_purged.nodes[node].get('func_beg'):
            func_beg_count +=1
        if ghidra_purged.nodes[node].get('dir_call'):
            dir_call_count +=1
        if ghidra_purged.nodes[node].get('indir_call'):
            indir_call_count +=1
        if ghidra_purged.nodes[node].get('cond_jump'):
            cond_jump_count +=1
        if ghidra_purged.nodes[node].get('dir_jump'):
            dir_jump_count +=1
        if ghidra_purged.nodes[node].get('indir_jump'):
            indir_jump_count +=1
        if ghidra_purged.nodes[node].get('has_return'):
            ret_count +=1
    
    print(f'{"Ghidra_purged"}')
    print(f'{"nodes_count "} {nodes_count}')
    print(f'{"edges_count "} {len(ghidra_purged.edges)}')
    print(f'{"func_beg_count "} {func_beg_count}')
    print(f'{"dir_call_count "} {dir_call_count}')
    print(f'{"indir_call_count "} {indir_call_count}')
    print(f'{"cond_jump_count "} {cond_jump_count}')
    print(f'{"dir_jump_count "} {dir_jump_count}')
    print(f'{"indir_jump_count "} {indir_jump_count}')
    print(f'{"ret_count "} {ret_count}' '\n')


    nodes_count = 0
    func_beg_count = 0
    dir_call_count = 0
    indir_call_count = 0
    cond_jump_count = 0
    dir_jump_count = 0
    indir_jump_count = 0
    ret_count = 0

    for node in radare_purged.nodes:
        nodes_count += 1
        if radare_purged.nodes[node].get('func_beg'):
            func_beg_count +=1
        if radare_purged.nodes[node].get('dir_call'):
            dir_call_count +=1
        if radare_purged.nodes[node].get('indir_call'):
            indir_call_count +=1
        if radare_purged.nodes[node].get('cond_jump'):
            cond_jump_count +=1
        if radare_purged.nodes[node].get('dir_jump'):
            dir_jump_count +=1
        if radare_purged.nodes[node].get('indir_jump'):
            indir_jump_count +=1
        if radare_purged.nodes[node].get('has_return'):
            ret_count +=1
    
    print(f'{"Radare_purged"}')
    print(f'{"nodes_count "} {nodes_count}')
    print(f'{"edges_count "} {len(radare_purged.edges)}')
    print(f'{"func_beg_count "} {func_beg_count}')
    print(f'{"dir_call_count "} {dir_call_count}')
    print(f'{"indir_call_count "} {indir_call_count}')
    print(f'{"cond_jump_count "} {cond_jump_count}')
    print(f'{"dir_jump_count "} {dir_jump_count}')
    print(f'{"indir_jump_count "} {indir_jump_count}')
    print(f'{"ret_count "} {ret_count}' '\n')
    

    nodes_count = 0
    func_beg_count = 0
    dir_call_count = 0
    indir_call_count = 0
    cond_jump_count = 0
    dir_jump_count = 0
    indir_jump_count = 0
    ret_count = 0

    for node in angr_purged.nodes:
        nodes_count += 1
        if angr_purged.nodes[node].get('func_beg'):
            func_beg_count +=1
        if angr_purged.nodes[node].get('dir_call'):
            dir_call_count +=1
        if angr_purged.nodes[node].get('indir_call'):
            indir_call_count +=1
        if angr_purged.nodes[node].get('cond_jump'):
            cond_jump_count +=1
        if angr_purged.nodes[node].get('dir_jump'):
            dir_jump_count +=1
        if angr_purged.nodes[node].get('indir_jump'):
            indir_jump_count +=1
        if angr_purged.nodes[node].get('has_return'):
            ret_count +=1
    
    print(f'{"Angr_purged"}')
    print(f'{"nodes_count "} {nodes_count}')
    print(f'{"edges_count "} {len(angr_purged.edges)}')
    print(f'{"func_beg_count "} {func_beg_count}')
    print(f'{"dir_call_count "} {dir_call_count}')
    print(f'{"indir_call_count "} {indir_call_count}')
    print(f'{"cond_jump_count "} {cond_jump_count}')
    print(f'{"dir_jump_count "} {dir_jump_count}')
    print(f'{"indir_jump_count "} {indir_jump_count}')
    print(f'{"ret_count"} {ret_count}' '\n')


    nodes_count = 0
    func_beg_count = 0
    dir_call_count = 0
    indir_call_count = 0
    cond_jump_count = 0
    dir_jump_count = 0
    indir_jump_count = 0
    ret_count = 0

    for node in ida_purged.nodes:
        nodes_count += 1
        if ida_purged.nodes[node].get('has_return'):
            ret_count +=1
        if ida_purged.nodes[node].get('func_beg'):
            func_beg_count +=1
        if ida_purged.nodes[node].get('dir_call'):
            dir_call_count +=1
        if ida_purged.nodes[node].get('indir_call'):
            indir_call_count +=1
        if ida_purged.nodes[node].get('cond_jump'):
            cond_jump_count +=1
        if ida_purged.nodes[node].get('dir_jump'):
            dir_jump_count +=1
        if ida_purged.nodes[node].get('indir_jump'):
            indir_jump_count +=1

    print(f'{"Ida_purged"}')
    print(f'{"nodes_count "} {nodes_count}')
    print(f'{"edges_count "} {len(ida_purged.edges)}')
    print(f'{"func_beg_count "} {func_beg_count}')
    print(f'{"dir_call_count "} {dir_call_count}')
    print(f'{"indir_call_count "} {indir_call_count}')
    print(f'{"cond_jump_count "} {cond_jump_count}')
    print(f'{"dir_jump_count "} {dir_jump_count}')
    print(f'{"indir_jump_count "} {indir_jump_count}')
    print(f'{"ret_count "} {ret_count}' '\n')


if __name__ == '__main__':
    run()