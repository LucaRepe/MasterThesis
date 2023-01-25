import pickle
import networkx as nx

def run():
    radare = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/radare.p", "rb"))
    angr = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/angr.p", "rb"))
    ida = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/ida.p", "rb"))
    ghidra = pickle.load(open("/home/luca/Scrivania/MasterThesis/Pickles/ghidra.p", "rb"))

    nodes_count = 0
    func_beg_count = 0
    dir_call_count = 0
    indir_call_count = 0
    cond_jump_count = 0
    dir_jump_count = 0
    indir_jump_count = 0
    ret_count = 0

    for node in radare.nodes:
        # print(radare.nodes[node])
        nodes_count += 1
        if radare.nodes[node].get('func_beg'):
            func_beg_count +=1
        if radare.nodes[node].get('dir_call'):
            dir_call_count +=1
        if radare.nodes[node].get('indir_call'):
            indir_call_count +=1
        if radare.nodes[node].get('cond_jump'):
            cond_jump_count +=1
        if radare.nodes[node].get('dir_jump'):
            dir_jump_count +=1
        if radare.nodes[node].get('indir_jump'):
            indir_jump_count +=1
        if radare.nodes[node].get('has_return'):
            ret_count +=1
    
    print(f'{"Radare"}')
    print(f'{"nodes_count "} {nodes_count}')
    print(f'{"edges_count "} {len(radare.edges)}')
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

    for node in angr.nodes:
        # print(angr.nodes[node])
        nodes_count += 1
        if angr.nodes[node].get('func_beg'):
            func_beg_count +=1
        if angr.nodes[node].get('dir_call'):
            dir_call_count +=1
        if angr.nodes[node].get('indir_call'):
            indir_call_count +=1
        if angr.nodes[node].get('cond_jump'):
            cond_jump_count +=1
        if angr.nodes[node].get('dir_jump'):
            dir_jump_count +=1
        if angr.nodes[node].get('indir_jump'):
            indir_jump_count +=1
        if angr.nodes[node].get('has_return'):
            ret_count +=1
    
    print(f'{"Angr"}')
    print(f'{"edges_count "} {len(angr.edges)}')
    print(f'{"nodes_count "} {nodes_count}')
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

    for node in ida.nodes:
        # print(ida.nodes[node])
        nodes_count += 1
        if ida.nodes[node].get('has_return'):
            ret_count +=1
        if ida.nodes[node].get('func_beg'):
            func_beg_count +=1
        if ida.nodes[node].get('dir_call'):
            dir_call_count +=1
        if ida.nodes[node].get('indir_call'):
            indir_call_count +=1
        if ida.nodes[node].get('cond_jump'):
            cond_jump_count +=1
        if ida.nodes[node].get('dir_jump'):
            dir_jump_count +=1
        if ida.nodes[node].get('indir_jump'):
            indir_jump_count +=1

    print(f'{"Ida"}')
    print(f'{"nodes_count "} {nodes_count}')
    print(f'{"edges_count "} {len(ida.edges)}')
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

    for node in ghidra.nodes:
        # print(ghidra.nodes[node])
        nodes_count += 1
        if ghidra.nodes[node].get('func_beg'):
            func_beg_count +=1
        if ghidra.nodes[node].get('dir_call'):
            dir_call_count +=1
        if ghidra.nodes[node].get('indir_call'):
            indir_call_count +=1
        if ghidra.nodes[node].get('cond_jump'):
            cond_jump_count +=1
        if ghidra.nodes[node].get('dir_jump'):
            dir_jump_count +=1
        if ghidra.nodes[node].get('indir_jump'):
            indir_jump_count +=1
        if ghidra.nodes[node].get('has_return'):
            ret_count +=1
    
    print(f'{"Ghidra"}')
    print(f'{"nodes_count "} {nodes_count}')
    print(f'{"edges_count "} {len(ghidra.edges)}')
    print(f'{"func_beg_count "} {func_beg_count}')
    print(f'{"dir_call_count "} {dir_call_count}')
    print(f'{"indir_call_count "} {indir_call_count}')
    print(f'{"cond_jump_count "} {cond_jump_count}')
    print(f'{"dir_jump_count "} {dir_jump_count}')
    print(f'{"indir_jump_count "} {indir_jump_count}')
    print(f'{"ret_count "} {ret_count}' '\n')


if __name__ == '__main__':
    run()