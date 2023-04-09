import os
import docker
import tarfile
import hashlib
import glob
import multiprocessing
import magic

def is_supported_file(file_path: str) -> bool:
    try:
        with open(file_path, 'rb') as fp:
            first_two_bytes = fp.read(2)
            if first_two_bytes == b'MZ':
                magic_sig = magic.from_file(file_path)
                if magic_sig.startswith('PE32'):  # if x64 -> 'PE32+'
                    if not magic_sig[4] == '+':
                        return True
    except Exception:
        pass
    return False


def get_sha256sum(file_path: str) -> str:
    hash_function = hashlib.sha256()
    with open(file_path, 'rb', buffering=0) as f:
        for chunk in iter(lambda: f.read(65536), b''):
            hash_function.update(chunk)
    return hash_function.hexdigest()

def process_file(filepath):
    client = docker.from_env()
    filename = os.path.basename(filepath)
    if not is_supported_file(file_path=filepath):
        print(f'{"File"} {filename} {"is not a x86 PE"}')
        return
    sha256 = get_sha256sum(file_path=filepath)
    tarpath = f"/tmp/{filename}.tar"
    with tarfile.open(tarpath, mode='w') as tar:
        tar.add(filepath, arcname=os.path.basename(filepath))
    containers = client.containers.list()
    with open(tarpath, 'rb') as f:
        containers[0].put_archive('/root/MasterThesis', f.read())
    cmd = f"mkdir /root/MasterThesis/Pickles/{sha256}"
    containers[0].exec_run(cmd)
    container_info = containers[0].attrs
    if container_info['Config']['Image'] == 'angr':
        cmd = f"python3 disassemblerAngr.py {filename} Pickles/{sha256}/analysisAngr.txt Pickles/{sha256}/angr.p"
    elif container_info['Config']['Image'] == 'radare2':
        cmd = f"python3 disassemblerRadare.py {filename} Pickles/{sha256}/analysisRadare.txt Pickles/{sha256}/radare.p"
    elif container_info['Config']['Image'] == 'ida':
        cmd = f'wine /root/.wine/drive_c/IDA/ida64.exe -c -A -S"/root/MasterThesis/disassemblerIDA.py /root/MasterThesis/Pickles/{sha256}/analysisIDA.txt /root/MasterThesis/Pickles/{sha256}/ida.p" /root/MasterThesis/{filename}'
    elif container_info['Config']['Image'] == 'ghidra':
        cmd = f'./Tools/ghidra_10.2.3_PUBLIC/support/analyzeHeadless /root/MasterThesis ANewProject -import /root/MasterThesis/{filename} -scriptPath /root/MasterThesis -postScript disassemblerGhidra.py /root/MasterThesis/Pickles/{sha256}/analysisGhidra.txt /root/MasterThesis/Pickles/{sha256}/ghidra.p -deleteProject'
    containers[0].exec_run(cmd)
    

def run():   
    client = docker.from_env() 
    files = glob.glob('/home/luca/Scrivania/MasterThesis/Input/*.exe')
    image_names = ['angr', 'ghidra', 'ida', 'radare2']
    for name in image_names:
        container = client.containers.run(
            image=name,
            detach=True,
            mounts=[docker.types.Mount(
                source='/home/luca/Scrivania/MasterThesis/Pickles/',
                target='/root/MasterThesis/Pickles/',
                type='bind'
            )]
        )
        with multiprocessing.Pool() as pool:
            pool.map(process_file, files)
        container.stop()
        container.remove()


if __name__ == '__main__':
    run()