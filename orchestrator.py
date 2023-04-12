import os
import docker
import tarfile
import hashlib
import glob
import multiprocessing
import magic

running_container = None

def is_supported_file(file_path: str) -> bool:
    try:
        with open(file_path, 'rb') as fp:
            first_two_bytes = fp.read(2)
            if first_two_bytes == b'MZ':
                magic_sig = magic.from_file(file_path)
                if magic_sig.startswith('PE32'):
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


def execute_disass(sha256, filename):
    container_info = running_container.attrs
    if container_info['Config']['Image'] == 'angr':
        cmd = f"python3 disassemblerAngr.py {filename} Pickles/{sha256}/analysisAngr.txt Pickles/{sha256}/angr.p"
    elif container_info['Config']['Image'] == 'ghidra':
        cmd = f'./Tools/ghidra_10.2.3_PUBLIC/support/analyzeHeadless /root/MasterThesis ANewProject -import /root/MasterThesis/{filename} -scriptPath /root/MasterThesis -postScript disassemblerGhidra.py /root/MasterThesis/Pickles/{sha256}/analysisGhidra.txt /root/MasterThesis/Pickles/{sha256}/ghidra.p -deleteProject'
    elif container_info['Config']['Image'] == 'ida':
        cmd = f'wine /root/.wine/drive_c/IDA/ida64.exe -c -A -S"/root/MasterThesis/disassemblerIDA.py /root/MasterThesis/Pickles/{sha256}/analysisIDA.txt /root/MasterThesis/Pickles/{sha256}/ida.p" /root/MasterThesis/{filename}'
    elif container_info['Config']['Image'] == 'radare2':
        cmd = f"python3 disassemblerRadare.py {filename} Pickles/{sha256}/analysisRadare.txt Pickles/{sha256}/radare.p"
    running_container.exec_run(cmd)
    cmd = f'cmd = "chmod -R a+wrx /root/MasterThesis/Pickles/{sha256}"'
    running_container.exec_run(cmd)


def process_file(filepath):
    filename = os.path.basename(filepath)
    if not is_supported_file(file_path=filepath):
        print(f'{"File"} {filename} {"is not a x86 PE"}')
        return
    sha256 = get_sha256sum(file_path=filepath)
    tarpath = f"/tmp/{filename}.tar"
    with tarfile.open(tarpath, mode='w') as tar:
        tar.add(filepath, arcname=os.path.basename(filepath))
    with open(tarpath, 'rb') as f:
        running_container.put_archive('/root/MasterThesis', f.read())
    cmd = f"mkdir /root/MasterThesis/Pickles/{sha256}"
    running_container.exec_run(cmd)
    execute_disass(sha256, filename)
    

def main():   
    client = docker.from_env() 
    global running_container
    input_folder = "/home/luca/Scrivania/MasterThesis/Input"
    assert input_folder
    files = glob.glob(input_folder + '/*.exe')
    
    image_names = ['angr', 'ghidra', 'ida', 'radare2']
    for name in image_names:
        if client.images.get(name):
            container = client.containers.run(
                image=name,
                detach=True,
                mounts=[docker.types.Mount(
                    source='/home/luca/Scrivania/MasterThesis/Pickles/',
                    target='/root/MasterThesis/Pickles/',
                    type='bind'
                )]
            )
        else:
            print(f"{name} {'image not found'}")
            return
        running_container = container
        with multiprocessing.Pool() as pool:
            pool.map(process_file, files)
        container.stop()
        container.remove()


if __name__ == '__main__':
    main()