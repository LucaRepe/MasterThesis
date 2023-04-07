import os
import docker
import tarfile
import hashlib

def is_supported_file(file_path: str) -> bool:
    try:
        with open(file_path, 'rb') as fp:
            first_two_bytes = fp.read(2)
            if first_two_bytes == b'MZ':
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


def run():    
    input_folder = '/home/luca/Scrivania/MasterThesis/Input'
    client = docker.from_env()
    containerAngr = client.containers.run(
        image='angr',
        detach=True,
        mounts=[docker.types.Mount(
            source='/home/luca/Scrivania/MasterThesis/Pickles/',
            target='/root/MasterThesis/Pickles/',
            type='bind'
        )]
    )

    containerIda = client.containers.run(
        image='ida',
        detach=True,
        mounts=[docker.types.Mount(
            source='/home/luca/Scrivania/MasterThesis/Pickles/',
            target='/root/MasterThesis/Pickles/',
            type='bind'
        )]
    )

    containerGhidra = client.containers.run(
        image='ghidra',
        detach=True,
        mounts=[docker.types.Mount(
            source='/home/luca/Scrivania/MasterThesis/Pickles/',
            target='/root/MasterThesis/Pickles/',
            type='bind'
        )]
    )

    containerRadare = client.containers.run(
        image='radare2',
        detach=True,
        mounts=[docker.types.Mount(
            source='/home/luca/Scrivania/MasterThesis/Pickles/',
            target='/root/MasterThesis/Pickles/',
            type='bind'
        )]
    )

    containers = [containerAngr, containerRadare,containerIda, containerGhidra]
    for container in containers:
        for filename in os.listdir(input_folder):
            filepath = os.path.join(input_folder, filename)
            if not is_supported_file(file_path=filepath):
                print(f'{"File"} {filename} {"is not PE"}')
                continue
            sha256 = get_sha256sum(file_path=filepath)
            tarpath = f"/tmp/{filename}.tar"
            with tarfile.open(tarpath, mode='w') as tar:
                tar.add(filepath, arcname=os.path.basename(filepath))
            with open(tarpath, 'rb') as f:
                container.put_archive('/root/MasterThesis', f.read())
            cmd = f"mkdir /root/MasterThesis/Pickles/{sha256}"
            container.exec_run(cmd)
            container_info = container.attrs
            if container_info['Config']['Image'] == 'angr':
                cmd = f"python3 disassemblerAngr.py {filename} Pickles/{sha256}/analysisAngr.txt Pickles/{sha256}/angr.p"
            if container_info['Config']['Image'] == 'radare2':
                cmd = f"python3 disassemblerRadare.py {filename} Pickles/{sha256}/analysisRadare.txt Pickles/{sha256}/radare.p"
            if container_info['Config']['Image'] == 'ida':
                cmd = f'wine /root/.wine/drive_c/IDA/ida64.exe -c -A -S"/root/MasterThesis/disassemblerIDA.py /root/MasterThesis/Pickles/{sha256}/analysisIDA.txt /root/MasterThesis/Pickles/{sha256}/ida.p" /root/MasterThesis/{filename}'
            if container_info['Config']['Image'] == 'ghidra':
                cmd = f'./Tools/ghidra_10.2.3_PUBLIC/support/analyzeHeadless /root/MasterThesis ANewProject -import /root/MasterThesis/{filename} -scriptPath /root/MasterThesis -postScript disassemblerGhidra.py /root/MasterThesis/Pickles/{sha256}/analysisGhidra.txt /root/MasterThesis/Pickles/{sha256}/ghidra.p -deleteProject'
            container.exec_run(cmd)

        # container.remove()


if __name__ == '__main__':
    run()