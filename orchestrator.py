import os
import docker
import tarfile
import hashlib

def is_supported_file(file_path: str) -> bool:
    try:
        with open(file_path, 'rb') as fp:
            first_two_bytes = fp.read(2)
            if first_two_bytes == b'MZ':
                return True  # PE
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
        # name='containerAngr',
        detach=True,
        mounts=[docker.types.Mount(
            source='/home/luca/Scrivania/MasterThesis/Pickles/',
            target='/MasterThesis/Pickles/',
            type='bind'
        )]
    )

    containerRadare = client.containers.run(
        image='radare2',
        # name='containerRadare',
        detach=True,
        mounts=[docker.types.Mount(
            source='/home/luca/Scrivania/MasterThesis/Pickles/',
            target='/MasterThesis/Pickles/',
            type='bind'
        )]
    )

    containers = [containerAngr, containerRadare]
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
                container.put_archive('/MasterThesis', f.read())
            cmd = f"mkdir Pickles/{sha256}"
            container.exec_run(cmd)
            container_info = container.attrs
            if container_info['Config']['Image'] == 'angr':
                cmd = f"python3 disassemblerAngr.py {filename} analysisAngr.txt Pickles/{sha256}/angr.p"
                container.exec_run(cmd)
            if container_info['Config']['Image'] == 'radare2':
                cmd = f"python3 disassemblerRadare.py {filename} analysisRadare.txt Pickles/{sha256}/radare.p"
                container.exec_run(cmd)

        # container.remove()


if __name__ == '__main__':
    run()