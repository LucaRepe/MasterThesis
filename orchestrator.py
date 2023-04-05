import os
import docker
import tarfile
import hashlib


def get_file_sha256sum(file_path: str) -> str:
    hash_function = hashlib.sha256()
    with open(file_path, 'rb', buffering=0) as f:
        for chunk in iter(lambda: f.read(65536), b''):
            hash_function.update(chunk)
    return hash_function.hexdigest()

def run():
    
    input_folder = '/home/luca/Scrivania/MasterThesis/Input'
    client = docker.from_env()
    container = client.containers.run("angr", detach=True)

    for filename in os.listdir(input_folder):

        filepath = os.path.join(input_folder, filename)
        tarpath = f"/tmp/{filename}.tar"
        with tarfile.open(tarpath, mode='w') as tar:
            tar.add(filepath, arcname=os.path.basename(filepath))

        with open(tarpath, 'rb') as f:
            container.put_archive('/MasterThesis', f.read())
        
        cmd = f"mkdir Pickles/{filename}"
        container.exec_run(cmd)

        cmd = f"python3 disassemblerAngr.py {filename} analysisAngr.txt Pickles/{filename}/angr.p"
        container.exec_run(cmd)

    # container.remove()


if __name__ == '__main__':
    run()