import subprocess

def umount(mount_point):
    subprocess.run(f'umount {mount_point}', shell=True)
