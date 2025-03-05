import subprocess


def mount(volumefile, mountpoint):
    # Specify the path and name of the volume file
    volume_file = volumefile

    # Specify the mount point directory
    mount_point = mountpoint

    # Create the mount point directory if it doesn't exist
    subprocess.run(f'mkdir -p {mount_point}', shell=True)

    # Mount the ext4 volume
    subprocess.run(f'mount {volume_file} {mount_point}', shell=True)