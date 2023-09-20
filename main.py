#!/usr/bin/env python

from __future__ import with_statement

import os
import sys
import errno
import argparse
import getpass
from pathlib import Path
import atexit
import signal
import stat

from fuse import FUSE, FuseOSError, Operations, fuse_get_context


from vol_multiple import get_file
from vol_multiple import borrar_contenido_carpeta
from vol_multiple import obtain_file_paths
from vol_multiple import init
from vol_multiple import set_file
from vol_multiple import set_random
from vol_multiple import get_enviroment
from vol_multiple import get_master_key
from vol_multiple import get_path_files
from vol_multiple import gen_attr_data
from vol_multiple import get_file_open
from vol_multiple import remove_file_container_filename
from vol_multiple import remove_file_container_filename_common_enviroment
from vol_multiple import open_empty_file

ROOT = ""
CONTAINER = ""
KEY = ""
MOUNTPOINT = ""
MASTER = ""
ENVIROMENT = ""


class Passthrough(Operations):
    def __init__(self, root, password, container_file, mount_point):
        print("init")
        self.root = root
        self.password = password
        self.container_file = container_file
        self.mount_point = mount_point
        self.files = []
        self.enviroment = get_enviroment(container_file, password)
        self.master = get_master_key(container_file, password, self.enviroment)
        borrar_contenido_carpeta(self.root)


    # Helpers
    # =======

    def _full_path(self, partial):
        if partial.startswith("/"):
            partial = partial[1:]
        path = os.path.join(self.root, partial)
        return path

    # Filesystem methods
    # ==================

    def access(self, path, mode):
        full_path = self._full_path(path)
        print("access")
        if not os.access(full_path, mode):
            raise FuseOSError(errno.EACCES)

    def chmod(self, path, mode):
        full_path = self._full_path(path)
        print("chmod")
        return os.chmod(full_path, mode)

    def chown(self, path, uid, gid):
        full_path = self._full_path(path)
        print("chown")
        return os.chown(full_path, uid, gid)

    def getattr(self, path, fh=None):
        full_path = self._full_path(path)
        print("getattr")
        if (path == "/"):
            st = os.lstat(full_path)
            data = dict((key, getattr(st, key)) for key in ('st_atime', 'st_ctime', 'st_gid', 'st_mode', 'st_mtime', 'st_nlink', 'st_size', 'st_uid'))
        else:
            entries, lengths = get_path_files(self.container_file, self.master, self.enviroment, self.mount_point)
            data = gen_attr_data()
            try:
                index = entries.index(path[1:])
            
                data["st_nlink"] = 1
                data["st_mode"] = 33188
                data["st_size"] = lengths[index]
                data["st_ctime"] = 10000

                # data["st_mode"] = stat.S_IFDIR
            except:
                data["st_nlink"] = 1
                data["st_mode"] = 33188
                data["st_size"] = 10000
                data["st_ctime"] = 10000
        return data

    def readdir(self, path, fh):
        full_path = self._full_path(path)
        print("readdir")
        dirents = ['.', '..']
        # if os.path.isdir(full_path):
        #     dirents.extend(os.listdir(full_path))
        entries, lengths = get_path_files(self.container_file, self.master, self.enviroment, self.mount_point)
        entries_new = []
        if (full_path.replace(self.root, "") == "/"):
            for entry in entries:
                if("/" not in entry):
                    entries_new.append(entry)
                else:
                    entry = entry.split("/")[0]
                    if (entry not in entries_new):
                        entries_new.append(entry.split("/")[0])
        else:
            for entry in entries:
                if (path.replace("/", "") in entry):
                    entries_new.append(entry.replace(path.replace("/", ""),"").replace("/",""))
        dirents.extend(entries_new)
        self.files = dirents
        for r in dirents:
            yield r

    def readlink(self, path):
        pathname = os.readlink(self._full_path(path))
        print("readlink")
        if pathname.startswith("/"):
            # Path name is absolute, sanitize it.
            return os.path.relpath(pathname, self.root)
        else:
            return pathname

    def rmdir(self, path):
        full_path = self._full_path(path)
        print("rmdir")
        return os.rmdir(full_path)

    def mkdir(self, path, mode):
        print("mkdir")
        return os.mkdir(self._full_path(path), mode)

    def statfs(self, path):
        full_path = self._full_path(path)
        stv = os.statvfs(full_path)
        print("statfs")
        return dict((key, getattr(stv, key)) for key in ('f_bavail', 'f_bfree',
            'f_blocks', 'f_bsize', 'f_favail', 'f_ffree', 'f_files', 'f_flag',
            'f_frsize', 'f_namemax'))

    def unlink(self, path):
        print("unlink")
        open_empty_file(self.container_file, self.master, self.root + path)
        file_removed = remove_file_container_filename_common_enviroment(self.container_file, self.master, path[1:], self.enviroment, self.root)
        return os.unlink(self._full_path(path))

    def symlink(self, name, target):
        print("symlink")  
        return os.symlink(target, self._full_path(name))

    def rename(self, old, new):
        print("rename")
        return os.rename(self._full_path(old), self._full_path(new))

    def link(self, target, name):
        print("link")
        return os.link(self._full_path(name), self._full_path(target))

    def utimens(self, path, times=None):
        print("utimens")
        return os.utime(self._full_path(path), times)

##

    def open(self, path, flags):
        print("open")
        full_path = self._full_path(path)
        open_empty_file(self.container_file, self.master, self.root + path)
        try:
            outhpath = get_file_open(self.container_file, self.master, self.enviroment, path, self.root)
        except:
            print("No outhpath")
        return os.open(full_path, flags)

    def create(self, path, mode, fi=None):
        print("create")
        uid, gid, pid = fuse_get_context()
        full_path = self._full_path(path)
        fd = os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)
        # os.chown(full_path,uid,gid) #chown to context uid & gid
        return fd

    def read(self, path, length, offset, fh):
        print("read")
        os.lseek(fh, offset, os.SEEK_SET)
        return os.read(fh, length)

    def write(self, path, buf, offset, fh):
        print("write")
        os.lseek(fh, offset, os.SEEK_SET)
        
        return os.write(fh, buf)

    def truncate(self, path, length, fh=None):
        full_path = self._full_path(path)
        print("truncate")
        with open(full_path, 'r+') as f:
            f.truncate(length)

    def flush(self, path, fh):
        print("flush")
        return os.fsync(fh)        

    def release(self, path, fh):
        print("release")
        # Rutina para guardar el cambio en el fichero y borrarlo del sistema de archivos
        file_removed, enviroment_return = remove_file_container_filename(self.container_file, self.master, path[1:], self.enviroment, self.root)
        archivos_encontrados = obtain_file_paths(self.root)
        for ruta_archivo in archivos_encontrados:
            print(ruta_archivo.split("/")[-1:][0])
            print(path[1:])
            if(ruta_archivo.split("/")[-1:][0] == path[1:]):
                if( enviroment_return == None):
                    set_file(self.container_file, self.master, self.enviroment, ruta_archivo, self.root)
                else:
                    set_file(self.container_file, self.master, enviroment_return, ruta_archivo, self.root)
        borrar_contenido_carpeta(self.root)
        return os.close(fh)

    def fsync(self, path, fdatasync, fh):
        print("fsync")

        return self.flush(path, fh)


def create_fuse_filesystem(mountpoint, root, password, container_file):
    # Variables necesarias para la iniciación del fuse --> PARA EL BORRADO DE LA CARPETA ROOT AL FINALIZAR EL PROGRAMA
    container_file = container_file
    global ROOT
    ROOT = root.strip()
    global CONTAINER
    CONTAINER = container_file.strip()
    global KEY
    KEY = password
    global MOUNTPOINT
    MOUNTPOINT = mountpoint.strip()
    fuse = FUSE(Passthrough(root, password=password, container_file=container_file, mount_point=mountpoint), mountpoint, nothreads=True, foreground=True, allow_other=False)


def cleanup():
    # Lógica para realizar tareas de limpieza al terminar la ejecución

    # Rutina para borrar el directorio root 
    borrar_contenido_carpeta(ROOT)
    print("Program completed")
    
def signal_handler(signal, frame):
    # Lógica para manejar la señal de interrupción (Ctrl + C)
    cleanup()
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description='Tool for create a fuse filesystem with plausible deniability')
    parser.add_argument('-f', '--file', help='Path of the file (with name of the file)')
    parser.add_argument('-s', '--size', help='Size of the random data to introduce in the file in Bytes')
    parser.add_argument('-o', '--outfile', help='Path of the output file (with name of the file)')
    parser.add_argument('-i', '--inputfile', help='Path of the input file (with name of the file)')
    
    subparsers = parser.add_subparsers(dest='command')
    
    create_parser = subparsers.add_parser('init', help='Initialization of the FUSE filesystem container file.')
    create_parser.add_argument('-f', '--file', help='Path of the file (with name of the file)')

    getfile_parser = subparsers.add_parser('getfile', help='Get a encrypt file of a enviroment')
    getfile_parser.add_argument('-f', '--file', help='Path of the file container (with name of the file)')
    getfile_parser.add_argument('-i', '--infile', help='The name of the file you want to recover')
    getfile_parser.add_argument('-o', '--outpath', help='The path where you want to recover the file')

    setfile_parser = subparsers.add_parser('setfile', help='Set a encrypt file in a enviroment')
    setfile_parser.add_argument('-f', '--file', help='Path of the file container (with name of the file)')
    setfile_parser.add_argument('-i', '--inputfile', help='Path of the input file (with name of the file)')
    setfile_parser.add_argument('-e', '--enviroment', help='Number of the enviroment in order to introduce a file to the common enviroment')

    fuse_parser = subparsers.add_parser('fuse', help='Mount the FUSE')
    fuse_parser.add_argument('-m', '--mountpoint', help='Path of the mount point')
    fuse_parser.add_argument('-r', '--root', help='Path of the root directory')
    fuse_parser.add_argument('-f', '--file', help='Path of the file container (with name of the file)')

    random_parser = subparsers.add_parser('random', help='Insert random data in the ')
    random_parser.add_argument('-f', '--file', help='Path of the file (with name of the file)')
    random_parser.add_argument('-n', '--number', help='Number of blocks of the random data to introduce in the file')
    



    args = parser.parse_args()

    if args.command == 'init':
        
        if not args.file:
            print("Use the option -f or --file to indicate the path of the file to be saved")
            sys.exit()
        
        init(args.file)
    
    elif args.command == 'setfile':
        
        if not args.file:
            print("Use the option -f or --file to indicate the path of the container file")
            sys.exit()

        key = getpass.getpass("Secret key: ")
        key_confirmed = getpass.getpass("Confirm secret key: ")
        if key.strip() != key_confirmed.strip():
            print("The entered values must match")
            sys.exit()

        if not args.inputfile:
            print("Use the option -i or --inputfile to indicate the path of the file to be saved in the container file")
            sys.exit()
        
        if not args.enviroment:
            enviroment = get_enviroment(args.file, key.encode("utf-8"))

        else:
            enviroment = int(args.enviroment.strip())

        enviroment_master = get_enviroment(args.file, key.encode("utf-8"))
        master = get_master_key(args.file, key.encode("utf-8"), enviroment_master)
        set_file(args.file, master, enviroment, args.inputfile.strip(), "")

    elif args.command == 'getfile':
        
        if not args.file:
            print("Use the option -f or --file to indicate the path of the container file")
            sys.exit()
        if not args.infile:
            print("Use the option -i or --infile to indicate the name of the file you want to recover")
            sys.exit()
        if not args.outpath:
            print("Use the option -o or --outpath to indicate the path where you want to recover the file")
            sys.exit()
        
        key = getpass.getpass("Secret key: ")

        enviroment = get_enviroment(args.file.strip(), key.encode("utf-8"))
        master = get_master_key(args.file.strip(), key.encode("utf-8"), enviroment)

        get_file(args.file.strip(), master, enviroment, args.infile.strip(), args.outpath.strip(), )


    elif args.command == 'fuse':
        
        if not args.root:
            print("Use the option -r or --root to indicate the path of the root directory")
            sys.exit()
        if not args.file:
            print("Use the option -f or --file to indicate the path of the file to be saved")
            sys.exit()
        if not args.mountpoint:
            print("Use the option -m or --mountpoint to indicate the path of the mount point")
            sys.exit()
            
        key = getpass.getpass("Secret key: ")
        key_confirmed = getpass.getpass("Confirm secret key: ")
        if key.strip() != key_confirmed.strip():
            print("The entered values must match")
            sys.exit()

        key = key.encode("utf8")
        # Variables necesarias para la iniciación del fuse
        global ROOT
        ROOT = args.root.strip()
        global CONTAINER
        CONTAINER = args.file.strip()
        global KEY
        KEY = key
        global MOUNTPOINT
        MOUNTPOINT = args.mountpoint.strip()

        print("Mountpoint: " + MOUNTPOINT)
        print("Root: " + ROOT)
        print("Key: " + KEY.decode("utf8"))
        print("Container :" + CONTAINER)
        create_fuse_filesystem(MOUNTPOINT, ROOT, KEY, CONTAINER)

        
        
    ## TODO
    elif args.command == 'random':
        
        if not args.file:
            print("Use the option -f or --file to indicate the path of the container file")
            sys.exit()
        if not args.number:
            print("Use the option -n or --number to indicate the number of blocks of the random data to introduce")
            sys.exit()
        
        try:
            number = int(args.number)
        except ValueError:
            print('Please enter an integer')
            sys.exit()

        key = getpass.getpass("Secret key: ")
        key_confirmed = getpass.getpass("Confirm secret key: ")
        if key.strip() != key_confirmed.strip():
            print("The entered values must match")
            sys.exit()

        
        enviroment = get_enviroment(args.file.strip(), key.encode("utf-8"))
        master = get_master_key(args.file.strip(), key.encode("utf-8"), enviroment)
        for i in range(number):
            set_random(args.file.strip(), master, enviroment, "random")

def pruebas():
    KEY = b"hola"
    CONTAINER = "./master_prueba.bin"
    create_fuse_filesystem("/tmp/fuse", "/home/jorge/tf/fuse", KEY, CONTAINER)


if __name__ == '__main__':

    # Registrar la función de limpieza para que se llame al finalizar
    atexit.register(cleanup)

    # Registrar el manejador de señal para la interrupción (Ctrl + C)
    signal.signal(signal.SIGINT, signal_handler)
    # Inicio del programa
    main()
    
    # file_ = "./master_prueba.bin"
    # clave = b"hola"
    # enviroment = 3
    # master = get_master_key(file_, clave, enviroment)
    # set_file(file_, master, enviroment, "./entropy.py", "")
    # pruebas()
