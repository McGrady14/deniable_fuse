import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import random
import binascii
import hashlib
import getpass


from crc32 import calculate_crc32
from crc32 import is_crc32_valid


# First index
FIRST_INDEX = 0

# Number of enviroments
NUMBER_KEYS = 2

# Value for each enviroment
COMMON_ENVIROMENT_VALUE = NUMBER_KEYS + 1
FIRST_ENVIROMENT_VALUE = 1
SECOND_ENVIROMENT_VALUE = 2

# Tamaño random data
MIN_RANDOM_DATA = 1024
MAX_RANDOM_DATA = 8192
MID_RANDOM_DATA = 2048




# BLOCK PARTS

# Every container file has its own salt and nonce of 16B each 
SALT_SIZE = 16
NONCE_SIZE = 16


# Master key size --> Two enviroments, so 64B per container file
MASTER_KEY_SIZE = 32
SHA_MASTER_KEY_SIZE = MASTER_KEY_SIZE * 2

## BLOCK SIZES 

# Block size indicating which environment the file is in --> 3 both, 1 first, 2 second
ENVIROMENTS_SIZE = 1

# Block size indicating the filename of the file
FILENAME_SIZE = 64

# Block size indicating the total number of blocks that contains the total of the file
N_TOTAL_SIZE = 5

# Block size indicating the nuber of block is this block
N_BLOCK_SIZE = 5 

# Block size indicating the length of the file in this block
N_LENGTH_SIZE = 5

# Block size indicating the size of the data in that block --> 16MB per block
DATA_SIZE = 16384

# Checksum CRC32 of 16B
CHECKSUM_SIZE = 16

# Block size indicating the total size of the block --> 16480B
BLOCK_SIZE = ENVIROMENTS_SIZE + FILENAME_SIZE + N_BLOCK_SIZE + N_TOTAL_SIZE + N_LENGTH_SIZE + DATA_SIZE + CHECKSUM_SIZE






def get_pbkdf(password, salt):

    backend = default_backend()

    # Deriva la clave de cifrado utilizando PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Tamaño de clave de 256 bits
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(password)

    return key



# Metodo para cifrar con chacha20 indicando salt y nonce
def encrypt_message_salt_nonce(message, password, salt, nonce):
    backend = default_backend()

    # Deriva la clave de cifrado utilizando PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Tamaño de clave de 256 bits
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(password)

    # Genera un nonce aleatorio

    # Crea el objeto Cipher con el algoritmo ChaCha20 y el modo AEAD
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=backend)

    # Cifra el mensaje utilizando el cifrador ChaCha20-Poly1305
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()

    # Retorna la sal, el nonce y el texto cifrado
    return ciphertext


# Metodo para descifrar 
def decrypt_message(salt, nonce, ciphertext, password):
    backend = default_backend()

    # Deriva la clave de cifrado utilizando PBKDF2 con la misma sal y contraseña
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Tamaño de clave de 256 bits
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(password)

    # Crea el objeto Cipher con el algoritmo ChaCha20 y el modo AEAD
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=backend)

    # Descifra el mensaje utilizando el cifrador ChaCha20-Poly1305
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext


# Sacar bytes aleatorios 
def random_data(size):
    return os.urandom(size)


def createfile(path):
    print("Creating file ...")
    # print(path)
    with open(path, "w+b") as file:
        # Generamos la salt y el nonce
        salt = random_data(SALT_SIZE)
        nonce = random_data(NONCE_SIZE)
        # print(salt)
        # Se crea el fichero, al inicio en nonce y la salt 
        file.write(nonce)
        file.write(salt)
        # Se generan entre 1k y 8k de data aleatoria 
        # rand_data = randint(MIN_RANDOM_DATA, MAX_RANDOM_DATA)
        # file.write(random_data(rand_data))
        file.close()

    

# Para crear una salt y un nonce para el fichero contenedor
def get_salt_nonce(path):
    with open(path, "r+b") as file:
        file.seek(FIRST_INDEX)
        nonce = file.read(NONCE_SIZE)
        file.seek(NONCE_SIZE)
        salt = file.read(SALT_SIZE)
        file.close()

        return salt, nonce

def init(path):
    # Se crea el fichero 
    createfile(path)

    salt, nonce = get_salt_nonce(path)
    master = get_pbkdf(os.urandom(32), salt)

    size_passw = 0 
    for i in range(NUMBER_KEYS):
        key = getpass.getpass("Secret key "+ str(i + 1) + ": ")
        key = key.encode("utf8")
        key_hashed = hashlib.sha256(key) # Clave hasheada con sha256
        # key = b'passwd'

        pwm_new = get_pbkdf(key, salt)
        master_sec = encrypt_message_salt_nonce(master, key, salt, nonce)

        with open(path, "r+b") as file:
            file.seek(NONCE_SIZE + SALT_SIZE + size_passw)
            file.write(key_hashed.digest())
            file.write(master_sec)
            file.close()
        # print("Master Key SEC number " + str(i) + " : " + str(binascii.hexlify(master_sec).decode('utf-8')))
        # with open(path, "r+b") as file:
            # file.seek(NONCE_SIZE+ SALT_SIZE)
            # master_rec = file.read(len(master_sec))
            # file.close()

        size_passw = size_passw + len(key_hashed.digest()) + len(master_sec)

    
    print("File created in ", str(path))

    return path





def master_recovery(path, key):

    salt, nonce = get_salt_nonce(path)
    data = []
    for i in range(2):
        data.append(input("key: ").encode("utf8"))

    size_passw = 0 

    print(salt)
    print(nonce)
    for key in data:
        print(key.decode('utf-8'))
        with open(path, "r+b") as file:
            file.seek(NONCE_SIZE+ SALT_SIZE + size_passw)
            # file.seek(0)
            master_rec = file.read(32)
            file.close()

        size_passw = size_passw + 32
        print(binascii.hexlify(master_rec).decode('utf-8'))
        # key = get_pbkdf(key, salt)
        
        # print(master_rec)

        master_rec = decrypt_message(salt, nonce, master_rec, key)
        print(binascii.hexlify(master_rec).decode('utf-8'))

    return master_rec


def master_recovery_(path, key):

    salt, nonce = get_salt_nonce(path)
    
    with open(path, "r+b") as file:
        file.seek(NONCE_SIZE+ SALT_SIZE)
        master_rec = file.read(MASTER_KEY_SIZE)
        file.close()

    master_rec = decrypt_message(salt, nonce, master_rec, key)
    print(binascii.hexlify(master_rec).decode('utf-8'))

    return master_rec

# Dividir el mensaje en bloques de mensaje de maximo DATA_SIZE
def split_bytes_into_segments(byte_string, segment_size):
    segments = []
    index = 0
    while index < len(byte_string):
        segment = byte_string[index:index+segment_size]
        segments.append(segment)
        index += segment_size
    return segments


# Introducir data al final del fichero
def append_data(data, path):
    with open(path, "ab") as file:
        file.write(data)
        file.close()

# Metodo para insertar un fichero dentro del fichero contenedor con una clave
def set_random(path, key, enviroment_select, infile):

    salt, nonce = get_salt_nonce(path)
    with open(path, "ab") as file: 
        # Enviroment
        enviroment = str(enviroment_select).zfill(ENVIROMENTS_SIZE).encode("utf-8")
        enviroment_ = encrypt_message_salt_nonce(enviroment, key, salt, nonce) 
        # Nombre fichero
        filename = str(infile).split("/")[-1]
        filename = filename.ljust(FILENAME_SIZE).encode("utf-8")
        filename_ = encrypt_message_salt_nonce(filename, key, salt, nonce) 
        # Num orden de bloque
        blocks = str(0).zfill(N_BLOCK_SIZE).encode("utf-8")
        blocks_ = encrypt_message_salt_nonce(blocks, key, salt, nonce) 
        # Total blocks
        total_blocks = str(0).zfill(N_TOTAL_SIZE).encode("utf-8")
        total_blocks_ = encrypt_message_salt_nonce(total_blocks, key, salt, nonce) 
        # Longitud del mensaje en el bloque tamaño del bloque 0 --> bloque vacío
        length = str(0).zfill(N_LENGTH_SIZE).encode("utf-8")
        length_ = encrypt_message_salt_nonce(length, key, salt, nonce) 
        # Mensaje cifrado con el padding de random data para completar el tamaño del bloque 
        cipher = os.urandom(DATA_SIZE)
        # Calculo del checksum de la data del bloque 
        checksum = calculate_crc32(cipher) 
        checksum_ = encrypt_message_salt_nonce(checksum.to_bytes(CHECKSUM_SIZE, 'big'), key, salt, nonce)
        
        # Bloque completo 
        block_complete = enviroment_ + filename_ + blocks_ + total_blocks_ + length_  + cipher + checksum_
        # Introducimos los datos al final del fichero
        append_data(block_complete, path)



# Metodo para insertar un fichero dentro del fichero contenedor con una clave
def set_file(path, key, enviroment_select, infile, root_mount):
    with open(infile,"r+b") as f:
        complete_file = f.read()
        # set_data(path, key, complete_file)
        message = complete_file
    salt, nonce = get_salt_nonce(path)
    if (".swap" != str(infile[-4:])):
        with open(path, "ab") as file:
            key_hashed = hashlib.sha256(key) 

            # El texto a guardar se divide en  funcion del tamaño del dato 
            plaintexts = split_bytes_into_segments(message, DATA_SIZE)
            # Las partes del mensaje cifrado 
            ciphertexts = []
            for plaintext in plaintexts:
                ciphertext = encrypt_message_salt_nonce(plaintext, key, salt, nonce)
                ciphertexts.append(ciphertext)
            ############ CREAR RUTINA PARA AÑADIR FICHEROS VACIOS HECHA
            n_block = 1
            if len(ciphertexts) == 0:
                # Enviroment
                enviroment = str(enviroment_select).zfill(ENVIROMENTS_SIZE).encode("utf-8")
                enviroment_ = encrypt_message_salt_nonce(enviroment, key, salt, nonce) 
                # Nombre fichero
                filename = str(infile).split("/")[-1]
                filename = filename.ljust(FILENAME_SIZE).encode("utf-8")
                filename_ = encrypt_message_salt_nonce(filename, key, salt, nonce) 
                # Num orden de bloque
                blocks = str(n_block).zfill(N_BLOCK_SIZE).encode("utf-8")
                blocks_ = encrypt_message_salt_nonce(blocks, key, salt, nonce) 
                # Total blocks
                total_blocks = str(len(ciphertexts)).zfill(N_TOTAL_SIZE).encode("utf-8")
                total_blocks_ = encrypt_message_salt_nonce(total_blocks, key, salt, nonce) 
                # Longitud del mensaje en el bloque tamaño del bloque 0 --> bloque vacío
                length = str(0).zfill(N_LENGTH_SIZE).encode("utf-8")
                length_ = encrypt_message_salt_nonce(length, key, salt, nonce) 
                # Mensaje cifrado con el padding de random data para completar el tamaño del bloque 
                cipher = os.urandom(DATA_SIZE)
                # Calculo del checksum de la data del bloque 
                checksum = calculate_crc32(cipher) 
                checksum_ = encrypt_message_salt_nonce(checksum.to_bytes(CHECKSUM_SIZE, 'big'), key, salt, nonce)
                
                # Bloque completo 
                block_complete = enviroment_ + filename_ + blocks_ + total_blocks_ + length_  + cipher + checksum_
                # Introducimos los datos al final del fichero
                append_data(block_complete, path)




                # Introducimos data random al fichero
                # rand_data = randint(MIN_RANDOM_DATA, MID_RANDOM_DATA)
                # dunce_data(path, rand_data)

            else:
                # El inicio de los bloques siempre es 1 ## TODO hay utilizarlo para el seteo aleatorio y para la acumulación de mensajes, actualmente si se actualiza un mensaje, se empiza con el n_block = 1  y es un error
                for cipher in ciphertexts:

                    if(len(cipher) < DATA_SIZE):
                        

                        # Enviroment
                        enviroment = str(enviroment_select).zfill(ENVIROMENTS_SIZE).encode("utf-8")
                        enviroment_ = encrypt_message_salt_nonce(enviroment, key, salt, nonce) 
                        # Nombre fichero
                        filename = str(infile).split("/")[-1]
                        filename = filename.ljust(FILENAME_SIZE).encode("utf-8")
                        filename_ = encrypt_message_salt_nonce(filename, key, salt, nonce) 
                        # Num orden de bloque
                        blocks = str(n_block).zfill(N_BLOCK_SIZE).encode("utf-8")
                        blocks_ = encrypt_message_salt_nonce(blocks, key, salt, nonce) 
                        # Total blocks
                        total_blocks = str(len(ciphertexts)).zfill(N_TOTAL_SIZE).encode("utf-8")
                        total_blocks_ = encrypt_message_salt_nonce(total_blocks, key, salt, nonce) 
                        # Longitud del mensaje en el bloque
                        length = str(len(cipher)).zfill(N_LENGTH_SIZE).encode("utf-8")
                        length_ = encrypt_message_salt_nonce(length, key, salt, nonce) 
                        # Mensaje cifrado con el padding de random data para completar el tamaño del bloque 
                        cipher = cipher + os.urandom(DATA_SIZE - len(cipher))
                        # Calculo del checksum de la data del bloque 
                        checksum = calculate_crc32(cipher) 
                        checksum_ = encrypt_message_salt_nonce(checksum.to_bytes(CHECKSUM_SIZE, 'big'), key, salt, nonce)
                        
                        # Bloque completo 
                        block_complete = enviroment_ + filename_ + blocks_ + total_blocks_ + length_  + cipher + checksum_
                        # Introducimos los datos al final del fichero
                        append_data(block_complete, path)




                        # Introducimos data random al fichero
                        # rand_data = randint(MIN_RANDOM_DATA, MID_RANDOM_DATA)
                        # dunce_data(path, rand_data)


                    else:

                        # Enviroment
                        enviroment = str(enviroment_select).zfill(ENVIROMENTS_SIZE).encode("utf-8")
                        enviroment_ = encrypt_message_salt_nonce(enviroment, key, salt, nonce) 
                        # Nombre fichero
                        filename = str(infile).split("/")[-1]
                        filename = filename.ljust(FILENAME_SIZE).encode("utf-8")
                        filename_ = encrypt_message_salt_nonce(filename, key, salt, nonce) 
                        # Num orden de bloque
                        blocks = str(n_block).zfill(N_BLOCK_SIZE).encode("utf-8")
                        blocks_ = encrypt_message_salt_nonce(blocks, key, salt, nonce) 
                        # Total blocks
                        total_blocks = str(len(ciphertexts)).zfill(N_TOTAL_SIZE).encode("utf-8")
                        total_blocks_ = encrypt_message_salt_nonce(total_blocks, key, salt, nonce)
                        # Longitud del mensaje en el bloque
                        length = str(len(cipher)).zfill(N_LENGTH_SIZE).encode("utf-8")
                        length_ = encrypt_message_salt_nonce(length, key, salt, nonce)
                        # Mensaje cifrado SIN padding 
                        cipher = cipher 
                        # Calculo del checksum de la data del bloque 
                        checksum = calculate_crc32(cipher)
                        checksum_ = encrypt_message_salt_nonce(checksum.to_bytes(CHECKSUM_SIZE, 'big'), key, salt, nonce)

                        # Bloque completo 
                        block_complete = enviroment_ + filename_ + blocks_ + total_blocks_ + length_  + cipher + checksum_
                        # Introducimos los datos al final del fichero
                        append_data(block_complete, path)



                        # Introducimos data random al fichero
                        # rand_data = randint(MIN_RANDOM_DATA, MID_RANDOM_DATA)
                        # dunce_data(path, rand_data)



                    n_block+=1 # Aumento del número de bloque 


def get_enviroment(path, key):
    
    
    with open(path, "rb") as file:
        # Fichero completo 
        data = file.read()
        tamaño_bytes = len(data)
        n_bloques = (tamaño_bytes - NONCE_SIZE - SALT_SIZE - (NUMBER_KEYS * MASTER_KEY_SIZE)) / BLOCK_SIZE
        key_hashed = hashlib.sha256(key) # Clave hasheada con sha256
    
        index = 32 # Primer byte de la primera clave
        indexes = [] # Guardar los indices donde se encuentran los hashes
        enviroment_number = 0
        for i in range(1, NUMBER_KEYS + 1):
            # Mover el cursor al indice siguiente
            file.seek(index)
            data = file.read(MASTER_KEY_SIZE) # Se leen 32B para descifrar la clave master
            if not data:  # Fin del archivo
                break
            if key_hashed.digest() in data:
                indexes.append(index + data.index(key_hashed.digest())) # Índice de inicio de la secuencia
                enviroment_number = i 
            index += SHA_MASTER_KEY_SIZE # Busqueda byte a byte, no es eficiente en ficheros grandes, hay que mejorar la búsqueda
        
            
    return enviroment_number

def get_master_key(path, key, enviroment):
    
    salt, nonce = get_salt_nonce(path)
    data = []
    
    with open(path, "r+b") as file:
        if enviroment == 1:
            file.seek(NONCE_SIZE+ SALT_SIZE + MASTER_KEY_SIZE)
        elif enviroment == 2:
            file.seek(NONCE_SIZE + SALT_SIZE + MASTER_KEY_SIZE + SHA_MASTER_KEY_SIZE)
        master_rec = file.read(MASTER_KEY_SIZE)
        file.close()

    master_rec = decrypt_message(salt, nonce, master_rec, key)
    

    return master_rec


def get_path_files(path, key, enviroment_select, outpath):
    # Seleccionar la salt y el nonce del fichero
    salt, nonce = get_salt_nonce(path)
    with open(path, "r+b") as file:
        # Se buscan las posiciones donde hay bloques 
        indexes = search_blocks(path,enviroment_select, key)
        # Contenedor de todos los mensajes de los bloques con la clave indicada
        total_files = []
        total_lengths = []
        total_message = []

        for index in indexes:
            # Cursor en el inicio del bloque
            file.seek(index)
            # Lectura del bloque completo
            block = file.read(BLOCK_SIZE)
            # Enviroment
            enviroment_cipher = block[FIRST_INDEX : ENVIROMENTS_SIZE]
            enviroment_plaintext = decrypt_message(salt, nonce, enviroment_cipher, key)
            enviroment_plaintext = int(enviroment_plaintext.decode("utf-8"))
            # print("enviroment:")
            # print(enviroment_plaintext)
            # if enviroment_plaintext != enviroment_select and enviroment_plaintext != COMMON_ENVIROMENT_VALUE:
            #     continue
            # Extraer el nombre del fichero
            filename_cipher = block[ENVIROMENTS_SIZE : ENVIROMENTS_SIZE + FILENAME_SIZE]
            filename_plaintext = decrypt_message(salt, nonce, filename_cipher, key)
            filename_plaintext = str(filename_plaintext.decode("utf-8")).strip()
            # Extraer la metadata del numero de bloque
            n_block_cipher = block[ENVIROMENTS_SIZE + FILENAME_SIZE: ENVIROMENTS_SIZE + FILENAME_SIZE + N_BLOCK_SIZE]
            n_block_plaintext = decrypt_message(salt, nonce, n_block_cipher, key)
            n_block_plaintext = int(n_block_plaintext.decode("utf-8"))
            # Extraer la metadata del total de bloques
            total_blocks_cipher = block[ENVIROMENTS_SIZE + FILENAME_SIZE + N_BLOCK_SIZE: ENVIROMENTS_SIZE + FILENAME_SIZE +  N_BLOCK_SIZE + N_TOTAL_SIZE]
            total_blocks_plaintext = decrypt_message(salt, nonce, total_blocks_cipher, key)
            total_blocks_plaintext = int(total_blocks_plaintext.decode("utf-8"))
            # print(total_blocks_plaintext)
            # print(type(total_blocks_plaintext))
            # Extraer la metadata de la longitud de la data del mensaje en el bloque
            length_cipher = block[ENVIROMENTS_SIZE + FILENAME_SIZE +  N_BLOCK_SIZE + N_TOTAL_SIZE : ENVIROMENTS_SIZE + FILENAME_SIZE +  N_BLOCK_SIZE + N_TOTAL_SIZE + N_LENGTH_SIZE]
            length_plaintext = decrypt_message(salt, nonce, length_cipher, key)
            length_plaintext = int(length_plaintext.decode("utf-8"))
            
            # Extraer la data del mensaje 
            message = block[ENVIROMENTS_SIZE + FILENAME_SIZE +  N_BLOCK_SIZE + N_TOTAL_SIZE + N_LENGTH_SIZE : ENVIROMENTS_SIZE + FILENAME_SIZE +  N_BLOCK_SIZE + N_TOTAL_SIZE + N_LENGTH_SIZE + DATA_SIZE]
            # Extraer el checksum de la data del bloque
            crc = block[ENVIROMENTS_SIZE + FILENAME_SIZE +  N_BLOCK_SIZE + N_TOTAL_SIZE + N_LENGTH_SIZE + DATA_SIZE : ENVIROMENTS_SIZE + FILENAME_SIZE +  N_BLOCK_SIZE + N_TOTAL_SIZE + N_LENGTH_SIZE + DATA_SIZE + CHECKSUM_SIZE]
            crc_plaintext = decrypt_message(salt, nonce, crc, key)
            crc_plaintext = int.from_bytes(crc_plaintext, byteorder='big')
            
            
            if (is_crc32_valid(message, crc_plaintext)):
                if total_blocks_plaintext == n_block_plaintext:
                    if enviroment_select == enviroment_plaintext or enviroment_plaintext == COMMON_ENVIROMENT_VALUE:
                        if (filename_plaintext != "random"):
                            total_files.append(filename_plaintext)
                            total_lengths.append(length_plaintext)
                # plaintext = decrypt_message(salt, nonce, message, key)
                # plaintext = plaintext[FIRST_INDEX:length_plaintext]
                # total_message.append(plaintext)
            else:
                print("CRC No Válido")
    
    # Para crear el fichero
    # with open(outpath, "w+b") as file:
    #     file.write(total_planintext)
    # print(total_message)
    return total_files, total_lengths
    # mount(outpath, "/mnt/ext4")
def get_file(path, key, enviroment_select, outpath, root_dir):
    
    # Seleccionar la salt y el nonce del fichero
    salt, nonce = get_salt_nonce(path)
    with open(path, "r+b") as file:
        # Se buscan las posiciones donde hay bloques 
        indexes = search_blocks(path, enviroment_select, key)
        # Contenedor de todos los mensajes de los bloques con la clave indicada
        total_files = []
        total_message = []
        total_planintext = b""

        for index in indexes:
            # Cursor en el inicio del bloque
            file.seek(index)
            # Lectura del bloque completo
            block = file.read(BLOCK_SIZE)
            # Enviroment
            enviroment_cipher = block[FIRST_INDEX : ENVIROMENTS_SIZE]
            enviroment_plaintext = decrypt_message(salt, nonce, enviroment_cipher, key)
            enviroment_plaintext = int(enviroment_plaintext.decode("utf-8"))
            # print("enviroment:")
            # print(enviroment_plaintext)
            # if enviroment_plaintext != enviroment_select and enviroment_plaintext != COMMON_ENVIROMENT_VALUE:
            #     continue
            # Extraer el nombre del fichero
            filename_cipher = block[ENVIROMENTS_SIZE : ENVIROMENTS_SIZE + FILENAME_SIZE]
            filename_plaintext = decrypt_message(salt, nonce, filename_cipher, key)
            filename_plaintext = str(filename_plaintext.decode("utf-8")).strip()
            # Extraer la metadata del numero de bloque
            n_block_cipher = block[ENVIROMENTS_SIZE + FILENAME_SIZE: ENVIROMENTS_SIZE + FILENAME_SIZE + N_BLOCK_SIZE]
            n_block_plaintext = decrypt_message(salt, nonce, n_block_cipher, key)
            n_block_plaintext = int(n_block_plaintext.decode("utf-8"))
            # Extraer la metadata del total de bloques
            total_blocks_cipher = block[ENVIROMENTS_SIZE + FILENAME_SIZE + N_BLOCK_SIZE: ENVIROMENTS_SIZE + FILENAME_SIZE +  N_BLOCK_SIZE + N_TOTAL_SIZE]
            total_blocks_plaintext = decrypt_message(salt, nonce, total_blocks_cipher, key)
            total_blocks_plaintext = int(total_blocks_plaintext.decode("utf-8"))
            # print(total_blocks_plaintext)
            # print(type(total_blocks_plaintext))
            # Extraer la metadata de la longitud de la data del mensaje en el bloque
            length_cipher = block[ENVIROMENTS_SIZE + FILENAME_SIZE +  N_BLOCK_SIZE + N_TOTAL_SIZE : ENVIROMENTS_SIZE + FILENAME_SIZE +  N_BLOCK_SIZE + N_TOTAL_SIZE + N_LENGTH_SIZE]
            length_plaintext = decrypt_message(salt, nonce, length_cipher, key)
            length_plaintext = int(length_plaintext.decode("utf-8"))

            
            # Extraer la data del mensaje 
            message = block[ENVIROMENTS_SIZE + FILENAME_SIZE +  N_BLOCK_SIZE + N_TOTAL_SIZE + N_LENGTH_SIZE : ENVIROMENTS_SIZE + FILENAME_SIZE +  N_BLOCK_SIZE + N_TOTAL_SIZE + N_LENGTH_SIZE + DATA_SIZE]
            # Extraer el checksum de la data del bloque
            crc = block[ENVIROMENTS_SIZE + FILENAME_SIZE +  N_BLOCK_SIZE + N_TOTAL_SIZE + N_LENGTH_SIZE + DATA_SIZE : ENVIROMENTS_SIZE + FILENAME_SIZE +  N_BLOCK_SIZE + N_TOTAL_SIZE + N_LENGTH_SIZE + DATA_SIZE + CHECKSUM_SIZE]
            crc_plaintext = decrypt_message(salt, nonce, crc, key)
            crc_plaintext = int.from_bytes(crc_plaintext, byteorder='big')
            


            if enviroment_plaintext == enviroment_select or enviroment_plaintext == COMMON_ENVIROMENT_VALUE:
                if (is_crc32_valid(message, crc_plaintext)):
                    if(outpath == filename_plaintext):
                        if n_block_plaintext == total_blocks_plaintext:
                            total_files.append(filename_plaintext)
                            plaintext = decrypt_message(salt, nonce, message, key)
                            plaintext = plaintext[FIRST_INDEX:length_plaintext]
                            total_message.append(plaintext)
                            
                            break
                        else:
                            plaintext = decrypt_message(salt, nonce, message, key)
                            plaintext = plaintext[FIRST_INDEX:length_plaintext]
                            total_message.append(plaintext)


                else:
                    print("CRC No Válido")
    
        for message in total_message:
            print(type(message))
            total_planintext += message
        print(root_dir + "/" + outpath)
        # if (root_dir[-1:] == "/" and outpath[0] != "/") or (root_dir[-1:] == "/" and outpath[:2] != "./"):
        create_file(total_planintext, root_dir + "/" + outpath)
        # elif (root_dir[-1:] == "/" and outpath[0] == "/"):
        #     create_file(total_planintext, root_dir + outpath[1:])
        # elif (root_dir[-1:] == "/" and outpath[:2] == "./"):
        #     create_file(total_planintext, root_dir + outpath[2:])
        # elif (root_dir[-1:] != "/" and outpath[0] != "/") or (root_dir[-1:] != "/" and outpath[:2] != "./"):
        #     create_file(total_planintext, root_dir + "/" + outpath)
        # elif (root_dir[-1:] != "/" and outpath[] == "/"):
        #     create_file(total_planintext, root_dir + outpath[1:])
            
    return total_planintext



def get_file_open(path, key, enviroment_select, outpath, root_dir):
    
    # Seleccionar la salt y el nonce del fichero
    salt, nonce = get_salt_nonce(path)
    with open(path, "r+b") as file:
        # Se buscan las posiciones donde hay bloques 
        indexes = search_blocks(path, enviroment_select, key)
        # Contenedor de todos los mensajes de los bloques con la clave indicada
        total_files = []
        total_message = []
        total_planintext = b""

        for index in indexes:
            # Cursor en el inicio del bloque
            file.seek(index)
            # Lectura del bloque completo
            block = file.read(BLOCK_SIZE)
            # Enviroment
            enviroment_cipher = block[FIRST_INDEX : ENVIROMENTS_SIZE]
            enviroment_plaintext = decrypt_message(salt, nonce, enviroment_cipher, key)
            enviroment_plaintext = int(enviroment_plaintext.decode("utf-8"))
            # print("enviroment:")
            # print(enviroment_plaintext)
            # if enviroment_plaintext != enviroment_select and enviroment_plaintext != COMMON_ENVIROMENT_VALUE:
            #     continue
            # Extraer el nombre del fichero
            filename_cipher = block[ENVIROMENTS_SIZE : ENVIROMENTS_SIZE + FILENAME_SIZE]
            filename_plaintext = decrypt_message(salt, nonce, filename_cipher, key)
            filename_plaintext = str(filename_plaintext.decode("utf-8")).strip()
            # Extraer la metadata del numero de bloque
            n_block_cipher = block[ENVIROMENTS_SIZE + FILENAME_SIZE: ENVIROMENTS_SIZE + FILENAME_SIZE + N_BLOCK_SIZE]
            n_block_plaintext = decrypt_message(salt, nonce, n_block_cipher, key)
            n_block_plaintext = int(n_block_plaintext.decode("utf-8"))
            # Extraer la metadata del total de bloques
            total_blocks_cipher = block[ENVIROMENTS_SIZE + FILENAME_SIZE + N_BLOCK_SIZE: ENVIROMENTS_SIZE + FILENAME_SIZE +  N_BLOCK_SIZE + N_TOTAL_SIZE]
            total_blocks_plaintext = decrypt_message(salt, nonce, total_blocks_cipher, key)
            total_blocks_plaintext = int(total_blocks_plaintext.decode("utf-8"))
            # print(total_blocks_plaintext)
            # print(type(total_blocks_plaintext))
            # Extraer la metadata de la longitud de la data del mensaje en el bloque
            length_cipher = block[ENVIROMENTS_SIZE + FILENAME_SIZE +  N_BLOCK_SIZE + N_TOTAL_SIZE : ENVIROMENTS_SIZE + FILENAME_SIZE +  N_BLOCK_SIZE + N_TOTAL_SIZE + N_LENGTH_SIZE]
            length_plaintext = decrypt_message(salt, nonce, length_cipher, key)
            length_plaintext = int(length_plaintext.decode("utf-8"))

            
            # Extraer la data del mensaje 
            message = block[ENVIROMENTS_SIZE + FILENAME_SIZE +  N_BLOCK_SIZE + N_TOTAL_SIZE + N_LENGTH_SIZE : ENVIROMENTS_SIZE + FILENAME_SIZE +  N_BLOCK_SIZE + N_TOTAL_SIZE + N_LENGTH_SIZE + DATA_SIZE]
            # Extraer el checksum de la data del bloque
            crc = block[ENVIROMENTS_SIZE + FILENAME_SIZE +  N_BLOCK_SIZE + N_TOTAL_SIZE + N_LENGTH_SIZE + DATA_SIZE : ENVIROMENTS_SIZE + FILENAME_SIZE +  N_BLOCK_SIZE + N_TOTAL_SIZE + N_LENGTH_SIZE + DATA_SIZE + CHECKSUM_SIZE]
            crc_plaintext = decrypt_message(salt, nonce, crc, key)
            crc_plaintext = int.from_bytes(crc_plaintext, byteorder='big')
            


            if enviroment_plaintext == enviroment_select or enviroment_plaintext == COMMON_ENVIROMENT_VALUE:
                if (is_crc32_valid(message, crc_plaintext)):
                    if(outpath[1:] == filename_plaintext):
                        if n_block_plaintext == total_blocks_plaintext:
                            total_files.append(filename_plaintext)
                            plaintext = decrypt_message(salt, nonce, message, key)
                            plaintext = plaintext[FIRST_INDEX:length_plaintext]
                            total_message.append(plaintext)
                            
                            break
                        else:
                            plaintext = decrypt_message(salt, nonce, message, key)
                            plaintext = plaintext[FIRST_INDEX:length_plaintext]
                            total_message.append(plaintext)


                else:
                    print("CRC No Válido")
    
        for message in total_message:
            print(type(message))
            total_planintext += message
        print(root_dir + outpath)
        create_file(total_planintext, root_dir + outpath)
    return total_planintext

# Funcion para crear los ficheros guardados
def create_file(data, outpath):
    # Para crear el fichero
    with open(outpath, "w+b") as file:
        file.write(data)
        file.close()


def borrar_bytes_archivo(container_file, indexes, key, enviroment):
    indexes.sort(reverse=True)
    with open(container_file, 'r+b') as file:
        for index in indexes:
            # Calculo del offset final del bloque que hay que borrar
            end_index = index + BLOCK_SIZE
            # Leer el contenido completo del container_file
            contenido = bytearray(file.read())

            # Eliminar el rango de bytes del contenido
            del contenido[index:end_index]

            # Volver al inicio del container_file y escribir el contenido modificado
            file.seek(0)
            file.write(contenido)

            # Truncar el archivo a la nueva longitud
            file.truncate(len(contenido))

def search_index_filename_common_enviroment(path, key, filename, enviroment_select):
    salt, nonce = get_salt_nonce(path)
    
    with open(path, "rb") as file:
        data = file.read()
        tamaño_bytes = len(data)
        data_bloques = tamaño_bytes - NONCE_SIZE - SALT_SIZE - (NUMBER_KEYS * SHA_MASTER_KEY_SIZE)
        n_bloques = int((tamaño_bytes - NONCE_SIZE - SALT_SIZE - (NUMBER_KEYS * SHA_MASTER_KEY_SIZE)) / BLOCK_SIZE)


        # Fichero completo 
        key_hashed = hashlib.sha256(key) # Clave hasheada con sha256
        index = NONCE_SIZE + SALT_SIZE + (NUMBER_KEYS * SHA_MASTER_KEY_SIZE) # Primer byte despues de la metadata inicial
        indexes = [] 
        for i in range(n_bloques):
            # print("INDEX: " + str(index))
            # Mover el cursor al indice siguiente
            file.seek(index)
            # data = file.read(KEY_HASH_SIZE) # Se leen 32B para compararlos con la clave hasheada

            if not data:  # Fin del archivo
                break
            else:
                # print(filename)
                # Cursor en el inicio del bloque
                file.seek(index)
                # Lectura del bloque completo
                block = file.read(BLOCK_SIZE)
                # Enviroment
                enviroment_cipher = block[FIRST_INDEX : ENVIROMENTS_SIZE]
                enviroment_plaintext = decrypt_message(salt, nonce, enviroment_cipher, key)
                enviroment_plaintext = int(enviroment_plaintext.decode("utf-8"))
                # if enviroment_plaintext != enviroment_select and enviroment_plaintext != COMMON_ENVIROMENT_VALUE:
                #     continue
                # Extraer el nombre del fichero
                filename_cipher = block[ENVIROMENTS_SIZE : ENVIROMENTS_SIZE + FILENAME_SIZE]
                filename_plaintext = decrypt_message(salt, nonce, filename_cipher, key)
                filename_plaintext = str(filename_plaintext.decode("utf-8")).strip()
                # print("FILENAME: " + str(filename_plaintext))
                

                # Extraer la metadata del numero de bloque
                n_block_cipher = block[ENVIROMENTS_SIZE + FILENAME_SIZE: ENVIROMENTS_SIZE + FILENAME_SIZE + N_BLOCK_SIZE]
                n_block_plaintext = decrypt_message(salt, nonce, n_block_cipher, key)
                n_block_plaintext = int(n_block_plaintext.decode("utf-8"))
                # Extraer la metadata del total de bloques
                total_blocks_cipher = block[ENVIROMENTS_SIZE + FILENAME_SIZE + N_BLOCK_SIZE: ENVIROMENTS_SIZE + FILENAME_SIZE +  N_BLOCK_SIZE + N_TOTAL_SIZE]
                total_blocks_plaintext = decrypt_message(salt, nonce, total_blocks_cipher, key)
                total_blocks_plaintext = int(total_blocks_plaintext.decode("utf-8"))
                # Extraer la metadata de la longitud de la data del mensaje en el bloque
                length_cipher = block[ENVIROMENTS_SIZE + FILENAME_SIZE +  N_BLOCK_SIZE + N_TOTAL_SIZE : ENVIROMENTS_SIZE + FILENAME_SIZE +  N_BLOCK_SIZE + N_TOTAL_SIZE + N_LENGTH_SIZE]
                length_plaintext = decrypt_message(salt, nonce, length_cipher, key)
                length_plaintext = int(length_plaintext.decode("utf-8"))
                # Extraer la data del mensaje 
                message = block[ENVIROMENTS_SIZE + FILENAME_SIZE +  N_BLOCK_SIZE + N_TOTAL_SIZE + N_LENGTH_SIZE : ENVIROMENTS_SIZE + FILENAME_SIZE +  N_BLOCK_SIZE + N_TOTAL_SIZE + N_LENGTH_SIZE + DATA_SIZE]
                # Extraer el checksum de la data del bloque
                crc = block[ENVIROMENTS_SIZE + FILENAME_SIZE +  N_BLOCK_SIZE + N_TOTAL_SIZE + N_LENGTH_SIZE + DATA_SIZE : ENVIROMENTS_SIZE + FILENAME_SIZE +  N_BLOCK_SIZE + N_TOTAL_SIZE + N_LENGTH_SIZE + DATA_SIZE + CHECKSUM_SIZE]
                crc_plaintext = decrypt_message(salt, nonce, crc, key)
                crc_plaintext = int.from_bytes(crc_plaintext, byteorder='big')
                
                enviroment_change = COMMON_ENVIROMENT_VALUE


                if enviroment_plaintext == enviroment_select:
                    if filename_plaintext == filename:
                        indexes.append(index) # Índice de inicio de la secuencia
                        if total_blocks_plaintext == n_block_plaintext:
                            break
                elif  enviroment_plaintext == COMMON_ENVIROMENT_VALUE:
                    if filename_plaintext == filename:
                        indexes.append(index) # Índice de inicio de la secuencia
                        if enviroment_select == FIRST_ENVIROMENT_VALUE:
                            enviroment_change = SECOND_ENVIROMENT_VALUE
                        elif enviroment_select == SECOND_ENVIROMENT_VALUE:
                            enviroment_change = FIRST_ENVIROMENT_VALUE
                        if total_blocks_plaintext == n_block_plaintext:
                            break
            index += BLOCK_SIZE # Busqueda por cada bloque
            
    return indexes, enviroment_change

def search_index_filename(path, key, filename, enviroment_select):
    salt, nonce = get_salt_nonce(path)
    
    with open(path, "rb") as file:
        data = file.read()
        tamaño_bytes = len(data)
        data_bloques = tamaño_bytes - NONCE_SIZE - SALT_SIZE - (NUMBER_KEYS * SHA_MASTER_KEY_SIZE)
        n_bloques = int((tamaño_bytes - NONCE_SIZE - SALT_SIZE - (NUMBER_KEYS * SHA_MASTER_KEY_SIZE)) / BLOCK_SIZE)


        # Fichero completo 
        key_hashed = hashlib.sha256(key) # Clave hasheada con sha256
        index = NONCE_SIZE + SALT_SIZE + (NUMBER_KEYS * SHA_MASTER_KEY_SIZE) # Primer byte despues de la metadata inicial
        indexes = [] 
        enviroment_return = None
        for i in range(n_bloques):
            # print("INDEX: " + str(index))
            # Mover el cursor al indice siguiente
            file.seek(index)
            # data = file.read(KEY_HASH_SIZE) # Se leen 32B para compararlos con la clave hasheada

            if not data:  # Fin del archivo
                break
            else:
                # print(filename)
                # Cursor en el inicio del bloque
                file.seek(index)
                # Lectura del bloque completo
                block = file.read(BLOCK_SIZE)
                # Enviroment
                enviroment_cipher = block[FIRST_INDEX : ENVIROMENTS_SIZE]
                enviroment_plaintext = decrypt_message(salt, nonce, enviroment_cipher, key)
                enviroment_plaintext = int(enviroment_plaintext.decode("utf-8"))
                # if enviroment_plaintext != enviroment_select and enviroment_plaintext != COMMON_ENVIROMENT_VALUE:
                #     continue
                # Extraer el nombre del fichero
                filename_cipher = block[ENVIROMENTS_SIZE : ENVIROMENTS_SIZE + FILENAME_SIZE]
                filename_plaintext = decrypt_message(salt, nonce, filename_cipher, key)
                filename_plaintext = str(filename_plaintext.decode("utf-8")).strip()
                # print("FILENAME: " + str(filename_plaintext))
                

                # Extraer la metadata del numero de bloque
                n_block_cipher = block[ENVIROMENTS_SIZE + FILENAME_SIZE: ENVIROMENTS_SIZE + FILENAME_SIZE + N_BLOCK_SIZE]
                n_block_plaintext = decrypt_message(salt, nonce, n_block_cipher, key)
                n_block_plaintext = int(n_block_plaintext.decode("utf-8"))
                # Extraer la metadata del total de bloques
                total_blocks_cipher = block[ENVIROMENTS_SIZE + FILENAME_SIZE + N_BLOCK_SIZE: ENVIROMENTS_SIZE + FILENAME_SIZE +  N_BLOCK_SIZE + N_TOTAL_SIZE]
                total_blocks_plaintext = decrypt_message(salt, nonce, total_blocks_cipher, key)
                total_blocks_plaintext = int(total_blocks_plaintext.decode("utf-8"))
                # Extraer la metadata de la longitud de la data del mensaje en el bloque
                length_cipher = block[ENVIROMENTS_SIZE + FILENAME_SIZE +  N_BLOCK_SIZE + N_TOTAL_SIZE : ENVIROMENTS_SIZE + FILENAME_SIZE +  N_BLOCK_SIZE + N_TOTAL_SIZE + N_LENGTH_SIZE]
                length_plaintext = decrypt_message(salt, nonce, length_cipher, key)
                length_plaintext = int(length_plaintext.decode("utf-8"))
                # Extraer la data del mensaje 
                message = block[ENVIROMENTS_SIZE + FILENAME_SIZE +  N_BLOCK_SIZE + N_TOTAL_SIZE + N_LENGTH_SIZE : ENVIROMENTS_SIZE + FILENAME_SIZE +  N_BLOCK_SIZE + N_TOTAL_SIZE + N_LENGTH_SIZE + DATA_SIZE]
                # Extraer el checksum de la data del bloque
                crc = block[ENVIROMENTS_SIZE + FILENAME_SIZE +  N_BLOCK_SIZE + N_TOTAL_SIZE + N_LENGTH_SIZE + DATA_SIZE : ENVIROMENTS_SIZE + FILENAME_SIZE +  N_BLOCK_SIZE + N_TOTAL_SIZE + N_LENGTH_SIZE + DATA_SIZE + CHECKSUM_SIZE]
                crc_plaintext = decrypt_message(salt, nonce, crc, key)
                crc_plaintext = int.from_bytes(crc_plaintext, byteorder='big')

                enviroment_return = None
                if enviroment_plaintext == enviroment_select or enviroment_plaintext == COMMON_ENVIROMENT_VALUE:
                    if filename_plaintext == filename:
                        indexes.append(index) # Índice de inicio de la secuencia
                        if total_blocks_plaintext == n_block_plaintext:
                            enviroment_return = enviroment_plaintext
                            break
                
            index += BLOCK_SIZE # Busqueda por cada bloque
            
    return indexes, enviroment_return

def remove_file_container_filename(container_file, key, filename, enviroment, root_mount):
    salt, nonce = get_salt_nonce(container_file)
    indexes = []
    enviroment_change = COMMON_ENVIROMENT_VALUE
    
    indexes, enviroment_return = search_index_filename(container_file, key, filename, enviroment)

    if not indexes:
        return False, enviroment_return
    else: 
        borrar_bytes_archivo(container_file, indexes, key, enviroment)
        return True, enviroment_return



def remove_file_container_filename_common_enviroment(container_file, key, filename, enviroment, root_mount):
    salt, nonce = get_salt_nonce(container_file)
    indexes = []
    enviroment_change = COMMON_ENVIROMENT_VALUE
    
    indexes, enviroment_change = search_index_filename_common_enviroment(container_file, key, filename, enviroment)

    if not indexes:
        return False

    elif enviroment_change != COMMON_ENVIROMENT_VALUE:
        ### CAMBIO ENVIROMENT RUTINA TODO

        get_file_open(container_file, key, enviroment, filename, root_mount,)
        # REMOVE FILE COMMON ENVIROMENT
        borrar_bytes_archivo(container_file, indexes, key, COMMON_ENVIROMENT_VALUE)
        # ENVIROMENT CHANGE
        set_file(container_file, key, enviroment_change, filename, root_mount)

        open_empty_file(container_file, key, root_mount + filename)
        borrar_contenido_carpeta(root_mount)
        print("COMMON ENVIROMENT CHANGE FILE")

        return True
    elif enviroment_change == COMMON_ENVIROMENT_VALUE: 
        borrar_bytes_archivo(container_file, indexes, key, enviroment)
        return True


def open_empty_file(path, key, outpath):
    # Seleccionar la salt y el nonce del fichero
    # if (".swp" not in outpath):
    plaintext = b" "
    create_file(plaintext, outpath)

def borrar_contenido_carpeta(carpeta):
    # Verificar si la carpeta existe
    if not os.path.exists(carpeta):
        # print(f"La carpeta '{carpeta}' no existe.")
        return

    try:
        # Recorrer los elementos de la carpeta
        for nombre_archivo in os.listdir(carpeta):
            ruta_archivo = os.path.join(carpeta, nombre_archivo)

            if os.path.isfile(ruta_archivo):
                # Borrar archivo
                os.remove(ruta_archivo)
            elif os.path.isdir(ruta_archivo):
                # Borrar directorio recursivamente
                shutil.rmtree(ruta_archivo)

        # print(f"El contenido de la carpeta '{carpeta}' ha sido borrado exitosamente.")

    except Exception as e:
        print(f"Se produjo un error al borrar el contenido de la carpeta '{carpeta}': {str(e)}")



def search_blocks(path, enviroment, key):

    # Seleccionar la salt y el nonce del fichero
    salt, nonce = get_salt_nonce(path)
    with open(path, "r+b") as file:
        tamaño_bytes = len(file.read())
        data_bloques = tamaño_bytes - NONCE_SIZE - SALT_SIZE - (NUMBER_KEYS * SHA_MASTER_KEY_SIZE)
        n_bloques = int((tamaño_bytes - NONCE_SIZE - SALT_SIZE - (NUMBER_KEYS * SHA_MASTER_KEY_SIZE)) / BLOCK_SIZE)
        first_offset = tamaño_bytes - data_bloques
        ofsets = []
        for i in range(n_bloques):
            if i != 0:
                first_offset = first_offset + BLOCK_SIZE
            ofsets.append(first_offset) 
            
    return ofsets


def obtain_file_paths(directorio):
    rutas_archivos = []

    for directorio_actual, _, archivos in os.walk(directorio):
        for archivo in archivos:
            ruta_completa = os.path.join(directorio_actual, archivo)
            rutas_archivos.append(ruta_completa)

    return rutas_archivos


def gen_attr_data():
    data = {
        'st_atime': 0,
        'st_ctime': 0,
        'st_gid': 1000,
        'st_mode': 0,
        'st_mtime': 0,
        'st_nlink': 0,
        'st_size': 100,
        'st_uid': 0
    }
    return data


def main():
    print("main")
    path = "master_prueba.bin"
    # path = init(path) 
    # createfile(path)
    password = b"hola"
    # key_hashed = hashlib.sha256(password) # Clave hasheada con sha256
    # salt, nonce = get_salt_nonce(path)
    # print(salt)
    # print(binascii.hexlify(key_hashed.digest()).decode('utf-8'))
    # search(path, password, "")
    #### Pruebas
    # with open(path, "r+b") as file:
    #     tamaño_bytes = len(file.read())
    #     # tamaño_bytes = os.path.getsize(path)
    #     n_bloques = (tamaño_bytes - NONCE_SIZE - SALT_SIZE - (NUMBER_KEYS * MASTER_KEY_SIZE)) / BLOCK_SIZE
    #     print(tamaño_bytes)
    #     print(int(n_bloques))

    print("Enviroment: " + str(get_enviroment(path, password)))
    enviroment = get_enviroment(path, password)
    master = get_master_key(path, password, enviroment)
    print(binascii.hexlify(master).decode('utf-8'))
    print(get_file_open(path, master, enviroment, "/bin.py", "./fuse"))

    # indexes = search_index_filename(path, master, "crc32.py", enviroment)
    # boool = remove_file_container_filename(path, master, "bin.py", enviroment)
    # print(boool)

    # print(len(indexes))
    # print(indexes)
    # set_file(path, master, enviroment, "./binary.py", "")
    enviroment = 3
    # set_file(path, master, enviroment, "./bin.py", "")
    set_file(path, master, enviroment, "./crc32.py","")
    files = get_path_files(path, master, enviroment, "")
    print(files)
    # master = master_recovery(path, password)
    # salt = os.urandom(32)
    # master = get_pbkdf(os.urandom(32), salt)
    # salt, nonce = get_salt_nonce(path)
    # print(binascii.hexlify(nonce).decode('utf-8'))
    # print(binascii.hexlify(salt).decode('utf-8'))
    # print(binascii.hexlify(master).decode('utf-8'))
    # ofsets = search(path, enviroment, master)
    # print(ofsets)
    # # with open(path, "r+b") as file:
    # #     file.seek(NONCE_SIZE + SALT_SIZE)
    # #     file.write(master)
    # #     file.close()










    








    







if __name__ == "__main__":
    main()







