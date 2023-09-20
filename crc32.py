import binascii

# Metodo para calcular el checksum CRC32
def calculate_crc32(data):
    crc32_checksum = binascii.crc32(data)
    return crc32_checksum

# Metodo para comprobar el checksum 
def is_crc32_valid(data, crc32_checksum):
    calculated_checksum = calculate_crc32(data)
    return calculated_checksum == crc32_checksum