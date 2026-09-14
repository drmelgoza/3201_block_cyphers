from operator import truediv
from Crypto.Cipher import AES
import random

#Create a new key (or also an init vector) that is 128 bits long,
#then converts it to the bytes type used by AES
def get_new_key(size:int = 128) -> bytes:
    key = random.getrandbits(size)
    byte_key = key.to_bytes(16)
    return byte_key

def xor_operation(data:bytes, iv:bytes) -> bytes:
    int_data = int.from_bytes(data)
    int_iv = int.from_bytes(iv)
    xor_data = int_data ^ int_iv
    xor_bytes = xor_data.to_bytes(16)
    return xor_bytes

def encrypt_cbc(key, iv):
    return

def submit(input: str, key: bytes, iv: bytes) -> str:
    # URL encode ';' and '=': replace ';' and '=' with hex equivalents in url encoding
    clean_in = input.replace(";", "3%B").replace("=", "%3D")
    formatted_in = "userid=456;userdata=" + clean_in + ";session-id=31337"

    # convert string to mutable byte array
    byte_input = bytearray(formatted_in.encode("utf-8"))
    str_len = len(byte_input)

    # Apply PKCS#7 padding to 16-byte block boundaries
    if ((str_len % 16) == 0):
        pass
    else:
        # Apply PKCS#7 padding to 16-byte block boundaries
        bytes_remaining = str_len - ((byte_input // 16) * 16)
        pad_bytes_needed = 16 - bytes_remaining
        pad_byte = pad_bytes_needed.to_bytes(1, byteorder='big')
        padding = pad_byte * pad_bytes_needed
        byte_input = byte_input + padding
        
    # Encrypt with AES-128-CBC using the global key & IV
    num_blocks = byte_input/16
    cipher = AES.new(key, AES.MODE_ECB)
    #perform an xor operation on the 1st data chunk and the IV
    xor_bytes = xor_operation(byte_input, init_vector)
    #encrypt the xor'ed data
    encrypted_data = cipher.encrypt(xor_bytes)
    new_bmp += encrypted_data
    previous_block = encrypted_data
    blocks_read = 1
    while file_size - blocks_read * 16 >= 16:
        blocks_read += 1
        data = f.read(16)
        #before encrypting the data, an xor operation is first performed
        #using the previous encrypted 16 byte chunk of data
        xor_bytes = xor_operation(data, previous_block)
        encrypted_data = cipher.encrypt(xor_bytes)
        previous_block = encrypted_data
        new_bmp += encrypted_data

    # Return ciphertext

def verify(input: str) -> str:

def main():
    aes_key = get_new_key()
    aes_iv = get_new_key()

    user = input("Input text here")
