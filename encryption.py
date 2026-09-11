from Crypto.Cipher import AES
import random

#Create a new key that is 128 bits long,
#then converts it to the bytes type used by AES
def get_new_key(size=128):
    key = random.getrandbits(size)
    byte_key = key.to_bytes(16)
    return byte_key

#PART 1:
#TODO: ECB cypher
def encrypt_ecb(key, file="mustang.bmp"):
    cipher = AES.new(key, AES.MODE_ECB)
    with open(file, "br") as f:
        #get file size (in bytes) using seek method
        f.seek(0, 2)
        file_size = f.tell() - 54
        f.seek(0)
        #read file header and store for later
        new_bmp = f.read(54)
        blocks_read = 0
        #all in bytes, if not one whole block left, do padding
        while file_size - blocks_read * 16 > 16:
            blocks_read += 1
            data = f.read(16)
            encrypted_data = cipher.encrypt(data)
            new_bmp += encrypted_data

        if (file_size - blocks_read * 16) == 0:
            # do something with the file and make new file
            pass
        else:
            # execute padding to make file perfect.
            padded_data = f.read(16)
            bytes_remaining = file_size - blocks_read * 16
            pad_bytes = 16 - (bytes_remaining % 16)
            pad_byte = pad_bytes.to_bytes(1, byteorder='big')
            padding = pad_byte * pad_bytes
            padded_data += padding
            encrypted_data = cipher.encrypt(padded_data)
            new_bmp += encrypted_data

    with open('mustang_encrypted_ECB.bmp', "wb") as f:
        f.write(new_bmp)


#TODO: CBC cypher

def main():
    new_key = get_new_key()
    encrypt_ecb(new_key)


main()