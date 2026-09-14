from Crypto.Cipher import AES
import random

#Create a new key (or also an init vector) that is 128 bits long,
#then converts it to the bytes type used by AES
def get_new_key(size:int = 128) -> bytes:
    key = random.getrandbits(size)
    byte_key = key.to_bytes(16)
    return byte_key

#Perform the xor operation on two sets of bytes.
#Convert bytes to ints, then perform the xor.
def xor_operation(data:bytes, iv:bytes) -> bytes:
    int_data = int.from_bytes(data)
    int_iv = int.from_bytes(iv)
    xor_data = int_data ^ int_iv
    xor_bytes = xor_data.to_bytes(16)
    return xor_bytes

def get_padding(file_size:int, blocks_read:int) -> bytes:
    bytes_remaining = file_size - blocks_read * 16
    pad_bytes_needed = 16 - (bytes_remaining % 16)
    pad_byte = pad_bytes_needed.to_bytes(1, byteorder='big')
    padding = pad_byte * pad_bytes_needed
    return padding

#Encrypt the given file using the ecb order.
def encrypt_ecb(key:bytes, file:str = "cp-logo.bmp"):
    cipher = AES.new(key, AES.MODE_ECB)
    #open file using "br" mode to read bytes.
    with open(file, "br") as f:
        #get file size (in bytes w/o header) using seek method.
        #go to last byte in file, and subtract 54 bytes, then return to the beginning.
        f.seek(0, 2)
        file_size = f.tell() - 54
        f.seek(0)
        #read file header and start the bytestream for the encrypted file.
        new_bmp = f.read(54)
        blocks_read = 0
        #while there are 16 byte blocks remaining, read and encrypt the file.
        #encrypted data stored in the new_bmp variable
        while file_size - blocks_read * 16 >= 16:
            blocks_read += 1
            data = f.read(16)
            encrypted_data = cipher.encrypt(data)
            new_bmp += encrypted_data

        #if file has data remaining, add padding
        if (file_size - blocks_read * 16) != 0:
            #read remaining data
            padded_data = f.read(16)
            #get remaining bytes, and build the padding bytes
            #add padding to remaining data
            padded_data += get_padding(file_size, blocks_read)
            #encrypt and add to file
            encrypted_data = cipher.encrypt(padded_data)
            new_bmp += encrypted_data

    filename = file.split(".")[0]
    with open(f'{filename}_encrypted_ECB.bmp', "wb") as f:
        f.write(new_bmp)



def encrypt_cbc(key:bytes, file:str = "mustang.bmp"):
    #still using ecb mode for this implementation of cbc
    #this structure parallels that of encrypt_ecb() differences are highlighted with comments
    cipher = AES.new(key, AES.MODE_ECB)
    with open(file, "br") as f:
        f.seek(0, 2)
        file_size = f.tell() - 54
        f.seek(0)
        new_bmp = f.read(54)
        data = f.read(16)
        #an initialization vector is created to begin the xor operations
        init_vector = get_new_key(16)
        #perform an xor operation on the 1st data chunk and the IV
        xor_bytes = xor_operation(data, init_vector)
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

        if (file_size - blocks_read * 16) != 0:
            #read remaining data
            padded_data = f.read(16)
            #get remaining bytes, and build the padding bytes
            #add padding to remaining data
            padded_data += get_padding(file_size, blocks_read)
            #encrypt and add to file
            xor_bytes = xor_operation(padded_data, previous_block)
            encrypted_data = cipher.encrypt(xor_bytes)
            new_bmp += encrypted_data

    filename = file.split(".")[0]
    with open(f'{filename}_encrypted_CBC.bmp', "wb") as f:
        f.write(new_bmp)


def main():
    new_key = get_new_key()
    encrypt_ecb(new_key)
    new_key = get_new_key()
    encrypt_cbc(new_key)


main()