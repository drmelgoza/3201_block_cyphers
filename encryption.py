from Crypto.Cipher import AES
import random

#Create a new key that is 128 bits long,
#then converts it to the bytes type used by AES
def get_new_key(size=128):
    key = random.getrandbits(size)
    byte_key = key.to_bytes(16)
    return byte_key

#PART 1:
def encrypt_ecb(key, file="mustang.bmp"):
    cipher = AES.new(key, AES.MODE_ECB)
    #Open file using "br" mode to read bytes.
    with open(file, "br") as f:
        #get file size (in bytes w/o header) using seek method.
        #Go to last byte in file, and subtract 54 bytes, then return to the beginning.
        f.seek(0, 2)
        file_size = f.tell() - 54
        f.seek(0)
        #read file header and start the bytestream for the encrypted file.
        new_bmp = f.read(54)
        blocks_read = 0
        #While there are 16 byte blocks remaining, read and encrypt the file.
        #Encrypted data stored in the new_bmp variable
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
            bytes_remaining = file_size - blocks_read * 16
            pad_bytes_needed = 16 - (bytes_remaining % 16)
            pad_byte = pad_bytes_needed.to_bytes(1, byteorder='big')
            padding = pad_byte * pad_bytes_needed
            #add padding to remaining data
            padded_data += padding
            #encrypt and add to file
            encrypted_data = cipher.encrypt(padded_data)
            new_bmp += encrypted_data

    with open('mustang_encrypted_ECB.bmp', "wb") as f:
        f.write(new_bmp)


#TODO: CBC cypher

def main():
    new_key = get_new_key()
    encrypt_ecb(new_key)


main()