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

def submit(input: str, key: bytes, iv: bytes) -> bytes:
    # URL encode ';' and '=': replace ';' and '=' with hex equivalents in url encoding
    clean_in = input.replace(";", "%3B").replace("=", "%3D")
    formatted_in = "userid=456;userdata=" + clean_in + ";session-id=31337"

    # convert string to mutable byte array
    byte_input = bytearray(formatted_in.encode("utf-8"))
    str_len = len(byte_input)

    # Apply PKCS#7 padding to 16-byte block boundaries
    if ((str_len % 16) == 0):
        pass
    else:
        # Apply PKCS#7 padding to 16-byte block boundaries
        bytes_remaining = str_len - ((str_len // 16) * 16)
        pad_bytes_needed = 16 - bytes_remaining
        pad_byte = pad_bytes_needed.to_bytes(1, byteorder='big')
        padding = pad_byte * pad_bytes_needed
        # input with padding so its perfect now
        byte_input = byte_input + padding
        
    # now encrypt with AES-128-CBC using the global key & IV
    # get updated length
    str_len = len(byte_input)
    num_blocks = str_len//16
    cipher = AES.new(key, AES.MODE_ECB)
    #perform an xor operation on the 1st data chunk and the IV
    xor_bytes = xor_operation(byte_input[0:16], iv)
    #encrypt the xor'ed data
    encrypted_byte_str = cipher.encrypt(xor_bytes)
    previous_block = encrypted_byte_str
    counter = 1

    while counter < num_blocks:
        data = byte_input[(16*counter):(16*(counter+1))]
        #before encrypting the data, an xor operation is first performed
        #using the previous encrypted 16 byte chunk of data
        xor_bytes = xor_operation(data, previous_block)
        encrypted_data = cipher.encrypt(xor_bytes)
        previous_block = encrypted_data
        encrypted_byte_str += encrypted_data
        counter += 1

    result = encrypted_byte_str

    # Return ciphertext
    return result

def verify(ciphertext: bytes, key:bytes, iv:bytes) -> bool:
    #take user input and decrypt string using library decrypt
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decyphered = cipher.decrypt(ciphertext)
    #directly search for ";admin=true;" in byte format
    result = b";admin=true;" in decyphered
    return result

def main():
    # create global keys
    aes_key = get_new_key()
    aes_iv = get_new_key()

    # ask for user input, for the bit flipping manipulation part we will use a premade input
    #user = input("Input text here: ")

    #user input for bit flipping attack
    #this input because first 4 bytes are from formatting so we add 12 bytes for safe padding
    #then ":admin<true:" because ":" and "<" are one bit away from the strings we want (";" and "=")
    user = "A" * 12 + ":admin<true:"

    #call submit function
    encrypted = submit(user, aes_key, aes_iv)

    # start attack
    # turn encrypted array into a mutable byte array
    attacking = bytearray(encrypted)

    # ":" is at byte 17, so we want to flip one bit to make it ";"
    attacking[16] ^= 0x01

    # "<" is at byte 23, so we want to flip one bit to make it "="
    attacking[22] ^= 0x01

     # ":" is at byte 28, so we want to flip one bit to make it ";"
    attacking[27] ^= 0x01

    # we will print out the verify result here
    print(verify(attacking, aes_key, aes_iv))

main()