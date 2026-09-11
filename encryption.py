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
def encrypt_ecb(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    if cipher:
        print("success!")


#TODO: CBC cypher

def main():
    dummy_text = "Cybersecurity"
    new_key = get_new_key()
    encrypt_ecb(new_key, dummy_text)


main()