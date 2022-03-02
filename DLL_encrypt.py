import sys
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

def aesenc(plain, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(bytes(pad(plaintext, AES.block_size)))

key_data = get_random_bytes(32)
iv_data = get_random_bytes(16)

try:
    file_path = os.path.dirname(sys.argv[0]) + '\\x64\\Release\\RIPPLDLL_unencrypted.dll'
    with open(file_path, 'rb') as file :
        plaintext = file.read()
    print("[+] Input unencrypted DLL read successfully!")
except:
    print("[-] Failed to read input DLL")
    sys.exit(-1)

ciphertext = aesenc(plaintext, key_data, iv_data)

try:
    file_path = os.path.dirname(sys.argv[0]) + '\\x64\\Release\\RIPPLDLL.dll'
    with open(file_path, 'wb') as file :
        file.write(ciphertext)
    print("[+] DLL successfully encrypted!")
except:
    print("[-] Failed to create the encrypted DLL")
    sys.exit(-1)

# Read in the file
try:
    file_path = os.path.dirname(sys.argv[0]) + '\\RIPPL\\utils.h'
    with open(file_path, 'r') as file :
      filedata = file.read()
except:
    print("[-] Failed to read the header to modify...")
    sys.exit(-1)

# Replace the target string
key = '{ 0x' + ', 0x'.join(hex(x)[2:] for x in key_data) + ' };'
iv = '{ 0x' + ', 0x'.join(hex(x)[2:] for x in iv_data) + ' };'
filedata = filedata.replace('[AESKEY]', key)
filedata = filedata.replace('[IV]', iv)

# Write the file out again
try:
    file_path = os.path.dirname(sys.argv[0]) + '\\RIPPL\\utils.h'
    with open(file_path, 'w') as file :
      file.write(filedata)
except:
    print("[-] Failed to write to the header...")
    sys.exit(-1)

print("[+] DLL encrypted. Key and IV saved to utils.h!")