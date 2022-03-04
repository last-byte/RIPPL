import os
import sys

# Read in the file
try:
    file_path = os.path.dirname(sys.argv[0]) + '\\RIPPL\\common.h'
    with open(file_path, 'r') as file :
      filedata = file.readlines()
except:
    print("[-] Failed to read the header to modify...")
    sys.exit(-1)

# Replace the target string
newdata = ""
for line in filedata:
    if "#define SHCODE" in line:
        line = "#define SHCODE {0}\n"
    elif "#define AESKEY" in line:
        line = "#define AESKEY {0}\n"
    elif "#define IV" in line:
        line = "#define IV {0}\n"
    newdata += line

# Write the file out again
try:
    file_path = os.path.dirname(sys.argv[0]) + '\\RIPPL\\common.h'
    with open(file_path, 'w') as file :
      file.write(newdata)
except:
    print("[-] Failed to write to the header...")
    sys.exit(-1)

print("[+] Postbuild done!")