import hashlib
import base64
from hashlib import sha256

# 请求用户输入十六进制流
hex_stream = input("Enter Hex Stream: ")

# 将十六进制流转换为字节流
byte_stream = bytes.fromhex(hex_stream)

# 提取字段
header = byte_stream[:10]  # 前10个字节为header
signature = byte_stream[-6:]  # 最后6个字节为signature
timestamp = byte_stream[-12:-6]  # signature前面的6个字节为timestamp
linkid = byte_stream[-13]  # timestamp的前一个字节为linkid
crc = byte_stream[-15:-13]  # linkid的前两个字节为crc
payload = byte_stream[10:-15]  # 剩余的是payload

# 将提取的字段转换为十六进制字符串
header = header.hex()
payload = payload.hex()
crc = crc.hex()
linkid = linkid.to_bytes(1, 'big').hex()
timestamp = timestamp.hex()

# 打印提取的字段（可选，用于验证）
print("Header: ", header)
print("Signature: ", signature.hex())
print("Timestamp: ", timestamp)
print("Link ID: ", linkid)
print("CRC: ", crc)
print("Payload: ", payload)

def calculate_secretkey(seed):
    print("Seed: ", seed)
    hashed_seed = sha256(seed.encode('utf-8')).hexdigest()
    print("SHA256: ", hashed_seed)
    hex_seed = bytes.fromhex(hashed_seed)
    base64_bytes = base64.b64encode(hex_seed)
    base64_seed = base64_bytes.decode('ascii')
    print("To base64 (KEY): ", base64_seed)
    print("Signature = sha256_48(secret_key + header + payload + CRC + Link ID + timestamp)")

def calculate_secretkey_input(hashed_seed, header, payload, crc, linkid, timestamp):
    signaturecompleta = hashed_seed + header + payload + crc + linkid + timestamp
    signature = sha256(bytes.fromhex(signaturecompleta)).hexdigest()
    signature48bit = signature[:12]
    return signature48bit

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

import argparse

parser = argparse.ArgumentParser(description='SHRACK: The hash cracker')
parser.add_argument('--type', help='Hash type', required=False)
parser.add_argument('--string', help='Hash string', required=False)
parser.add_argument('--hashes', help='Hashes file', required=False)
parser.add_argument('--wordlist', help='Wordlist', required=False)
parser.add_argument('--v', help="(true/false) Show more information while cracking", default=False, type=lambda x: (str(x).lower() == 'true'))
args = parser.parse_args()

hashes = []
cracked = []

if args.string:
    if args.type:
        hashes.append(args.string + ":" + args.type + ":cli")
    else:
        print("You have been specified the hash, but not the type, please use the \"--type\" param to specify the type")
        exit()

if args.hashes:
    if args.string:
        print("Warning: you specified a list of hashes and a hash from the cli, both of them will be cracked")
    with open(args.hashes) as hashlist:
        hashlist = hashlist.read()
        hasheslines = hashlist.split('\n')
        for hashline in hasheslines:
            hashline = hashline.replace('\\', '').replace(' ', '')
            if hashline:
                hashes.append(hashline)
            else:
                print('Warning: detected empty line. Ignoring')

if len(hashes) == 0:
    print('No hashes imported. Exiting...')
    exit()

supported_types = ('md5', 'sha256', 'sha1', 'sha224', 'sha384')
wordlist = args.wordlist

def encrypt(hash_type, hash_string):
    if hash_type == "md5":
        return (hashlib.md5(hash_string.encode()).hexdigest())
    if hash_type == "sha256":
        return (hashlib.sha256(hash_string.encode()).hexdigest())
    if hash_type == "sha1":
        return (hashlib.sha1(hash_string.encode()).hexdigest())
    if hash_type == "sha224":
        return (hashlib.sha224(hash_string.encode()).hexdigest())
    if hash_type == "sha384":
        return (hashlib.sha384(hash_string.encode()).hexdigest())

def crack_hash(hash_type, hash_string):
    hashed_seed = ""
    if hash_type in supported_types:
        with open(wordlist, 'r') as wl:
            guesses = wl.read().split('\n')
            for guess in guesses:
                hashed_seed = sha256(guess.encode('utf-8')).hexdigest()
                hashed_guess = calculate_secretkey_input(hashed_seed, header, payload, crc, linkid, timestamp)
                print(hashed_guess)
                if hashed_guess == hash_string:
                    print(bcolors.OKGREEN + "\nFOUND:\n" + bcolors.ENDC)
                    print(hash_string + ":" + bcolors.BOLD + bcolors.OKGREEN + guess + bcolors.ENDC)
                    cracked.append(hash_string + ":" + guess)
                    break
                else:
                    if args.v:
                        print(bcolors.FAIL + "Fail \"" + guess + "\"" + bcolors.ENDC + " (" + str(guesses.index(guess) + 1) + "/" + str(guesses.__len__()) + ")")
            print("End of the list.")
    else:
        print("hash type \"" + hash_type + "\" is not supported.")
        print("")
        print("Supported types:")
        for hashtype in supported_types:
            print("  " + hashtype)

for hashstr in hashes:
    crack_hash(hashstr.split(':')[1], hashstr.split(":")[0].lower())

if len(cracked) != 0:
    print(bcolors.OKGREEN + "\nRESULT:\n" + bcolors.ENDC)
    for crackedhash in cracked:
        print(crackedhash)
        print("")
