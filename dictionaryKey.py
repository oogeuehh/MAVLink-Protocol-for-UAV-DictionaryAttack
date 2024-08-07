import datetime
import hashlib
import sys
import argparse
import time
import binascii
import base64
from hashlib import sha256

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def extract_fields(hex_stream):
    bytes_data = bytes.fromhex(hex_stream)
    header = bytes_data[:10]
    signature = bytes_data[-6:]
    timestamp = bytes_data[-12:-6]
    linkid = bytes_data[-13]
    crc = bytes_data[-15:-13]
    payload = bytes_data[10:-15]
    return header, signature, timestamp, linkid, crc, payload

def encrypt(hash_type, hash_string):
    if hash_type == "md5":
        return hashlib.md5(hash_string.encode()).hexdigest()
    if hash_type == "sha256":
        return hashlib.sha256(hash_string.encode()).hexdigest()
    if hash_type == "sha1":
        return hashlib.sha1(hash_string.encode()).hexdigest()
    if hash_type == "sha224":
        return hashlib.sha224(hash_string.encode()).hexdigest()
    if hash_type == "sha384":
        return hashlib.sha384(hash_string.encode()).hexdigest()

def calculate_secretkey(seed):
    print("\nSeed: ", seed)
    hashed_seed = sha256(seed.encode('utf-8')).hexdigest()
    print("SHA256: ", hashed_seed)
    hex_seed = bytes.fromhex(hashed_seed)
    base64_bytes = base64.b64encode(hex_seed)
    base64_seed = base64_bytes.decode('ascii')
    print("To base64 (KEY): ", base64_seed)
    return base64_seed, hashed_seed

def calculate_signature(hashed_seed, header, payload, crc, linkid, timestamp):
    signaturecompleta = hashed_seed + header.hex() + payload.hex() + crc.hex() + linkid.to_bytes(1, 'big').hex() + timestamp.hex()
    signature = sha256(bytes.fromhex(signaturecompleta)).hexdigest()
    signature48bit = signature[:12]
    return signature48bit

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

def crack_hash(hash_type, hash_string, header, payload, crc, linkid, timestamp):
    if hash_type in supported_types:
        with open(wordlist, 'r') as wl:
            guesses = wl.read().split('\n')
            for guess in guesses:
                hashed_seed = sha256(guess.encode('utf-8')).hexdigest()
                base64_seed, hashed_seed = calculate_secretkey(guess)
                signature48bit = calculate_signature(hashed_seed, header, payload, crc, linkid, timestamp)
                print("Generated Signature: ", signature48bit)
                if signature48bit == hash_string:
                    print(bcolors.OKGREEN + "\nFOUND:\n" + bcolors.ENDC)
                    print(hash_string + ":" + bcolors.BOLD + bcolors.OKGREEN + guess + bcolors.ENDC)
                    cracked.append(hash_string + ":" + guess)
                    break
                else:
                    if args.v:
                        print(bcolors.FAIL + "Fail \"" + guess + "\"" + bcolors.ENDC + " (" + str(guesses.index(guess) + 1) + "/" + str(len(guesses)) + ")")
            print("End of the list.")
    else:
        print("Hash type \"" + hash_type + "\" is not supported.")
        print("")
        print("Supported types:")
        for hashtype in supported_types:
            print("  " + hashtype)

# Main program
hex_stream = input("请输入一段hex流: ")
header, signature, timestamp, linkid, crc, payload = extract_fields(hex_stream)

print(f"\nExtracted Header: {header.hex()}")
print(f"Extracted Signature: {signature.hex()}")
print(f"Extracted Timestamp: {timestamp.hex()}")
print(f"Extracted LinkID: {linkid:02x}")
print(f"Extracted CRC: {crc.hex()}")
print(f"Extracted Payload: {payload.hex()}")

for hashstr in hashes:
    crack_hash(hashstr.split(':')[1], hashstr.split(":")[0].lower(), header, payload, crc, linkid, timestamp)

if len(cracked) != 0:
    print(bcolors.OKGREEN + "\nRESULT:\n" + bcolors.ENDC)
    for crackedhash in cracked:
        print(crackedhash)
        print("")