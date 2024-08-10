import hashlib
import base64
import argparse
from hashlib import sha256

def calculate_secretkey(seed):
    print("Seed: ", seed)
    hashed_seed = sha256(seed.encode('utf-8')).hexdigest()
    print("SHA256: ", hashed_seed)
    hex_seed = bytes.fromhex(hashed_seed)
    print("")
    print("From HEX: ", hex_seed)
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

parser = argparse.ArgumentParser(description='SHRACK: The hash cracker')
parser.add_argument('--type', help='Hash type', required=False)
parser.add_argument('--string', help='Hash string', required=False)
parser.add_argument('--hashes', help='Hashes file', required=False)
parser.add_argument('--wordlist', help='Wordlist', required=False)
parser.add_argument('--v', help="(true/false) Show more information while cracking", default=False, type=lambda x: (str(x).lower() == 'true'))
parser.add_argument('header', help='Header value', type=str)
parser.add_argument('payload', help='Payload value', type=str)
parser.add_argument('crc', help='CRC value', type=str)
parser.add_argument('linkid', help='Link ID value', type=str)
parser.add_argument('timestamp', help='Timestamp value', type=str)
args = parser.parse_args()

hashes = []
cracked = []

if args.string:
    if args.type:
        hashes.append(args.string + ":" + args.type + ":cli")
    else:
        print("You have specified a hash, but not the type. Please use the \"--type\" param to specify the type.")
        exit()

if args.hashes:
    if args.string:
        print("Warning: you specified a list of hashes and a hash from the CLI, both of them will be cracked.")
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

def crack_hash(hash_type, hash_string):
    hashed_seed = ""
    if hash_type in supported_types:
        with open(args.wordlist, 'r') as wl:
            guesses = wl.read().split('\n')
            for guess in guesses:
                hashed_seed = sha256(guess.encode('utf-8')).hexdigest()
                hashed_guess = calculate_secretkey_input(hashed_seed, args.header, args.payload, args.crc, args.linkid, args.timestamp)
                print(hashed_guess)
                if hashed_guess == hash_string:
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

for hashstr in hashes:
    crack_hash(hashstr.split(':')[1], hashstr.split(":")[0].lower())

if len(cracked) != 0:
    print(bcolors.OKGREEN + "\nRESULT:\n" + bcolors.ENDC)
    for crackedhash in cracked:
        print(crackedhash)
        print("")
