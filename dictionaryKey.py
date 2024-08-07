import hashlib
import base64
import argparse

def extract_fields(hex_stream):
    # 提取header、signature等字段的函数
    header = hex_stream[:20]
    signature = hex_stream[-12:]
    timestamp = hex_stream[-18:-12]
    linkid = hex_stream[-19:-18]
    crc = hex_stream[-21:-19]
    payload = hex_stream[20:-21]
    return header, payload, crc, linkid, timestamp, signature

def calculate_secretkey(seed):
    print("Seed: ", seed)
    hashed_seed = hashlib.sha256(seed.encode('utf-8')).hexdigest()
    print("SHA256: ", hashed_seed)
    hex_seed = bytes.fromhex(hashed_seed)
    base64_bytes = base64.b64encode(hex_seed)
    base64_seed = base64_bytes.decode('ascii')
    print("To base64 (KEY): ", base64_seed)
    return base64_seed, hashed_seed

def calculate_signature(hashed_seed, header, payload, crc, linkid, timestamp):
    signature_completa = hashed_seed + header + payload + crc + linkid + timestamp
    signature = hashlib.sha256(bytes.fromhex(signature_completa)).hexdigest()
    signature48bit = signature[:12]
    return signature48bit

def crack_hash(hash_type, hash_string, header, payload, crc, linkid, timestamp, wordlist):
    if hash_type in supported_types:
        with open(wordlist, 'r') as wl:
            guesses = wl.read().split('\n')
            for guess in guesses:
                hashed_seed = hashlib.sha256(guess.encode('utf-8')).hexdigest()
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

# 主逻辑部分
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

for hashstr in hashes:
    hash_string, hash_type = hashstr.split(':')
    crack_hash(hash_type.lower(), hash_string, header, payload, crc, linkid, timestamp, wordlist)

if len(cracked) != 0:
    print(bcolors.OKGREEN + "\nRESULT:\n" + bcolors.ENDC)
    for crackedhash in cracked:
        print(crackedhash)
        print("")
