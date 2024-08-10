import argparse
import hashlib
import base64
from hashlib import sha256

def calculate_secretkey_input(hashed_seed, header, payload, crc, linkid, timestamp):
    signaturecompleta = hashed_seed + header + payload + crc + linkid + timestamp
    signature = sha256(bytes.fromhex(signaturecompleta))
    stampa_signature = signature.hexdigest()
    signature48bit = stampa_signature[:12]
    return signature48bit

def crack_hash(hash_type, hash_string, header, payload, crc, linkid, timestamp, wordlist, verbose=False):
    supported_types = ('md5', 'sha256', 'sha1', 'sha224', 'sha384')
    if hash_type not in supported_types:
        print(f"Hash type '{hash_type}' is not supported.")
        print("Supported types:")
        for hashtype in supported_types:
            print("  " + hashtype)
        return
    
    cracked = []
    with open(wordlist, 'r') as wl:
        guesses = wl.read().split('\n')
        print("Starting to crack hash...")
        for guess in guesses:
            hashed_seed = sha256(guess.encode('utf-8')).hexdigest()
            hashed_guess = calculate_secretkey_input(hashed_seed, header, payload, crc, linkid, timestamp)
            if hashed_guess == hash_string:
                print("FOUND:")
                print(f"{hash_string}: {guess}")
                cracked.append(f"{hash_string}: {guess}")
                break
            elif verbose:
                print(f"Fail \"{guess}\" ({guesses.index(guess) + 1}/{len(guesses)})")
        print("End of the list.")
    
    if cracked:
        print("\nRESULT:")
        for crackedhash in cracked:
            print(crackedhash)

def main():
    parser = argparse.ArgumentParser(description='SHRACK: The hash cracker')
    parser.add_argument('--type', help='Hash type', required=True)
    parser.add_argument('--string', help='Hash string', required=True)
    parser.add_argument('--wordlist', help='Wordlist', required=True)
    parser.add_argument('--header', help='Header', required=True)
    parser.add_argument('--payload', help='Payload', required=True)
    parser.add_argument('--crc', help='CRC', required=True)
    parser.add_argument('--linkid', help='Link ID', required=True)
    parser.add_argument('--timestamp', help='Timestamp', required=True)
    parser.add_argument('--v', help="(true/false) Show more information while cracking", default=False, type=lambda x: (str(x).lower() == 'true'))
    args = parser.parse_args()

    crack_hash(args.type, args.string, args.header, args.payload, args.crc, args.linkid, args.timestamp, args.wordlist, args.v)

if __name__ == "__main__":
    main()
