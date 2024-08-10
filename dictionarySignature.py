import hashlib
import base64
from hashlib import sha256

def calculate_secretkey(seed):
    print("Seed: ", seed)
    hashed_seed = (sha256(seed.encode('utf-8')).hexdigest())
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
    signature = sha256(bytes.fromhex(signaturecompleta))
    stampa_signature = signature.hexdigest()
    signature48bit = stampa_signature[:12]
    return signature48bit

def crack_hash(hash_type, hash_string, header, payload, crc, linkid, timestamp, wordlist, verbose=False):
    supported_types = ('md5', 'sha256', 'sha1', 'sha224', 'sha384')
    if hash_type not in supported_types:
        print(f"hash type '{hash_type}' is not supported.")
        print("Supported types:")
        for hashtype in supported_types:
            print("  " + hashtype)
        return "Unsupported hash type"
    
    cracked = []
    with open(wordlist, 'r') as wl:
        guesses = wl.read().split('\n')
        for guess in guesses:
            hashed_seed = (sha256(guess.encode('utf-8')).hexdigest())
            hashed_guess = calculate_secretkey_input(hashed_seed, header, payload, crc, linkid, timestamp)
            if hashed_guess == hash_string:
                result = f"FOUND:\n{hash_string}: {guess}"
                print(result)
                cracked.append(result)
                break
            elif verbose:
                print(f"Fail \"{guess}\" ({guesses.index(guess) + 1}/{len(guesses)})")
        print("End of the list.")
    
    if cracked:
        return "\nRESULT:\n" + "\n".join(cracked)
    else:
        return "No match found"
