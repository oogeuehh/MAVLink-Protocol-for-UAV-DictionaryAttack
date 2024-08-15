import os
import getpass

def extract_fields(hex_stream):
    bytes_data = bytes.fromhex(hex_stream.strip())
    
    header = bytes_data[:10]
    signature = bytes_data[-6:]
    timestamp = bytes_data[-12:-6]
    linkid = bytes_data[-13]
    crc = bytes_data[-15:-13]
    payload = bytes_data[10:-15]
    
    return header, signature, timestamp, linkid, crc, payload
    
def main():     
    try:
        with open("mavlink_hex_stream.txt file path", "r") as file:
            hex_stream = file.readline().strip()
    
        header, signature, timestamp, linkid, crc, payload = extract_fields(hex_stream)
    
        print(f"Header: {header.hex()}")
        print(f"Signature: {signature.hex()}")
        print(f"Timestamp: {timestamp.hex()}")
        print(f"LinkID: {linkid:02x}")
        print(f"CRC: {crc.hex()}")
        print(f"Payload: {payload.hex()}")
        
    except FileNotFoundError:
        print("file not found")
    
if __name__ == "__main__":
    main()
