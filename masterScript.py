import subprocess
import os
import time

def extract_hex_file():
  hex_file = "mavlink_hex_stream.txt"
  while not os.path.exists(hex_file):
    print("waiting hex file...")
    time.sleep(5)
  print("hex file existed")

def extract_fields():
  result = subprocess.run(["python3", wk_reading_script], capture_output=True, Text=True)
  print("extract finished")

def analyze_signature(header, payload, crc, linkid, timestamp, signature):
  command = [
    "python3", "dictionarySignature.py",
    "--type", "sha256",
    "--string", signature,
    "--wordlist", "wordlist.txt"
  ]
  print("running file")
  subprocess.run(command)
  print(analyze finished)

def main():
  header, payload, crc, linkid, timestamp, signature = extract_fields()
  analyze_signature(header, payload, crc, linkid, timestamp, signature)
  print(all finished)

if __name__ == "__main__"
  main()
  
