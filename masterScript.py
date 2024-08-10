import subprocess
import os
import time

def wait_for_file(filepath, timeout = 20):
    startTime = time.time()
    while not os.path.exists(filepath):
        if time.time()-startTime > timeout:
            raise TimeoutError(f"waiting {filepath} timeout")
        time.sleep(0.5)
    return True
    
def read_hex(filepath):
    with open(filepath, 'r')as file:
        hex_stream = file.read().strip()
    return hex_stream

def run_wkReading(hex_stream):
  result = subprocess.run(["python3", "wkReading.py"], capture_output=True, text=True)
  
  output = result.stdout.strip().split('\n')
  
  if len(output)!=6:
    raise ValueError("fields number is wrong")
    
  header = output[0].split(":")[1].strip()
  payload = output[1].split(":")[1].strip()
  crc = output[2].split(":")[1].strip()
  linkid = output[3].split(":")[1].strip()
  timestamp = output[4].split(":")[1].strip()
  signature = output[5].split(":")[1].strip()
  
  return header, payload, crc, linkid, timestamp, signature
  print("extract finished")

def analyze_signature(header, payload, crc, linkid, timestamp, signature):
  command = [
    "python3", "dictionarySignature.py",
    "--type", "sha256",
    "--string", signature,
    "--wordlist", "wordlist.txt"
  ]
  print("running file")
  process = subprocess.run(command)
  print("analyze finished")

def main():
  filepath = "mavlink_hex_stream.txt"
  wait_for_file(filepath)
  
  hex_stream = read_hex(filepath)
  
  header, payload, crc, linkid, timestamp, signature = run_wkReading(hex_stream)
  
  analyze_signature(header, payload, crc, linkid, timestamp, signature)
  print("all finished")

if __name__ == "__main__":
  main()
  
