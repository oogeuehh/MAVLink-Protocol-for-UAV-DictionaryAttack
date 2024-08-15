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
  result = subprocess.run(["python3", "wkReading.py", hex_stream], capture_output=True, text=True)
  
  output = result.stdout.strip().split('\n')
  
  if len(output)!=6:
    raise ValueError("mavlink fields number is wrong")
    
  header = output[0].split(":")[1].strip()
  signature = output[1].split(":")[1].strip()
  timestamp = output[2].split(":")[1].strip()
  linkid = output[3].split(":")[1].strip()
  crc = output[4].split(":")[1].strip()
  payload = output[5].split(":")[1].strip()
  
  return header, payload, crc, linkid, timestamp, signature
  print("extract finished")

def analyze_signature(header, payload, crc, linkid, timestamp, signature):
  command = [
    "python3", "dictionarySignature.py",
    "--type", "sha256",
    "--string", signature,
    "--wordlist", "wordlist.txt",
    "--header", header,
    "--payload", payload,
    "--crc", crc, 
    "--linkid", linkid,
    "--timestamp", timestamp
  ]
  
  result = subprocess.run(command, capture_output=True, text=True)
  
  if result.stdout:
    return result.stdout.strip()
  else:
    return result.stdout.strip() if result.stderr else "No output received"

def main():
  filepath = '/home/wenjun/MAVLink-Protocol-for-UAV-DictionaryAttack/mavlink_hex_stream.txt'
  wait_for_file(filepath)
  
  hex_stream = read_hex(filepath)
  
  header, payload, crc, linkid, timestamp, signature = run_wkReading(hex_stream)
  
  psw = analyze_signature(header, payload, crc, linkid, timestamp, signature)
    
  print(psw)

if __name__ == "__main__":
  main()
