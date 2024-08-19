from pymavlink import mavutil
import time
import hmac
import hashlib

def user_input(prompt):
    return input(prompt).strip()
    
secreteKey = user_input("Enter secrete key: ").encode('utf-8')
linkid = bytes.fromhex(user_input("Enter linkid: "))

def build_payload():
    target_system = 1,
    target_component = 1,
    command = mavutil.mavlink.MAVLink_command_long_message(
        target_system = target_system,
        target_component = target_component,
        command = mavutil.mavlink.MAV_CMD_NAV_RETURN_TO_LAUNCH,
        confirmation = 0,
        param1 =  0, param2 =  0, param3 =  0, 
        param4 =  0, param5 =  0, param6 =  0, param7 =  0, 
    )
    return command.pack(master.mav)[10:]


# SYSTEM_ID = 255
# COMPONENT_ID = 190

master = mavutil.mavlink_connection('udpout:10.0.2.5:14550')

payload = build_payload()
header = bytes.fromhex(user_input("Enter header: "))

message = header + payload
crc = mavutil.x25crc(message)
timestamp = int(time.time()).to_bytes(4, 'little')

signature_input = secreteKey + header + payload + crc.to_bytes(2, 'little') + linkid + timestamp
hash_result = hashlib.sha256(signature_input).digest()

signature = hash_result[:6]

signed_msg = header + payload + crc.to_bytes(2, 'little') + linkid + timestamp + signature

try:
    master.write(signed_msg)
    print("message sended")
    
except Exception as e:
    print("error")
