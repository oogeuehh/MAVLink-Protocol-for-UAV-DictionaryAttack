# MAVLink-Protocol-for-UAV-DitionaryAttack

A extension for program (URL: https://github.com/VSecLab/MAVLink-Protocol-for-UAV), which hold a automically extract and analyse for transmitted message and following injection attack.

# wireshark mavlink plugins

For extract the mavlink packet using wireshark, you need to access the wensite (URL: https://mavlink.io/en/guide/wireshark.html), and follow the guidlines.

# wkReading

Script that allow you to extract the mavlink fields automatically.

# dictionaryKey and dictionarySignature

Scripts that allow you to perform a dictionary attack. The "key" file carries out the attack starting from the secret key recovered in the exchange of messages. The "signature" file carries out the attack starting from the signature exchanged in the messages, without the need for the secret key.

dictionaryKey:

time python3 dictionaryKey.py --type sha256 --string "secretkey" --wordlist wordlist.txt

dictionarySignature:

time python3 dictionarySignature.py --type sha256 --string "signature" --wordlist wordlist.txt

# wordlist

Wordlist used to carry out the attack.  It contains about 100,000 words including the most used passwords in the world, the most common Italian names and surnames, and finally many terms from the Italian dictionary.

# Software Requirements 

- Python 3
- Mission Planner
- Ardupilot
- WireShark
