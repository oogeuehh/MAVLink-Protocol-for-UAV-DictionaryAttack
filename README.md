# MAVLink-Protocol-for-UAV-DitionaryAttack

An extension for program (URL: https://github.com/VSecLab/MAVLink-Protocol-for-UAV), which hold a automically extract and analyse for transmitted message and following injection attack.

# wireshark mavlink plugins

To check and debug the MAVLink packet using wireshark, you need to access the website (URL: https://mavlink.io/en/guide/wireshark.html), and follow the guidlines.

# capture_mavlink.lua

A plugin for extract the hex stream of the MAVLink Message (HeartBeat Message) as a txt file.

# wkReading

Scripts that allow you to extract the mavlink fields automatically, including header, payload, linkid, crc, signature, and timestamp.

# dictionaryKey and dictionarySignature

Scripts that allow you to perform a dictionary attack. The "key" file carries out the attack starting from the secret key recovered in the exchange of messages. The "signature" file carries out the attack starting from the signature exchanged in the messages, without the need for the secret key.

dictionaryKey:

time python3 dictionaryKey.py --type sha256 --string "secretkey" --wordlist wordlist.txt

dictionarySignature:

time python3 dictionarySignature.py --type sha256 --string "signature" --wordlist wordlist.txt --header "header" --payload "payload" --crc "crc" --linkid "linkid" --timestamp "timestamp"

# masterScript

Scripts that allow you run all the required code in series without manually input the content.

# wordlist

Wordlist used to carry out the attack.  It contains about 100,000 words including the most used passwords in the world, the most common Italian names and surnames, and finally many terms from the Italian dictionary.

# Software Requirements 

- Python 3
- Mission Planner
- Ardupilot
- WireShark
