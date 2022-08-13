
# Some info:
- Right now, this dissector only supports protocol version 3.4, which is still W.I.P
- To use this dissector you have to copy lockbox lib to the right directory (I did to 'C:\Program Files\Wireshark\lua')
  - Download the lockbox lib from [lockbox repo](https://github.com/somesocks/lua-lockbox)
  - Take all the files from lua-lockbox/lockbox and copy them to 'C:\Program Files\Wireshark\lua' (i.e. init.lua, cipher folder, ... are in 'C:\Program Files\Wireshark\lua\init.lua', 'C:\Program Files\Wireshark\lua\cipher\')
  - Take this script (tuya.lua) and place it (or symlink it from git folder) to 'C:\Program Files\Wireshark\plugins\3.6' or one of the lua plugins folder (Help -> About Wireshark -> Folders)
- You have to input device_key into the protocol settings (right click on Tuya packet -> Protocol Preferences -> Tuya Protocol -> device_key)
   - You need to get the device_key from tuya developer cloud site ([tuya cloud api](https://iot.tuya.com/), guide at for example: [localtuya](https://github.com/rospogrigio/localtuya))
- The device key is in ASCII string, while others are in hex stream - e.g. B61978 == 0xB6 0x19 0x78 (because they have random bytes and values 0x00-0x1F fuck up the printing... I am in LUA what can I do, pls help :D)
- I do not know where does the naming of the commands came from, so it may not be relevant ¯\_(ツ)_/¯
- If the decoding is screwed up, click packets in this order: BIND(0x03), RENAME_GW(0x04)
- If anything else is broken (erors, etc.) -> reload lua plugins: Analyze -> reload lua plugins (ctrl + shift + l (<-'L', not 1))
- To find dps (datapoints) descriptions go to [tuya cloud api](https://iot.tuya.com/) -> Cloud -> Api explorer then Device control -> Get Device Specification Attribute (or search Get Device Specification Attribute)
   - or search Get the device specifications and properties of the device
   - or try your luck at [docs](https://developer.tuya.com/en/docs/iot/remote-control?id=Kaof8v52k1ij3) (docs -> cloud development -> standard instruction set -> ..... somewhere in here)

**If any of this info seem broken, go to first git commit of this info: 'Add code info and description'**

## TERMINOLOGY
Some terminology (may not match with the terminology of [tuyapi repo](https://github.com/harryzz/tuyapi)):
- local == pc/mobile
- remote == Tuya device (switch, sensor, ...)
- header == first 16B (B == bytes)
- payload == all data after header 
- return code == only sometimes! Only from remote? 4B after header counts to payload_len
- dps == datapoints

## PACKET DESCRIPTION
**Sometimes there are multiple tuya packets inside one tcp!!!!**
- The Tuya header and payload:
   - Header (16B):
       - 4B Prefix 0x000055AA
       - 4B Sequence_number (separate sequence numbers for remote and local)
       - 4B Command
       - 4B Payload length
       
       ---
    
   - Payload (Payload length long):
       - Sometimes 4B return_code from remote (could to be always - [tuya-iotos-embeded-sdk-wifi](https://github.com/tuya/tuya-iotos-embeded-sdk-wifi-ble-bk7231n/blob/master/sdk/include/lan_protocol.h))
       - xB DATA - has padding
           - As to my understanding from the code I am rewriting, the padding is always there. Not shure it is true all the time.
           - Padding bytes are the length of padding (0x........10101010101010101010101010101010 - padding is 0x10 == 16 and is 16B long, 0x...327D090909090909090909 - 9 x 0x09 (== 9))
       - 32B HMAC_SHA256 - for as error detectiong code (crc/hash....)
       - 4B suffix 0x0000AA55
       
       ---

   - DATA is always ECB_AES128 encrypted with device_key

## HANDSHAKE AND SESSION_KEY GENERATION
This is how the session_key handshake goes (after TCP Syn handshake):
- local generates local_key == 16B (B == bytes) random
- add padding to local_key (0x10101010101010101010101010101010 when (len % 16 == 0))
- data = encode local_key using ecb_aes128 with device_key as passw (no padding or iv)
- create packet with prefix, local_seq_n, command = 0x00000003 (BIND), len (68? calculate it yourself :D), data
- calculate HMAC_SHA256 of previous packet using device_key as secret (passw) (no padding or iv)
- append hmac_hash to packet and append suffix (0x0000AA55)
- send!

---

- receive tuya packet (payload_len = 104B) with command 0x04 (do the previous in reverse :) ):
- remove suffix
- read the hmac_hash, calculate the hash (using device_key as secret) of the rest yourself and compare -> check if not data is lost/manipulated
- remove return_code from data in payload (first 4B in payload) if present (look at code at 'Remove return code' in tuya_protocol.dissector(...))
- take the remaining data in payload and decrypt it using ecb_aes128 with device_key as passw:
    - remove padding (look at code at 'Remove padding' in _decrypt())
    - first 16B is the remote_key
    - next 32B is the HMAC_SHA256 hash of the local_key using device_key as secret (passw) -> calculate it yourself and compare
    
---
    
- calculate the session_key as (python code):
    - XOR coresponding bytes and then encrypt using device_key as passw

    - for i in range(0x00, 0x10):
        session_key.append(local_key[i] ^ remote_key[i])

    session_key = cipher_ECB_AES128.encrypt(session_key)
    
---
        
- send the message similar to the first one (0x00000003, BIND)
    - increment local seq_n
    - command = 0x00000005 (RENAME_DEVICE)
    - len = 84
    - Data = HMAC_SHA256 of remote_key using device_key as secret (passw)
    
---

- Ta duh... You are connected :)

- **!!!From now on use session_key in AES encryption and ALSO in HMAC hash!!!**

---

## DPS (for aubess switch):
    - 1:   "code": "switch_1", "value": false
    - 9:   "code": "countdown_1", "value": 0
    - 38:  "code": "relay_status", "value": "1"
    - 42:  "code": "random_time", "value": ""
    - 43:  "code": "cycle_time", "value": ""
    - 44:  "code": "switch_inching", "value": "AQEs"
    - 47?


## ADDITIONAL INFO
for more info on the 3.4 protocol and where I 'inspired' myself go to:
- encryption described (mainly looked at code in repo below :D): https://github.com/codetheweb/tuyapi/issues/481#issuecomment-921756711
- harryzz tuyapi repo with 3.4 implementation: https://github.com/harryzz/tuyapi
- codetheweb original tuyapi: https://github.com/codetheweb/tuyapi
