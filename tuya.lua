local Lockbox = require("lockbox");
Lockbox.ALLOW_INSECURE = true;
local Array = require("lockbox.util.array");
local HMAC_SHA256 = require("lockbox.mac.hmac");
local SHA256Digest = require("lockbox.digest.sha2_256");
local ECBMode = require("lockbox.cipher.mode.ecb");
local AES128Cipher = require("lockbox.cipher.aes128");
local ZeroPadding = require("lockbox.padding.zero");
local Stream = require("lockbox.util.stream");

-- Some info:
    -- Right now, this dissector only supports protocol version 3.4, which is still W.I.P
    -- To use this dissector you have to copy lockbox lib to the right directory (I did to 'C:\Program Files\Wireshark\lua')
        -- Download the lockbox lib from https://github.com/somesocks/lua-lockbox
        -- Take all the files from lua-lockbox/lockbox and copy them to 'C:\Program Files\Wireshark\lua' (i.e. init.lua, cipher folder, ... are in 'C:\Program Files\Wireshark\lua\init.lua', 'C:\Program Files\Wireshark\lua\cipher\')
        -- Take this script (tuya.lua) and place it (or symlink it from git folder) to 'C:\Program Files\Wireshark\plugins\3.6' or one of the lua plugins folder (Help -> About Wireshark -> Folders)
    -- You have to input device_key into the protocol settings (right click on Tuya packet -> Protocol Preferences -> Tuya Protocol -> device_key)
        -- You need to get the device_key from tuya developer cloud site (https://iot.tuya.com/, guide at for example: https://github.com/rospogrigio/localtuya)
    -- The device key is in ASCII string, while others are in hex stream - e.g. B61978 == 0xB6 0x19 0x78 (because they have random bytes and values 0x00-0x1F fuck up the printing... I am in LUA what can I do, pls help :D)
    -- I do not know where does the naming of the commands came from, so it may not be relevant ¯\_(ツ)_/¯
    -- If the decoding is screwed up, click packets in this order: BIND(0x03), RENAME_GW(0x04)
    -- If anything else is broken (erors, etc.) -> reload lua plugins: Analyze -> reload lua plugins (ctrl + shift + l (<-'L', not 1))
    -- To find dps (datapoints) descriptions go to https://iot.tuya.com/ -> Cloud -> Api explorer then Device control -> Get Device Specification Attribute (or search Get Device Specification Attribute)
        -- or search Get the device specifications and properties of the device
        -- or try your luck at docs https://developer.tuya.com/en/docs/iot/remote-control?id=Kaof8v52k1ij3 (docs -> cloud development -> standard instruction set -> ..... somewhere in here)

    -- If any of this info seem broken, go to first git commit of this info: 'Add code info and description'

    -- TERMINOLOGY
    -- Some terminology (may not match with the terminology of https://github.com/harryzz/tuyapi):
        -- local == pc/mobile
        -- remote == Tuya device (switch, sensor, ...)
        -- header == first 16B (B == bytes)
        -- payload == all data after header 
        -- return code == only sometimes! Only from remote? 4B after header counts to payload_len
        -- dps == datapoints

    -- PACKET DESCRIPTION
    -- Sometimes there are multiple tuya packets inside one tcp!!!!
    -- The Tuya header and payload:
        -- Header (16B):
            -- 4B Prefix 0x000055AA
            -- 4B Sequence_number (separate sequence numbers for remote and local)
            -- 4B Command
            -- 4B Payload length
        
        -- Payload (Payload length long):
            -- Sometimes 4B return_code from remote
            -- xB DATA - has padding
                -- As to my understanding from the code I am rewriting, the padding is always there. Not shure it is true all the time.
                -- Padding bytes are the length of padding (0x........10101010101010101010101010101010 - padding is 0x10 == 16 and is 16B long, 0x...327D090909090909090909 - 9 x 0x09 (== 9))
            -- 32B HMAC_SHA256 - for as error detectiong code (crc/hash....)
            -- 4B suffix 0x0000AA55

        -- DATA is always ECB_AES128 encrypted with device_key

    -- HANDSHAKE AND SESSION_KEY GENERATION
    -- This is how the session_key handshake goes (after TCP Syn handshake):
        -- local generates local_key == 16B (B == bytes) random
        -- add padding to local_key (0x10101010101010101010101010101010 when (len % 16 == 0))
        -- data = encode local_key using ecb_aes128 with device_key as passw (no padding or iv)
        -- create packet with prefix, local_seq_n, command = 0x00000003 (BIND), len (68? calculate it yourself :D), data
        -- calculate HMAC_SHA256 of previous packet using device_key as secret (passw) (no padding or iv)
        -- append hmac_hash to packet and append suffix (0x0000AA55)
        -- send!

        -- receive tuya packet (payload_len = 104B) with command 0x04 (do the previous in reverse :) ):
        -- remove suffix
        -- read the hmac_hash, calculate the hash (using device_key as secret) of the rest yourself and compare -> check if not data is lost/manipulated
        -- remove return_code from data in payload (first 4B in payload) if present (look at code at 'Remove return code' in tuya_protocol.dissector(...))
        -- take the remaining data in payload and decrypt it using ecb_aes128 with device_key as passw:
            -- remove padding (look at code at 'Remove padding' in _decrypt())
            -- first 16B is the remote_key
            -- next 32B is the HMAC_SHA256 hash of the local_key using device_key as secret (passw) -> calculate it yourself and compare
        
        -- calculate the session_key as (python code):
            -- XOR coresponding bytes and then encrypt using device_key as passw

            -- for i in range(0x00, 0x10):
            --     session_key.append(local_key[i] ^ remote_key[i])

            -- session_key = cipher_ECB_AES128.encrypt(session_key)
            
        -- send the message similar to the first one (0x00000003, BIND)
            -- increment local seq_n
            -- command = 0x00000005 (RENAME_DEVICE)
            -- len = 84
            -- Data = HMAC_SHA256 of remote_key using device_key as secret (passw)

        -- Ta duh... You are connected :)

        -- !!!From now on use session_key in AES encryption and ALSO in HMAC hash!!!

    -- DPS (for aubess switch):
        -- 1:   "code": "switch_1", "value": false
        -- 9:   "code": "countdown_1", "value": 0
        -- 38:  "code": "relay_status", "value": "1"
        -- 42:  "code": "random_time", "value": ""
        -- 43:  "code": "cycle_time", "value": ""
        -- 44:  "code": "switch_inching", "value": "AQEs"
        -- 47?


    -- ADDITIONAL INFO
    -- for more info on the 3.4 protocol and where I 'inspired' myself go to:
        -- encryption described (mainly looked at code in repo below :D): https://github.com/codetheweb/tuyapi/issues/481#issuecomment-921756711
        -- harryzz tuyapi repo with 3.4 implementation: https://github.com/harryzz/tuyapi
        -- codetheweb original tuyapi: https://github.com/codetheweb/tuyapi


function _encrypt(key, data)
    local cipher = ECBMode.Cipher()
        .setKey(Array.fromString(key))
        .setBlockCipher(AES128Cipher)
        .setPadding(ZeroPadding);
    local encrypted_bytes = cipher
        .init()
        .update(Stream.fromString(data))
        .finish()
        .asBytes();

    return Array.toHex(encrypted_bytes)
end

function _decrypt(key, data)
    local cipher = ECBMode.Decipher()
        .setKey(Array.fromString(key))
        .setBlockCipher(AES128Cipher)
        .setPadding(ZeroPadding);
    local decrypted_bytes = cipher
        .init()
        .update(Stream.fromString(data))
        .finish()
        .asBytes();
    
    print("\n\nKey(hex) : " .. Array.toHex(Array.fromString(key)) .. ", \ndata : '" .. Array.toHex(Array.fromString(data)) .. "', \ndecrypted_data : '" .. Array.toHex(decrypted_bytes) .. "'\n")
    
    -- Remove padding
    decrypted_bytes_len = Array.size(decrypted_bytes)
    decrypted_bytes = Array.truncate(decrypted_bytes, decrypted_bytes_len - decrypted_bytes[decrypted_bytes_len]) 
    
    print("\n\nKey : " .. key .. ", \ndata : '" .. Array.toHex(Array.fromString(data)) .. "', \ndecrypted_data : '" .. Array.toHex(decrypted_bytes) .. "'\n")
    return Array.toHex(decrypted_bytes)
end

function decrypt(data)
    if session_key ~= nil then
        print("have session key")
        decrypted_payload = _decrypt(Array.toString(Array.fromHex(session_key)), data)
    else
        print("don't have session key")
        decrypted_payload = _decrypt(tuya_protocol.prefs.device_key, data)
    end

    return decrypted_payload
end

function _hmac_sha256(key, data)
    local hmac = HMAC_SHA256()
        .setBlockSize(64)
        .setDigest(SHA256Digest)
        .setKey(Array.fromString(key))
    local hash = hmac
        .init()
        .update(Stream.fromString(data))
        .finish()
        .asBytes()
    
    return Array.toHex(hash)
end

function hmac_sha256(data)
    if session_key ~= nil then
        return _hmac_sha256(Array.toString(Array.fromHex(session_key)), data)
    else
        return _hmac_sha256(tuya_protocol.prefs.device_key, data)
    end
end

tuya_protocol = Proto("Tuya", "Tuya Protocol")

local pf_device_key = ProtoField.string("tuya.device_key", "Device key", base.ASCII)
local pf_local_key = ProtoField.string("tuya.local_key", "Local key", base.ASCII)
local pf_remote_key = ProtoField.string("tuya.remote_key", "Remote key", base.ASCII)
local pf_session_key = ProtoField.string("tuya.session_key", "Session key", base.ASCII)

local pf_message_preffix = ProtoField.uint32("tuya.message_preffix", "Preffix", base.HEX)
local pf_message_suffix = ProtoField.uint32("tuya.message_suffix", "Suffix", base.HEX)

local pf_message_sequence_num = ProtoField.uint32("tuya.sequence_number", "Sequence Number", base.UINT)
local pf_message_command_byte = ProtoField.uint32("tuya.command_byte", "Command Byte", base.HEX)
local pf_message_payload_size = ProtoField.uint32("tuya.payload_size", "Payload Size", base.UINT)

local pf_message_return_code = ProtoField.uint32("tuya.return_code", "Return Code", base.HEX)

local pf_data_message = ProtoField.bytes("tuya.data_message", "Data Message", base.NONE)
local pf_data_message_decrypted = ProtoField.string("tuya.data_message_decrypted", "Data Message Decrypted", base.ASCII)
local pf_data_message_decrypted_seq = ProtoField.uint16("tuya.data_message_decrypted_seq", "Data Message Decrypted Sequence", base.UINT)
local pf_data_hash = ProtoField.bytes("tuya.data_hash", "Data Hash", base.NONE)
local pf_data_calculated_hash = ProtoField.string("tuya.data_calculated_hash", "Data Calculated Hash", base.ASCII)

-- DEBUG
local pf_dissector_state = ProtoField.string("tuya.dissector.state", "Dissector State", base.ASCII)

tuya_protocol.fields = { pf_device_key,
                        pf_local_key,
                        pf_remote_key,
                        pf_session_key,
                        pf_message_preffix,
                        pf_message_suffix,
                        pf_message_sequence_num,
                        pf_message_command_byte,
                        pf_message_payload_size,
                        pf_message_return_code,
                        pf_data_message,
                        pf_data_message_decrypted,
                        pf_data_message_decrypted_seq,
                        pf_data_hash,
                        pf_data_calculated_hash,
                        pf_dissector_state 
                    }

-- -- Preferences
-- local default_settings = {
--     variant = 1
-- }

-- local variant_pref_enum = {
--     { 1, "1", 1 },
--     { 2, "2", 2 }
-- }

-- tuya_protocol.prefs.variant = Pref.enum("Variant", default_settings.variant,
--     "The variant", variant_pref_enum)

tuya_protocol.prefs.device_key = Pref.string("Device key", "", "Device key of the TUYA device you are trying to decode")

if tuya_states == nil then
    tuya_states = {}
end
local f_ip_src = Field.new("ip.src")
local f_ip_dst = Field.new("ip.dst")
local HEADER_SIZE = 16

PREFIX = "000055AA"
SUFFIX = "0000AA55"

function tuya_protocol.dissector(buffer, pinfo, tree)
    print("\nParsing TUYA packet:")

    pinfo.cols.protocol = tuya_protocol.name
    
    local tuya_subtree = tree:add(tuya_protocol, buffer(), "Tuya Protocol Data")
    
    local length = buffer:len()
    
    src_ip = f_ip_src().value
    dst_ip = f_ip_dst().value

    local packet_no = 1

    -- Find all TUYA packets inside TCP packet and dissect them
    local buff_in_hexstream = buffer(0, length):bytes():tohex()
    local packet_bounds, packet_bounds_end = string.find(buff_in_hexstream, PREFIX .. "%x-" .. SUFFIX)

    while(packet_bounds ~= nil) do
        packet_start = (packet_bounds - 1) / 2
        packet_end = (packet_bounds_end) / 2
        packet_len =  packet_end - packet_start

        print("Start: " .. packet_start .. ", End: " .. packet_end .. ", Len: " .. packet_len)

        tuya_packet_buffer = buffer(packet_start, packet_len)
        
        -- add headers info
        local seq_num = tuya_packet_buffer(4,4)
        local command_byte = tuya_packet_buffer(8,4)
        local payload_size = tuya_packet_buffer(12,4)

        local command = command_byte:int()
        if command == 0x3 then
            ip_id = dst_ip
            tuya_states[ip_id] = "connected"
        elseif command == 0x4 then
            ip_id = src_ip
            tuya_states[ip_id] = "session_key"
        elseif command == 0x5 then
            tuya_states[ip_id] = "rename_device"
        else
            tuya_states[ip_id] = "other"
        end

        -- Remove return code
        -- If there is a return value, remove it (Return value is from the remote)
        local payload = nil
        local payload_empty = false
        local return_code = nil
        if(bit.band(tuya_packet_buffer(HEADER_SIZE, 4):uint(), 0xFFFFFF00) ~= 0) then
            if payload_size:uint() == 0x24 then payload_empty = true end
            payload = tuya_packet_buffer(HEADER_SIZE, payload_size:uint() - 0x24):bytes():raw()
        else
            if payload_size:uint() == 0x28 then payload_empty = true end
            payload = tuya_packet_buffer(HEADER_SIZE + 4, payload_size:uint() - 4 - 0x24):bytes():raw()
            return_code = tuya_packet_buffer(HEADER_SIZE, 4)
        end

        local calculated_hash = nil
        if tuya_states[ip_id] == "connected" then
            remote_key = nil
            session_key = nil
        
            -- Calculate hash and decrypt data
            calculated_hash = hmac_sha256(tuya_packet_buffer(0, packet_len - 32 - 4):bytes():raw())
            decrypted_payload = decrypt(payload)
        
            local_key = string.sub(decrypted_payload, 1, 32) -- 1B is 2 chars -> 16B are 32 chars
        
        elseif tuya_states[ip_id] == "session_key" then
            -- Calculate hash and decrypt data
            calculated_hash = hmac_sha256(tuya_packet_buffer(0, packet_len - 32 - 4):bytes():raw())
            decrypted_payload = decrypt(payload)
        
            remote_key = string.sub(decrypted_payload, 1, 32) -- 1B is 2 chars -> 16B are 32 chars
            session_key = Array.toString(Array.XOR(Array.fromHex(local_key), Array.fromHex(remote_key)))
            session_key = _encrypt(tuya_protocol.prefs.device_key, session_key)
        
        elseif tuya_states[ip_id] == "rename_device" then
            local tmp_session_key = session_key
            session_key = nil
        
            -- Calculate hash and decrypt data
            calculated_hash = hmac_sha256(tuya_packet_buffer(0, packet_len - 32 - 4):bytes():raw())
            decrypted_payload = decrypt(payload)
        
            session_key = tmp_session_key
        
        elseif tuya_states[ip_id] == "other" and command == 0x5 then
            -- Calculate hash and decrypt data
            calculated_hash = _hmac_sha256(tuya_protocol.prefs.device_key, tuya_packet_buffer(0, packet_len - 32 - 4):bytes():raw())
            decrypted_payload = _decrypt(tuya_protocol.prefs.device_key, payload)
        else
            -- Only calculate hash and check if any data is present. If it is -> decrypt the data
            calculated_hash = hmac_sha256(tuya_packet_buffer(0, packet_len - 32 - 4):bytes():raw())

            if payload_empty == true then
                decrypted_payload = nil
            else
                decrypted_payload = Array.toString(Array.fromHex(decrypt(payload)))
            end
        end

        if packet_no == 1 then
            tuya_subtree:add(pf_device_key, tuya_protocol.prefs.device_key)
            
            if local_key ~= nil then
                tuya_subtree:add(pf_local_key, local_key)
            end
            if remote_key ~= nil then
                tuya_subtree:add(pf_remote_key, remote_key)
            end
            if session_key ~= nil then
                tuya_subtree:add(pf_session_key, session_key)
            end
            
            -- Debug the state machine
            tuya_subtree:add(pf_dissector_state, tuya_states[ip_id]):add_expert_info(PI_DEBUG)
        end

        local tuya_packets_subtree = tuya_subtree:add(tuya_protocol, tuya_packet_buffer, "Tuya packet #" .. packet_no):append_text( " : " .. get_command_name(command_byte:uint()))
        pinfo.cols.info:append(" | packet #" .. packet_no .. " (" .. get_command_name(command_byte:uint()) .. ")")

        tuya_packets_subtree:add(pf_message_sequence_num, seq_num)
        tuya_packets_subtree:add(pf_message_command_byte, command_byte):append_text( " (" .. get_command_name(command_byte:uint()) .. ")")
        tuya_packets_subtree:add(pf_message_payload_size, payload_size)
        if return_code ~=nil then tuya_packets_subtree:add(pf_message_return_code, return_code) end
        
        -- add data info
        local payload_subtree = tuya_packets_subtree:add(tuya_protocol, tuya_packet_buffer(16, packet_len - 16), "Payload") -- minus checksum and suffix

        local message = tuya_packet_buffer(16, packet_len - 16 - 32 - 4) -- minus first 32 and last (32 + 4, checksum and suffix)
        local hash = tuya_packet_buffer(packet_len - 32 - 4, 32) -- minus checksum and suffix

        -- If has payload add payload to subtree
        if payload_empty ~= true then
            payload_subtree:add(pf_data_message, message)

            local decrypted_payload_no_zeros = decrypted_payload
            local decrypted_seq = nil
            if string.sub(decrypted_payload, 1, 3) == "3.4" then
                decrypted_seq = Struct.unpack(">I2", string.sub(decrypted_payload, 10, 11))
                decrypted_payload_no_zeros = string.gsub(decrypted_payload, "\0", "") 
            end
            
            -- print(type(decrypted_seq))
            -- print(Struct.unpack(">I2", decrypted_seq))
            payload_subtree:add(pf_data_message_decrypted, decrypted_payload_no_zeros)
            
            if decrypted_seq ~= nil then
                payload_subtree:add(pf_data_message_decrypted_seq, decrypted_seq)
                decrypted_seq = nil
            end
        end
        payload_subtree:add(pf_data_hash, hash)
        local tree_item = payload_subtree:add(pf_data_calculated_hash, calculated_hash)
        
        local exp_hash = hash:bytes()
        local calc_hash = ByteArray.new(calculated_hash)
        if exp_hash == calc_hash then
            tree_item:append_text(" [MATCHES] ")
        else
            tree_item:append_text(" [DOES NOT MATCH] ")
        end

        -- Try to find next message
        packet_bounds, packet_bounds_end = string.find(buff_in_hexstream, PREFIX .. "%x-" .. SUFFIX, packet_bounds_end)
        packet_no = packet_no + 1
    end
    

end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(6668, tuya_protocol)



function get_command_name(command)
    local command_name = "UNKNOWN"

        if command == 0 then command_name = "UDP"
    elseif command == 1 then command_name = "AP_CONFIG"
    elseif command == 2 then command_name = "ACTIVE"
    elseif command == 3 then command_name = "BIND"
    elseif command == 4 then command_name = "RENAME_GW"
    elseif command == 5 then command_name = "RENAME_DEVICE"
    elseif command == 6 then command_name = "UNBIND"
    elseif command == 7 then command_name = "CONTROL"
    elseif command == 8 then command_name = "STATUS"
    elseif command == 9 then command_name = "HEART_BEAT"
    elseif command == 10 then command_name = "DP_QUERY"
    elseif command == 11 then command_name = "QUERY_WIFI"
    elseif command == 12 then command_name = "TOKEN_BIND"
    elseif command == 13 then command_name = "CONTROL_NEW"
    elseif command == 14 then command_name = "ENABLE_WIFI"
    elseif command == 16 then command_name = "DP_QUERY_NEW"
    elseif command == 17 then command_name = "SCENE_EXECUTE"
    elseif command == 18 then command_name = "DP_REFRESH"
    elseif command == 19 then command_name = "UDP_NEW"
    elseif command == 20 then command_name = "AP_CONFIG_NEW"
    elseif command == 240 then command_name = "LAN_GW_ACTIVE"
    elseif command == 241 then command_name = "LAN_SUB_DEV_REQUEST"
    elseif command == 242 then command_name = "LAN_DELETE_SUB_DEV"
    elseif command == 243 then command_name = "LAN_REPORT_SUB_DEV"
    elseif command == 244 then command_name = "LAN_SCENE"
    elseif command == 245 then command_name = "LAN_PUBLISH_CLOUD_CONFIG"
    elseif command == 246 then command_name = "LAN_PUBLISH_APP_CONFIG"
    elseif command == 247 then command_name = "LAN_EXPORT_APP_CONFIG"
    elseif command == 248 then command_name = "LAN_PUBLISH_SCENE_PANEL"
    elseif command == 249 then command_name = "LAN_REMOVE_GW"
    elseif command == 250 then command_name = "LAN_CHECK_GW_UPDATE"
    elseif command == 251 then command_name = "LAN_GW_UPDATE"
    elseif command == 252 then command_name = "LAN_SET_GW_CHANNEL" 
    end

    return command_name
end




-- function crc32(bytes)
--     local crc = 0xFFFFFFFF
  
--     for i = 0, bytes:len()-1 do
--       crc = bit.bxor(bit.rshift(crc, 8), crc32Table[bit.band(bit.bxor(crc, bytes.get_index(i)), 255)])
--     end
  
--     return bit.bxor(crc, 0xFFFFFFFF)
-- end


-- local crc32Table = {
--   0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA,
--   0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
--   0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
--   0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
--   0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE,
--   0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
--   0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC,
--   0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
--   0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
--   0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
--   0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940,
--   0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
--   0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116,
--   0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
--   0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
--   0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
--   0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A,
--   0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
--   0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818,
--   0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
--   0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
--   0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
--   0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C,
--   0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
--   0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2,
--   0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
--   0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
--   0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
--   0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086,
--   0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
--   0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4,
--   0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
--   0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
--   0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
--   0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8,
--   0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
--   0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE,
--   0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
--   0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
--   0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
--   0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252,
--   0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
--   0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60,
--   0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
--   0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
--   0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
--   0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04,
--   0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
--   0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A,
--   0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
--   0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
--   0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
--   0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E,
--   0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
--   0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C,
--   0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
--   0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
--   0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
--   0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0,
--   0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
--   0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6,
--   0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
--   0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
--   0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
-- }