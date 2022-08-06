tuya_protocol = Proto("Tuya", "Tuya Protocol")

local message_preffix = ProtoField.uint32("tuya.message_preffix", "Preffix", base.HEX)
local message_suffix = ProtoField.uint32("tuya.message_suffix", "Suffix", base.HEX)

local message_sequence_num = ProtoField.uint32("tuya.sequence_number", "Sequence Number", base.UINT)
local message_command_byte = ProtoField.uint32("tuya.command_byte", "Command Byte", base.HEX)
local message_payload_size = ProtoField.uint32("tuya.payload_size", "Payload Size", base.UINT)

local data_message = ProtoField.bytes("tuya.data_message", "Data Message", base.SPACE)
local data_hash = ProtoField.bytes("tuya.data_hash", "Data Hash", base.SPACE)

-- DEBUG
local dissector_state = ProtoField.string("tuya.dissector.state", "Dissector State", base.ASCII)

tuya_protocol.fields = { message_preffix, message_suffix, message_sequence_num, message_command_byte, message_payload_size, data_message, data_hash, dissector_state }

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

tuya_protocol.prefs.local_key = Pref.string("Device local_key", "", "Local key of the TUYA device you are trying to decode")

if tuya_states == nil then
    tuya_states = {}
end
local f_ip_src = Field.new("ip.src")
local f_ip_dst = Field.new("ip.dst")

function tuya_protocol.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    --if length == 0 then return end

    pinfo.cols.protocol = tuya_protocol.name

    local tuya_subtree = tree:add(tuya_protocol, buffer(), "Tuya Protocol Data")

    -- check if message has prefixes
    local prefix = buffer(0,4):uint()
    local suffix = buffer(length - 4, 4):uint()
    if preffix ~= 0x000055aa and suffix ~= 0x0000aa55 then 
        tuya_subtree:append_text(" : Invalid prefix or suffix")
        tuya_subtree:add(message_preffix, prefix)
        tuya_subtree:add(message_suffix, suffix)
        return 
    end

    
    -- add headers info
    local seq_num = buffer(4,4)
    local command_byte = buffer(8,4)
    local payload_size = buffer(12,4)

    src_ip = f_ip_src().value
    dst_ip = f_ip_dst().value

    local command = command_byte:int()
    if command == 0x3 then
        ip_id = dst_ip
        tuya_states[ip_id] = "connected"
    elseif command == 0x4 then
        ip_id = src_ip
        tuya_states[ip_id] = "shared_key"
    end

    tuya_subtree:add(message_sequence_num, seq_num)
    tuya_subtree:add(message_command_byte, command_byte):append_text( " (" .. get_command_name(command_byte:uint()) .. ")")
    tuya_subtree:add(message_payload_size, payload_size)


    -- add data info
    local payload_subtree = tuya_subtree:add(tuya_protocol, buffer(16, length - 16), "Data") -- minus checksum and suffix

    local message = buffer(16, length - 16 - 32 - 4) -- minus first 32 and last (32 + 4, checksum and suffix)
    local hash = buffer(length - 32 - 4, 32) -- minus checksum and suffix

    payload_subtree:add(data_message, message)
    payload_subtree:add(data_hash, hash)
    payload_subtree:add(dissector_state, tuya_states[ip_id]):add_expert_info(PI_DEBUG)

    -- print(crc32)
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(6668, tuya_protocol)



function get_command_name(command)
    local command_name = "Unknown"

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