local tap = Listener.new("frame", "udp.port == 14550")
local captured = false
local file = io.open("mavlink_hex_stream.txt file path", "w")

function tap.packet(pinfo, tvb)
	if not captured then
		local mavlink_data = tvb:range(42):tvb()
		local hex_stream = mavlink_data:bytes():tohex(false, " ")
		
		local msgid = tvb:range(49, 3):le_uint()
		
		if msgid == 0 then
			file:write(hex_stream .. "\n")
			captured = true
			file:close()
		end
	end
end

function tap.reset()
	file:close()
end
