-- Lua Dissector for ST 2110_30
-- Author: Jaewon Kim (resource@kbs.co.kr)
--
-- to use in Wireshark:
-- 1) Ensure your Wireshark works with Lua plugins - "About Wireshark" should say it is compiled with Lua
-- 2) Install this dissector in the proper plugin directory - see "About Wireshark/Folders" to see Personal
--    and Global plugin directories.  After putting this dissector in the proper folder, "About Wireshark/Plugins"
--    should list "ST-2110_30.lua"
-- 3) In Wireshark Preferences, under "Protocols", set st_2110_30 as dynamic payload type being used, bitrate
--    and number of channel. Mismatch between captured data and input value would make decoding error.
-- 4) Capture packets of ST 2110_30
-- 5) "Decode As" those UDP packets as RTP
-- 6) You will now see the ST 2110_30 Data dissection of the RTP payload
--
-- This program is based on ST 2110_20 dissector made by Thomas Edwasrds.
-- This program is free software; you can redistribute it and/or
-- modify it under the terms of the GNU General Public License
-- as published by the Free Software Foundation; either version 2
-- of the License, or (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
--
------------------------------------------------------------------------------------------------
do
    local st_2110_30 = Proto("st_2110_30", "ST 2110_30")
    local prefs = st_2110_30.prefs

    prefs.dyn_pt = Pref.uint("ST 2110_30 dynamic payload type", 97, "The value > 96")
    prefs.num_ch_audio = Pref.uint("Number of audio channel", 16)
    prefs.bitrate = Pref.uint("Bitrate", 24)

    local F = st_2110_30.fields
    F.AudioData=ProtoField.bytes("ST_2110_30.Audio_Data","Audio Data") -- defined but not used

    function st_2110_30.dissector(tvb, pinfo, tree)
        local subtree = tree:add(st_2110_30, tvb(),"ST 2110_30 Data")
        local datalength = pinfo.len-54
        subtree:append_text(", Length: ".. datalength.. " byte")
        local channels = prefs.num_ch_audio
        local bitdepth = prefs.bitrate
        local bytepersample = bitdepth / 8 
        local numberofsamples = datalength / (channels * bytepersample)
        subtree:append_text(", Samples per packet: ".. numberofsamples)
        
        Offset=0
        
        for i=1,numberofsamples do
            local data = tvb(Offset,48)
            subtree:add(data, "Sample No.".. i..": ", tostring(data))
            Offset=Offset+48
        end
    end

    -- register dissector to dynamic payload type dissectorTable
    local dyn_payload_type_table = DissectorTable.get("rtp_dyn_payload_type")
    dyn_payload_type_table:add("st_2110_30", st_2110_30)

    -- -- register dissector to RTP payload type
    local payload_type_table = DissectorTable.get("rtp.pt")
    local old_dissector = nil
    local old_dyn_pt = 0
    function st_2110_30.init()
        if (prefs.dyn_pt ~= old_dyn_pt) then
            if (old_dyn_pt > 0) then
                if (old_dissector == nil) then
                    payload_type_table:remove(old_dyn_pt, st_2110_30)
                else
                    payload_type_table:add(old_dyn_pt, old_dissector)
                end
            end
            old_dyn_pt = prefs.dyn_pt
            old_dissector = payload_type_table:get_dissector(old_dyn_pt)
            if (prefs.dyn_pt > 0) then
                payload_type_table:add(prefs.dyn_pt, st_2110_30)
            end
        end
    end
end
