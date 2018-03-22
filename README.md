# smpte2110-20 dissector


Lua Dissector for ST 2110_30
Author: Jaewon Kim (resource@kbs.co.kr)

to use in Wireshark:
1) Ensure your Wireshark works with Lua plugins - "About Wireshark" should say it is compiled with Lua
2) Install this dissector in the proper plugin directory - see "About Wireshark/Folders" to see Personal
   and Global plugin directories.  After putting this dissector in the proper folder, "About Wireshark/Plugins"
   should list "ST-2110_30.lua"
3) In Wireshark Preferences, under "Protocols", set st_2110_30 as dynamic payload type being used, bitrate
   and number of channel. Mismatch between captured data and input value would make decoding error.
4) Capture packets of ST 2110_30
5) "Decode As" those UDP packets as RTP
6) You will now see the ST 2110_30 Data dissection of the RTP payload

This program is based on ST 2110_20 dissector made by Thomas Edwasrds.
This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.
This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
