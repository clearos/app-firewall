------------------------------------------------------------------------------
--
-- ClearOS Firewall
--
-- Multipath routing routines.  This code is now a shared external Lua chunk
-- so that it can be used by other scripts.
--
------------------------------------------------------------------------------
--
-- Copyright (C) 2011 ClearFoundation
-- 
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
-- You should have received a copy of the GNU General Public License
-- along with this program; if not, write to the Free Software
-- Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

------------------------------------------------------------------------------
--
-- F U N C T I O N S
--
------------------------------------------------------------------------------

------------------------------------------------------------------------------
--
-- RunMultipathRouting
--
-- Create and sync multipath routing tables (50, 100, 101, ...).
--
------------------------------------------------------------------------------

function RunMultipathRouting()
    local ifn
    local t = 100
    local ip, netmask, network, prefix

    -- Create high-priority "main" routing table
    execute(IPBIN .. " route flush table 50")
    execute(IPBIN .. " route ls table main | grep -Ev ^default | while read LINE; do " ..
        IPBIN .. " route add table 50 $LINE; done")

    -- Create interface routing tables
    for _, ifn in pairs(WANIF) do
        ip, netmask, network, prefix = GetInterfaceInfo(ifn)

        execute(string.format("%s route flush table %s", IPBIN, t))
        execute(string.format("%s route ls table main | grep -Ev ^default | while read LINE; do " ..
            "HOST=$(echo $LINE | awk '{ print $1 }'); DEV=$(echo $LINE | awk '{ print $3 }'); " ..
            "if [ \"$HOST\" == \"%s\" -a \"$DEV\" != \"%s\" ]; then continue; fi; " ..
            "%s route add table %d $LINE; done",
            IPBIN, GetInterfaceGateway(ifn), ifn, IPBIN, t))
        execute(string.format("%s route add table %d default via %s dev %s",
            IPBIN, t, GetInterfaceGateway(ifn), ifn))

        t = t + 1
    end
end

-- vi: syntax=lua ts=4
