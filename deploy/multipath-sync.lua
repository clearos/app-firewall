------------------------------------------------------------------------------
--
-- ClearOS Firewall
--
-- Multipath synchronization utility.
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
-- M A I N
--
-- Synchronize main routing table (254) with multipath routing tables (50,
-- 100, 101, ...)
--
------------------------------------------------------------------------------

echo("Synchronizing multipath routing tables...")

-- Load external firewall initialization routines
firewall_init = assert(loadfile("/usr/clearos/apps/firewall/deploy/libfirewall.lua"))
firewall_init();

LoadEnvironment()
NetworkInterfaces()

-- Bail if multipath is disabled or not enough (< 2) interfaces
if MULTIPATH ~= "on" or table.getn(WANIF) < 2 then
    return
end

-- Sort WAN interfaces
table.sort(WANIF)

-- Setup multipath routing tables
mr_init = assert(loadfile("/usr/clearos/apps/firewall/deploy/libmultipath.lua"))
mr_init()

RunMultipathRouting()

execute(IPBIN .. " route flush cache")

-- vi: syntax=lua ts=4
