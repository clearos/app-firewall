------------------------------------------------------------------------------
--
-- ClearOS Firewall
--
-- External initialization routines.  This code is now a shared external Lua
-- chunk so that it can be used by other scripts.
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
-- Explode
--
-- Explodes a delimited string into a Lua table.
--
------------------------------------------------------------------------------

function Explode(d, s)
    local i = 0
    local p = 0
    local l = 0
    local t = {}

    while true do
        i = string.find(s, d, i + 1)

        if i ~= nil then
            l = i - 1
        else
            l = string.len(s)
        end

        table.insert(t, string.sub(s, p, l))
        if i == nil then break end

        p = i + 1
    end

    return t
end

------------------------------------------------------------------------------
--
-- PackWhitespace
--
-- Removes redundant white-space from supplied string.
--
------------------------------------------------------------------------------

function PackWhitespace(s)
    local c = 1

    while c > 0 do
        s, c = string.gsub(s, "  ", " ")
    end

    c = 1
    while c > 0 do
        s, c = string.gsub(s, "\t\t", " ")
    end

    c = 1
    while c > 0 do
        s, c = string.gsub(s, "\n\n", " ")
    end

    return s
end

------------------------------------------------------------------------------
--
-- TableCount
--
-- Returns the number of items in a dictionary table (where getn doesn't work).
--
------------------------------------------------------------------------------

function TableCount(t)
    local k
    local v
    local c = 0
    for k, v in pairs(t) do c = c + 1 end
    return c
end

------------------------------------------------------------------------------
--
-- TablePrint
--
-- Print contents of a dictionary table to assist debugging.
--
------------------------------------------------------------------------------

function TablePrint(t)
    local k
    local v
    local c = 0
    for k, v in pairs(t) do
        if(type(v) == 'table') then
            debug(string.format("%4d: %20s => {", c, k))
            TablePrint(v)
            debug(string.format("%26s", "}"))
        else
            debug(string.format("%4d: %20s => %s", c, k, v))
        end
        c = c + 1
    end
end

------------------------------------------------------------------------------
--
-- ValidateRule
--
-- Perform a series of sanity checks (address resolution) on a rule.  If the
-- rule is found to be invalid, the rule is temporary disabled and is also
-- added to an invalid rule state file (for other programs to see).
--
------------------------------------------------------------------------------

function StripIpMask(ip)
    _ = string.find(ip, "/")
    if _ == nil then
        return ip
    else
        return string.sub(ip, 0, _ - 1)
    end
end

function DisableRule(r_type, r_proto, r_addr, r_port, r_param)
    local f = io.open("/var/clearos/firewall/invalid.state", "a+")
    f:write(string.format("||0x%08x|%d|%s|%s|%s\n", r_type, r_proto, r_addr, r_port, r_param))
    io.close(f)

    r_type = r_type - tonumber(os.getenv("FWR_ENABLED"))
    return string.format("||0x%08x|%d|%s|%s|%s", r_type, r_proto, r_addr, r_port, r_param)
end

function ValidateRule(r)
    local r_type, r_proto, r_addr, r_port, r_param
    local ip1, ip2
    local network, prefix
    local ifn_wan = nil

    r_type, r_proto, r_addr, r_port, r_param = ExpandRule(r)

    if b_and(r_type, tonumber(os.getenv("FWR_ENABLED"))) == 0 then
        return r
    end

    if b_and(r_type, tonumber(os.getenv("FWR_IFADDRESS"))) ~= 0 then
        if if_exists(r_addr) then
            ip1, _, _, _ = GetInterfaceInfo(r_addr)
            r = string.format("||0x%08x|%d|%s|%s|%s", r_type, r_proto, ip1, r_port, r_param)
        else
            r = DisableRule(r_type, r_proto, r_addr, r_port, r_param)
        end
    end

    if b_and(r_type, tonumber(os.getenv("FWR_IFNETWORK"))) ~= 0 then
        if if_exists(r_addr) then
            _, _, network, prefix = GetInterfaceInfo(r_addr)
            r = string.format("||0x%08x|%d|%s/%s|%s|%s", r_type, r_proto, network, prefix, r_port, r_param)
        else
            r = DisableRule(r_type, r_proto, r_addr, r_port, r_param)
        end
    end

    if (b_and(r_type, tonumber(os.getenv("FWR_INCOMING_BLOCK"))) ~= 0 or
        b_and(r_type, tonumber(os.getenv("FWR_DMZ_INCOMING"))) ~= 0 or
        b_and(r_type, tonumber(os.getenv("FWR_DMZ_PINHOLE"))) ~= 0 or
        b_and(r_type, tonumber(os.getenv("FWR_PROXY_BYPASS"))) ~= 0 or
        b_and(r_type, tonumber(os.getenv("FWR_FORWARD"))) ~= 0) and
        b_and(r_type, tonumber(os.getenv("FWR_MAC_SOURCE"))) == 0 then

        ip1 = gethostbyname(StripIpMask(r_addr))

        if ip1 == nil then
            r = DisableRule(r_type, r_proto, r_addr, r_port, r_param)
        else
            r = string.format("||0x%08x|%d|%s|%s|%s", r_type, r_proto, r_addr, r_port, r_param)
        end
    elseif b_and(r_type, tonumber(os.getenv("FWR_OUTGOING_BLOCK"))) ~= 0 and
        b_and(r_type, tonumber(os.getenv("FWR_MAC_SOURCE"))) == 0 and
        r_addr ~= nil and string.len(r_addr) ~= 0 then

        ip1 = gethostbyname(StripIpMask(r_addr))

        if ip1 == nil then
            r = DisableRule(r_type, r_proto, r_addr, r_port, r_param)
        else
            r = string.format("||0x%08x|%d|%s|%s|%s", r_type, r_proto, r_addr, r_port, r_param)
        end
    elseif b_and(r_type, tonumber(os.getenv("FWR_ONE_TO_ONE"))) ~= 0 then

        ip1 = gethostbyname(r_addr)
        ip2 = gethostbyname(r_param)

        _ = string.find(r_param, "_")

        if _ == 1 then
            ip2 = string.sub(r_param, 2)
        elseif _ ~= nil then
            ifn_wan = string.sub(r_param, 1, _ - 1)
            ip2 = string.sub(r_param, _ + 1)
        end

        if ifn_wan ~= nil then ip2 = ifn_wan .. "_" .. ip2 end

        if ip1 == nil or ip2 == nil then
            r = DisableRule(r_type, r_proto, r_addr, r_port, r_param)
        else
            r = string.format("||0x%08x|%d|%s|%s|%s", r_type, r_proto, ip1, r_port, ip2)
        end
    end

    return r
end

------------------------------------------------------------------------------
--
-- CalculateRateToQuantum
--
-- Calculate a suitable "r2q" value for HTB qdisc.
--
------------------------------------------------------------------------------

function CalculateRateToQuantum(rate)
    local r2q = 1
    local quantum = 20000

    while quantum > 1500 do
        quantum = (rate * 1000 / 8) / r2q
        r2q = r2q + 1
    end

    r2q = r2q - 2
    quantum = (rate * 1000 / 8) / r2q
    debug("Auto-r2q for minimum rate " .. rate ..
        ": " .. r2q .. " (quantum: " .. quantum .. ")")

    return r2q
end

------------------------------------------------------------------------------
--
-- LoadEnvironment
--
-- Load and parse environment variables as Lua globals
--
------------------------------------------------------------------------------

function LoadEnvironment()
    local i, f, t
    local ifn
    local rule
    local rules = {}

    echo("Loading environment")

    TABLES = { "filter", "mangle", "nat" }

    -- Exported firewall configuration variables 
    FW_MODE = os.getenv("MODE")
    FW_ADHOC = os.getenv("FW_ADHOC")
    FW_PROTO = os.getenv("FW_PROTO")

    WANIF = os.getenv("EXTIF")
    WANIF_BACKUP = os.getenv("EXTIF_BACKUP")
    WANIF_STANDBY = os.getenv("EXTIF_STANDBY")
    SYSWATCH_WANIF = os.getenv("SYSWATCH_WANIF")
    LANIF = os.getenv("LANIF")
    HOTIF = os.getenv("HOTIF")
    DMZIF = os.getenv("DMZIF")
    WIFIF = os.getenv("WIFIF")

    IFCFG = EnumerateInterfaceConfigs()

    BANDWIDTH_QOS = os.getenv("BANDWIDTH_QOS")
    BANDWIDTH_UPSTREAM = os.getenv("BANDWIDTH_UPSTREAM")
    BANDWIDTH_UPSTREAM_BURST = os.getenv("BANDWIDTH_UPSTREAM_BURST")
    BANDWIDTH_UPSTREAM_CBURST = os.getenv("BANDWIDTH_UPSTREAM_CBURST")
    BANDWIDTH_DOWNSTREAM = os.getenv("BANDWIDTH_DOWNSTREAM")
    BANDWIDTH_DOWNSTREAM_BURST = os.getenv("BANDWIDTH_DOWNSTREAM_BURST")
    BANDWIDTH_DOWNSTREAM_CBURST = os.getenv("BANDWIDTH_DOWNSTREAM_CBURST")

    QOS_ENABLE = os.getenv("QOS_ENABLE")
    QOS_ENGINE = os.getenv("QOS_ENGINE")
    QOS_UPSTREAM = os.getenv("QOS_UPSTREAM")
    QOS_DOWNSTREAM = os.getenv("QOS_DOWNSTREAM")
    QOS_UPSTREAM_BWRES= os.getenv("QOS_UPSTREAM_BWRES")
    QOS_DOWNSTREAM_BWRES= os.getenv("QOS_DOWNSTREAM_BWRES")
    QOS_UPSTREAM_BWLIMIT= os.getenv("QOS_UPSTREAM_BWLIMIT")
    QOS_DOWNSTREAM_BWLIMIT= os.getenv("QOS_DOWNSTREAM_BWLIMIT")
    QOS_PRIOMARK4 = os.getenv("QOS_PRIOMARK4")
    QOS_PRIOMARK6 = os.getenv("QOS_PRIOMARK6")
    QOS_PRIOMARK4_CUSTOM = os.getenv("QOS_PRIOMARK4_CUSTOM")
    QOS_PRIOMARK6_CUSTOM = os.getenv("QOS_PRIOMARK6_CUSTOM")

    SQUID_USER_AUTHENTICATION = os.getenv("SQUID_USER_AUTHENTICATION")
    SQUID_TRANSPARENT = os.getenv("SQUID_TRANSPARENT")

    IPSEC_SERVER = os.getenv("IPSEC_SERVER")
    PPTP_SERVER = os.getenv("PPTP_SERVER")
    PPTP_PASSTHROUGH_FORCE = os.getenv("PPTP_PASSTHROUGH_FORCE")

    ONE_TO_ONE_NAT_MODE = os.getenv("ONE_TO_ONE_NAT_MODE")

    MULTIPATH = os.getenv("MULTIPATH")
    MULTIPATH_WEIGHTS = os.getenv("MULTIPATH_WEIGHTS")
    MULTIPATH_SKIP_DOWN_WANIF = os.getenv("MULTIPATH_SKIP_DOWN_WANIF")

    RULES = os.getenv("RULES")

    GATEWAYDEV = os.getenv("GATEWAYDEV")

    FW_ACCEPT = os.getenv("FW_ACCEPT")
    FW_DROP = os.getenv("FW_DROP")
    FW_LOG_DROPS = os.getenv("FW_LOG_DROPS")

    IFCONFIG = os.getenv("IFCONFIG")
    IPBIN = os.getenv("IPBIN")
    MODPROBE = os.getenv("MODPROBE")
    RMMOD = os.getenv("RMMOD")
    SYSCTL = os.getenv("SYSCTL")
    TCBIN = os.getenv("TCBIN")

    EGRESS_FILTERING = os.getenv("EGRESS_FILTERING")
    PROTOCOL_FILTERING = os.getenv("PROTOCOL_FILTERING")

    -- Validate variables
    if FW_MODE == nil then error("MODE not defined")
    else debug("FW_MODE=" .. FW_MODE) end

    if FW_PROTO == nil then error("FW_PROTO not defined")
    else debug("FW_PROTO=" .. FW_PROTO) end

    if WANIF == nil then
        error("WANIF not defined")
    else
        t = {}
        WANIF = Explode(" ", WANIF)
        for i, ifn in pairs(WANIF) do
            if ifn ~= nil and string.len(ifn) ~= 0 and string.find(ifn, ":") == nil then
                table.insert(t, ifn)
                debug("WANIF=" .. ifn)
            end
        end
        WANIF = t
    end

    if WANIF_BACKUP == nil then
        WANIF_BACKUP = {}
    else
        t = {}
        WANIF_BACKUP = Explode(" ", WANIF_BACKUP)
        for i, ifn in pairs(WANIF_BACKUP) do
            if ifn ~= nil and string.len(ifn) ~= 0 and string.find(ifn, ":") == nil then
                table.insert(t, ifn)
                debug("WANIF_BACKUP=" .. ifn)
            end
        end
        WANIF_BACKUP = t
    end

    if WANIF_STANDBY == nil then
        WANIF_STANDBY = {}
    else
        t = {}
        WANIF_STANDBY = Explode(" ", WANIF_STANDBY)
        for i, ifn in pairs(WANIF_STANDBY) do
            if ifn ~= nil and string.len(ifn) ~= 0 and string.find(ifn, ":") == nil then
                table.insert(t, ifn)
                debug("WANIF_STANDBY=" .. ifn)
            end
        end
        WANIF_STANDBY = t
    end

    if LANIF == nil then
        error("LANIF not defined")
    else
        t = {}
        LANIF = Explode(" ", LANIF)
        for i, ifn in pairs(LANIF) do
            if ifn ~= nil and string.len(ifn) ~= 0 and string.find(ifn, ":") == nil then
                table.insert(t, ifn)
                debug("LANIF=" .. ifn)
            end
        end
        LANIF = t
    end

    if HOTIF ~= nil then
        t = {}
        HOTIF = Explode(" ", HOTIF)
        for i, ifn in pairs(HOTIF) do
            if ifn ~= nil and string.len(ifn) ~= 0 and string.find(ifn, ":") == nil then
                table.insert(t, ifn)
                table.insert(LANIF, ifn)
                debug("HOTIF=" .. ifn)
            end
        end
        HOTIF = t
    else
        HOTIF = {}
    end

    if DMZIF == nil then
        error("DMZIF not defined")
    else
        t = {}
        DMZIF = Explode(" ", DMZIF)
        for i, ifn in pairs(DMZIF) do
            if ifn ~= nil and string.len(ifn) ~= 0 and string.find(ifn, ":") == nil then
                table.insert(t, ifn)
                debug("DMZIF=" .. ifn)
            end
        end
        DMZIF = t

        if FW_MODE == "gateway" and table.getn(DMZIF) ~= 0 then
            FW_MODE = "dmz"
            debug("Switching from gateway to DMZ mode, DMZ interface(s) detected")
        elseif FW_MODE == "dmz" and table.getn(DMZIF) == 0 then
            FW_MODE = "gateway"
            debug("Switching from DMZ mode to gateway mode, no DMZ interface(s) detected")
        end
    end

    if SYSWATCH_WANIF == nil then
        SYSWATCH_WANIF = {}
    else
        t = {}
        SYSWATCH_WANIF = Explode(" ", SYSWATCH_WANIF)
        for i, ifn in pairs(SYSWATCH_WANIF) do
            if ifn ~= nil and string.len(ifn) ~= 0 then
                table.insert(t, ifn)
                debug("SYSWATCH_WANIF=" .. ifn)
            end
        end
        SYSWATCH_WANIF = t
    end

    if WIFIF == nil then WIFIF="" end
    debug("WIFIF=" .. WIFIF)

    if BANDWIDTH_QOS == nil then BANDWIDTH_QOS="off" end
    debug("BANDWIDTH_QOS=" .. BANDWIDTH_QOS)

    if QOS_ENGINE == nil then QOS_ENGINE ="internal" end
    debug("QOS_ENGINE=" .. QOS_ENGINE)

    if SQUID_USER_AUTHENTICATION == nil then SQUID_USER_AUTHENTICATION = "off" end
    debug("SQUID_USER_AUTHENTICATION=" .. SQUID_USER_AUTHENTICATION)

    if SQUID_TRANSPARENT == nil then SQUID_TRANSPARENT = "off" end
    debug("SQUID_TRANSPARENT=" .. SQUID_TRANSPARENT)

    if IPSEC_SERVER == nil then IPSEC_SERVER = "off" end
    debug("IPSEC_SERVER=" .. IPSEC_SERVER)

    if PPTP_SERVER == nil then PPTP_SERVER = "off" end
    debug("PPTP_SERVER=" .. PPTP_SERVER)

    if ONE_TO_ONE_NAT_MODE == nil then ONE_TO_ONE_NAT_MODE = "type2" end
    debug("ONE_TO_ONE_NAT_MODE=" .. ONE_TO_ONE_NAT_MODE)

    if MULTIPATH == nil then MULTIPATH = "off"
    elseif MULTIPATH == "yes" then MULTIPATH = "on" end

    if MULTIPATH == "on" then
        if MULTIPATH_WEIGHTS == nil or MULTIPATH_WEIGHTS == "" then
            MULTIPATH_WEIGHTS = {}
            for _, ifn in pairs(WANIF) do
                table.insert(MULTIPATH_WEIGHTS, ifn .. "|1")
            end
        else
            t = {}
            MULTIPATH_WEIGHTS = Explode(" ", MULTIPATH_WEIGHTS)
            for i, ifn in pairs(MULTIPATH_WEIGHTS) do
                if ifn ~= nil and string.len(ifn) ~= 0 then
                    table.insert(t, ifn)
                    debug("MULTIPATH_WEIGHTS=" .. ifn)
                end
            end
            MULTIPATH_WEIGHTS = t
        end
    end

    if MULTIPATH_SKIP_DOWN_WANIF ~= nil and MULTIPATH_SKIP_DOWN_WANIF ~= "off" then
        MULTIPATH_SKIP_DOWN_WANIF = nil
    end

    -- Empty invalid rule state file
    f = io.open("/var/clearos/firewall/invalid.state", "w+")
    if f ~= nil then io.close(f) end

    -- Explode rules in to a table
    if RULES ~= nil then
        rules = Explode(" ", string.gsub(PackWhitespace(RULES), "\t", ""))
    end

    -- Validate firewall rules
    RULES = {}
    for _, rule in pairs(rules) do
        if rule ~= nil and string.len(rule) ~= 0 then
            rule = ValidateRule(rule)
            table.insert(RULES, rule)
            debug("RULES=" .. rule)
        end
    end

    if FW_DROP == nil then FW_DROP = "DROP" end
    debug("FW_DROP=" .. FW_DROP)

    if FW_ACCEPT == nil then FW_ACCEPT = "ACCEPT" end
    debug("FW_ACCEPT=" .. FW_ACCEPT)

    if IPBIN == nil then IPBIN = "/sbin/ip" end
    debug("IPBIN=" .. IPBIN)

    if TCBIN == nil then TCBIN = "/sbin/tc" end
    debug("TCBIN=" .. TCBIN)

    if MODPROBE == nil then MODPROBE = "/sbin/modprobe" end
    debug("MODPROBE=" .. MODPROBE)

    if RMMOD == nil then RMMOD = "/sbin/rmmod" end
    debug("RMMOD=" .. RMMOD)

    if SYSCTL == nil then SYSCTL = "/sbin/sysctl" end
    debug("SYSCTL=" .. SYSCTL)

    if IFCONFIG == nil then IFCONFIG = "/sbin/ifconfig" end
    debug("IFCONFIG=" .. IFCONFIG)

    if PPTP_PASSTHROUGH_FORCE == nil then PPTP_PASSTHROUGH_FORCE = "no" end
    debug("PPTP_PASSTHROUGH_FORCE=" .. PPTP_PASSTHROUGH_FORCE)

    if EGRESS_FILTERING == nil then
        EGRESS_FILTERING = "off"
    elseif EGRESS_FILTERING ~= "on" and EGRESS_FILTERING ~= "off" then
        EGRESS_FILTERING = "off"
    end
    debug("EGRESS_FILTERING=" .. EGRESS_FILTERING)

    if PROTOCOL_FILTERING == nil then
        PROTOCOL_FILTERING = "off"
    elseif PROTOCOL_FILTERING ~= "on" and PROTOCOL_FILTERING ~= "off" then
        PROTOCOL_FILTERING = "off"
    end

    if PROTOCOL_FILTERING == "on" then
        if execute("/etc/init.d/l7-filter status >/dev/null 2>&1") ~= 0 then
            echo("WARNING: l7-filter is not running, disabling protocol filtering.")
            PROTOCOL_FILTERING = "off"
        end
    end
    debug("PROTOCOL_FILTERING=" .. PROTOCOL_FILTERING)
end

------------------------------------------------------------------------------
--
-- GetInterfaceInfo
--
-- Returns variables containing an interface's address, netmask, network, and
-- prefix.
--
------------------------------------------------------------------------------

function GetInterfaceInfo(ifn)
    local ip = if_address(ifn)
    local netmask = "255.255.255.255"
    local network = "0.0.0.0"
    local prefix = 32

    if if_isppp(ifn) then
        network = if_dst_address(ifn)
    else
        netmask = if_netmask(ifn)
        if netmask == "255.255.255.255" then
            network = ip
        else
            network = ip_network(ip, netmask)
        end
        prefix = ip_prefix(netmask)
    end

    return ip, netmask, network, prefix
end

------------------------------------------------------------------------------
--
-- EnumerateInterfaceConfigs
--
-- Returns an array of interface configurations from:
-- /etc/sysconfig/network-scripts/ifcfg-???
--
------------------------------------------------------------------------------

function EnumerateInterfaceConfigs()
    local f
    local ifn
    local dev
    local fname
    local key
    local value
    local keys = { "eth", "type", "bootproto", "ipaddr", "netmask", "gateway" }
    local ifn_table = {}

    for fname in dir("/etc/sysconfig/network-scripts/") do
        _, __, ifn = string.find(fname, "ifcfg%-([%w:%.]+)")
        if ifn ~= nil then
            dev = ifn
            f = io.open("/etc/sysconfig/network-scripts/" .. fname)

            if f ~= nil then
                for line in f:lines() do
                    _, _, value = string.find(line,
                        "DEVICE%s*=%s*\"*([%w%.%-%_:]+)\"*")
                    if value ~= nil then
                        dev = value
                        break
                    end
                end

                ifn_table[dev] = {}
                ifn_table[dev]["config_ifn"] = ifn
                for _, key in pairs(keys) do
                    ifn_table[dev][key] = nil
                end

                f:seek("set")
                for line in f:lines() do
                    for _, key in pairs(keys) do
                        _, _, value = string.find(line,
                            string.upper(key) .. "%s*=%s*\"*([%w%.%-%_:]+)\"*")
                        if (value ~= nil) then
                            ifn_table[dev][key] = string.lower(value)
                            break
                        end
                    end
                end
            end
        end
    end

    return ifn_table
end

------------------------------------------------------------------------------
--
-- GetInterfaceGateway
--
-- Returns the gateway for the given network interface.  If none is found in
-- /etc/sysconfig/network-scripts/ifcfg-??? nil is returned.  For PPPoE
-- interfaces, if_dst_address() is used for their gateway.
-- DHCP interface gateways are found in: /var/lib/dhclient/*.routers
--
------------------------------------------------------------------------------

function GetInterfaceGateway(ifn)
    local f
    local gw = nil
    local netmask = if_netmask(ifn)

    -- PPPOEKLUDGE: Return the peer IP address for PPP interfaces 
    if if_isppp(ifn) then
        return if_dst_address(ifn)
    end

    if IFCFG[ifn] ~= nil and IFCFG[ifn]["gateway"] ~= nil then
        gw = IFCFG[ifn]["gateway"]
    end

    if gw ~= nil then return gw end

    -- DHCPKLUDGE: Return stowed gateway (router) for DHCP interfaces
    f = io.open("/var/lib/dhclient/" .. ifn .. ".routers")

    if f ~= nil then
        for line in f:lines() do
            _, _, gw = string.find(line, "(%d+\.%d+\.%d+\.%d+)")
            if gw ~= nil then break end
        end

        io.close(f)
    end

    return gw
end

------------------------------------------------------------------------------
--
-- GetPhysicalInterface
--
-- Returns the bridge interface associated with the given PPP device.
--
------------------------------------------------------------------------------

function GetPhysicalInterface(ifn)
    local f
    local dev = nil

    if IFCFG[ifn] ~= nil and IFCFG[ifn]["eth"] ~= nil then
        dev = IFCFG[ifn]["eth"]
    end

    if dev == nil then dev = ifn end

    return dev
end

------------------------------------------------------------------------------
--
-- GetUntrustedInterfaces
--
-- Returns a table of untrusted interfaces - DMZIF, HOTIF, WANIF
-- If all_interfaces is true, use WANIF_CONFIG instead of WANIF.
--
------------------------------------------------------------------------------

function GetUntrustedInterfaces(all_interfaces)
    local ifn
    local ifn_trusted = {}

    for _, ifn in pairs(HOTIF) do
        if if_exists(ifn) then
            table.insert(ifn_trusted, ifn)
        end
    end

    for _, ifn in pairs(DMZIF) do
        if if_exists(ifn) then
            table.insert(ifn_trusted, ifn)
        end
    end

    if all_interfaces == true then
        for _, ifn in pairs(WANIF_CONFIG) do
            if if_exists(ifn) then
                table.insert(ifn_trusted, ifn)
            end
        end
    else
        for _, ifn in pairs(WANIF) do
            if if_exists(ifn) then
                table.insert(ifn_trusted, ifn)
            end
        end
    end

    return ifn_trusted
end

------------------------------------------------------------------------------
--
-- GetTrustedInterfaces
--
-- Returns a table of LAN interfaces (not Hot LAN)
--
------------------------------------------------------------------------------

function GetTrustedInterfaces()
    local ifn
    local ifn_trusted = {}
    local is_hot

    for _, ifn in pairs(LANIF) do
        if if_exists(ifn) then
            is_hot = false

            for __, ifn_hot in pairs(HOTIF) do
                if ifn == ifn_hot then is_hot = true; break end 
            end

            if is_hot == false then
                table.insert(ifn_trusted, ifn)
            end
        end
    end

    return ifn_trusted
end

------------------------------------------------------------------------------
--
-- IsValidInterface
--
-- Determine if WAN interface is active/valid.
--
------------------------------------------------------------------------------

function IsValidInterface(ifn)
    local ifn_wan

    if not if_exists(ifn) then return false end
    if MULTIPATH_SKIP_DOWN_WANIF ~= nil then return true end

    for _, ifn_wan in pairs(WANIF) do
        if ifn == ifn_wan then return true end
    end

    return false
end

------------------------------------------------------------------------------
--
-- NetworkInterfaces
--
-- The following interfaces are exported from the firewall configuration file:
-- WANIF_CONFIG     - all WAN interface(s) (EXTIF in /etc/firewall)
-- WANIF     - WAN interface(s) which are up
-- SYSWATCH_WANIF  - all primary WAN interfaces (from syswatch)
-- LANIF     - LAN interface(s)
-- DMZIF     - DMZ interface(s)
-- WIFIF     - Wireless interface
-- BAKIF     - Backup WAN interfaces
--
-- + Make sure we have an IP address set on our WAN interface.
-- + Make sure LAN and DMZ interfaces are configured (network-scripts present).
-- + Make sure all configured interfaces are UP.
--
------------------------------------------------------------------------------

function NetworkInterfaces()
    local i, t
    local ifn, ifn_ppp, ifn_wan
    local ifn_pppoe = {}
    local pppoe_list = {}
    local difs = {}

    -- Build list of PPPoE bridge interfaces
    pppoe_list = if_list_pppoe()
    if table.getn(pppoe_list) ~= 0 then
        table.sort(pppoe_list)
        for _, ifn in pairs(pppoe_list) do
            table.insert(ifn_pppoe, GetPhysicalInterface(ifn))
        end
    end

    -- All interfaces without a set role default to a LAN interface
    BAKIF = {}
    for _, ifn in pairs(WANIF) do
        if string.len(ifn) ~= 0 and if_exists(ifn) then
            table.insert(difs, ifn)
            -- Interfaces in WANIF and not in SYSWATCH_WANIF must be backup interfaces
            f = true
		    for __, sifn in pairs(SYSWATCH_WANIF) do
		    	if ifn == sifn then f = false end
            end
            if f then table.insert(BAKIF, ifn) end
        end
    end

    for _, ifn in pairs(WANIF_BACKUP) do
        if string.len(ifn) ~= 0 and if_exists(ifn) then
            table.insert(difs, ifn)
        end
    end

    for _, ifn in pairs(WANIF_STANDBY) do
        if string.len(ifn) ~= 0 and if_exists(ifn) then
            table.insert(difs, ifn)
        end
    end

    for _, ifn in pairs(LANIF) do
        if string.len(ifn) ~= 0 and if_exists(ifn) then
            table.insert(difs, ifn)
        end
    end

    for _, ifn in pairs(DMZIF) do
        if string.len(ifn) ~= 0 and if_exists(ifn) then
            table.insert(difs, ifn)
        end
    end

    for i, ifn in pairs(if_list()) do
        if string.find(ifn, "^[ae]th%d$") then
            f = false
            for _, difn in pairs(difs) do
                if ifn == difn then f = true end
            end

            -- PPPOEKLUDGE... sigh.
            if not f then
                for __, ifn_ppp in pairs(ifn_pppoe) do
                    if ifn == ifn_ppp then f = true; break end
                end

                if f then
                    echo("Detected PPPoE bridge device: " .. ifn)
                else
                    for ___, ifn_wan in pairs(WANIF) do
                        if ifn == ifn_wan then f = true; break end
                    end

                    if f == false then
                        echo("Assuming device is a LAN interface: " .. ifn)
                        table.insert(LANIF, ifn)
                    end
                end
            end
        end
    end

    WANIF_CONFIG = WANIF

    -- Display detected interface roles
    for _, ifn in pairs(WANIF) do
        echo("Detected WAN role for interface: " .. ifn)
    end

    for _, ifn in pairs(WANIF_BACKUP) do
        echo("Detected WAN backup role for interface: " .. ifn)
    end

    for _, ifn in pairs(WANIF_STANDBY) do
        echo("Detected WAN stand-by role for interface: " .. ifn)
    end

    for _, ifn in pairs(BAKIF) do
        echo("Detected WAN backup role for interface: " .. ifn)
    end

    for _, ifn in pairs(LANIF) do
        echo("Detected LAN role for interface: " .. ifn)
    end

    for _, ifn in pairs(DMZIF) do
        echo("Detected DMZ role for interface: " .. ifn)
    end

    -- Ensure address of WAN interfaces are set
    WANIF = PruneInterfaceTable(WANIF, "WAN")
    SYSWATCH_WANIF = PruneInterfaceTable(SYSWATCH_WANIF, nil)
    BAKIF = PruneInterfaceTable(BAKIF, nil)

    if table.getn(WANIF) == 0 then
        echo("WARNING: No configured WAN interfaces, continuing anyway...")
    end

    -- Check LAN interface(s)
    if FW_MODE ~= "standalone" and FW_MODE ~= "trustedstandalone" then
        LANIF = PruneInterfaceTable(LANIF, "LAN")
    end

    -- Check Hot LAN interface(s)
    if FW_MODE ~= "standalone" and FW_MODE ~= "trustedstandalone" then
        HOTIF = PruneInterfaceTable(HOTIF, "LAN")
    end

    -- Check DMZ interface(s)
    if FW_MODE == "dmz" then
        DMZIF = PruneInterfaceTable(DMZIF, "DMZ")
    end
end

------------------------------------------------------------------------------
--
-- PruneInterfaceTable
--
-- Remove interfaces with no IP address, or down from a table
-- if message is not nil, echo a warning message explaining why an interface is removed from the table
--
------------------------------------------------------------------------------

function PruneInterfaceTable(tab, message)
	t = {}
	for _, ifn in pairs(tab) do
		m = nil
            if if_exists(ifn) then
                -- Test if network configuration file exists
			f = io.open("/etc/sysconfig/network-scripts/ifcfg-" .. ifn)

			if f == nil then
				m = "interface is not configured: " .. ifn
                else
				io.close(f)

                    -- Test if interface has a set address and is up
                    if if_address(ifn) == nil then
					m = "device has no IP address: " .. ifn
                    elseif if_isup(ifn) == false then
					m = "interface seems to be down: " .. ifn
                    else
					table.insert(t, ifn)
                    end
                end
            else
			m = "interface doesn't exist: " .. ifn
        end
		if m ~= nil and message ~= nil then echo("Warning: " .. message .. " " .. m) end
    end
	return t
end

------------------------------------------------------------------------------
--
-- ResolveRules
--
-- Resolve firewall rule (network) addresses:
-- Firewall rules which contain the LOCAL_NETWORK or EXTERNAL_ADDR flags need
-- to be expanded for each local network or external address.
--
------------------------------------------------------------------------------

function ResolveRules()
    local ifn
    local rule
    local rules = {}
    local r_type, r_proto, r_addr, r_port, r_param
    local ip, network, prefix

    rules = RULES; RULES = {}
    for _, rule in pairs(rules) do
        r_type, r_proto, r_addr, r_port, r_param = ExpandRule(rule)
        if b_and(r_type, tonumber(os.getenv("FWR_ENABLED"))) ~= 0 and
            b_and(r_type, tonumber(os.getenv("FWR_LOCAL_NETWORK"))) ~= 0 then
            if FW_MODE ~= "standalone" and FW_MODE ~= "trustedstandalone" then
                for __, ifn in pairs(LANIF) do
                    ___, ___, network, prefix = GetInterfaceInfo(ifn)
                    rule = string.format("||0x%08x|%d|%s/%d|%s|%s",
                        r_type, r_proto, network, prefix, r_port, r_param)
                    table.insert(RULES, rule)
                end
                for __, ifn in pairs(HOTIF) do
                    ___, ___, network, prefix = GetInterfaceInfo(ifn)
                    rule = string.format("||0x%08x|%d|%s/%d|%s|%s",
                        r_type, r_proto, network, prefix, r_port, r_param)
                    table.insert(RULES, rule)
                end
            end
            if FW_MODE == "dmz" then
                for __, ifn in pairs(DMZIF) do
                    ___, ___, network, prefix = GetInterfaceInfo(ifn)
                    rule = string.format("||0x%08x|%d|%s/%d|%s|%s",
                        r_type, r_proto, network, prefix, r_port, r_param)
                    table.insert(RULES, rule)
                end
            end
        elseif b_and(r_type, tonumber(os.getenv("FWR_ENABLED"))) ~= 0 and
            b_and(r_type, tonumber(os.getenv("FWR_EXTERNAL_ADDR"))) ~= 0 then
            for __, ifn in pairs(WANIF) do
                if if_exists(ifn) then
                    ip, ___, ___, ___ = GetInterfaceInfo(ifn)
                    rule = string.format("||0x%08x|%d|%s|%s|%s",
                        r_type, r_proto, ip, r_port, r_param)
                    table.insert(RULES, rule)
                end
            end
        else
            table.insert(RULES, rule)
        end
    end 
end

------------------------------------------------------------------------------
--
-- ExpandRule
--
-- Return packed rule components; type, protocol, address, port, parameter
--
------------------------------------------------------------------------------

function ExpandRule(r)
    local rule = Explode("|", r)
    return tonumber(rule[3]), tonumber(rule[4]), rule[5], rule[6], rule[7]
end

------------------------------------------------------------------------------
--
-- LoadLayer7Config
--
-- Loads/parses the l7-filter configuration file
--
------------------------------------------------------------------------------

function LoadLayer7Config()
    local line
    local config = {}
    local f = io.open("/etc/l7-filter/l7-filter.conf", "r")

    if f ~= nil then
        for line in f:lines() do
            _, _, protocol, mark = string.find(line, "^([%w-]+)%s+(%d+)")
            if protocol ~= nil and mark ~= nil then
                config[protocol] = mark
            end
        end

        io.close(f)
    end

    return config
end

------------------------------------------------------------------------------
--
-- GetMemInfo
--
-- Returns memory total in kilobytes
--
------------------------------------------------------------------------------

function GetMemInfo()
    local line
    local total = 0
    local f = io.open("/proc/meminfo", "r")

    if f == nil then return nil end

    for line in f:lines() do
        _, _, total = string.find(line, "^MemTotal:%s+(%d+)")
        if total ~= nil then break end
    end

    io.close(f)

    return total
end

------------------------------------------------------------------------------
--
-- IsServiceRunning
--
-- Returns true if service is running.
--
------------------------------------------------------------------------------

function IsServiceRunning(service)
    local pid = nil
    local f = io.open(string.format("/var/run/%s.pid", service), "r")

    if f == nil then return false end

    for line in f:lines() do
        _, _, pid = string.find(line, "^(%d+)")
        if pid ~= nil then break end
    end

    io.close(f)

    if pid == nil then return false end

    f = io.open(string.format("/proc/%d/comm", pid), "r")
    if f == nil then return false end

    for line in f:lines() do
        if line == service then
            io.close(f)
            return true
        end
    end

    io.close(f)
    return false
end

-- Debug
-- configs = EnumerateInterfaceConfigs()
-- TablePrint(configs)

-- vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
