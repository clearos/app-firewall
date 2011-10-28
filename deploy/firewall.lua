------------------------------------------------------------------------------
--
-- ClearOS Firewall
--
------------------------------------------------------------------------------
--
-- Original by Dinesh Kandiah
-- + additions by Daniel Carrera
-- + additions by Paul Moore, pcmoore@engin.umich.edu
-- + port to app-firewall (Lua) by darryl@pointclark.net
--
-- Copyright (C) 2000-2009 Point Clark Networks
-- Copyright (C) 2003 Paul Moore
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
--
-- Inspired by...
-- + Trinity OS
-- + Linux Security
-- + linux-firewall-tools.com
-- + Usenet
--
------------------------------------------------------------------------------
--
-- Notes:
-- This script is run by app-firewall which is a combination of iptables, the
-- Lua interpreter and various custom functions.  The purpose of the port to
-- Lua is performance.  All iptables operations are queued and are not
-- commited until the end only if all input was valid.  If there are any
-- errors then the firewall will not be touched.  See /sbin/app-firewall -h
-- for help and /etc/rc.d/rc.firewall for an example of how to invoke this
-- script.
--
-- Semantics:
-- + Incoming - packets destined for *this* machine
-- + Outgoing - packets from the LAN/DMZ to the outside world
-- + Forward  - packets from the outside world to the LAN/DMZ
--
------------------------------------------------------------------------------

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
        debug(string.format("%4d: %20s => %s", c, k, v))
        c = c + 1
    end
end

------------------------------------------------------------------------------
--
-- SetKernelSettings
-- 
-- Defines some default kernel settings...  mostly for added security and
-- performance tuning.
--
-- TODO: IPv6 support
--
------------------------------------------------------------------------------

function SetKernelSettings()
    echo("Setting kernel parameters")

    local neigh_gc_index = nil
    local neigh_gc_thresh1 = { 2048, 1024, 512, 256 }
    local neigh_gc_thresh2 = { 8192, 4096, 2048, 1024 }
    local neigh_gc_thresh3 = { 16384, 8192, 4096, 2048 }
    local memory_table = {
        8 * 1024 * 1024, 4 * 1024 * 1024,
        2 * 1024 * 1024, 1 * 1024 * 1024
    }

    -- Detect memory size
    local total = GetMemInfo()
    if total ~= nil then
        if tonumber(total) >= memory_table[1] - memory_table[1] * 0.1 then
            -- >= 8GB
            neigh_gc_index = 1
        elseif tonumber(total) >= memory_table[2] - memory_table[2] * 0.1 then
            -- >= 4GB
            neigh_gc_index = 2
        elseif tonumber(total) >= memory_table[3] - memory_table[3] * 0.1 then
            -- >= 2GB
            neigh_gc_index = 3
        elseif tonumber(total) >= memory_table[4] - memory_table[4] * 0.1 then
            -- >= 1GB
            neigh_gc_index = 4
        end
        -- Less than 1GB, use default values
    end

    -- Tune neighbor table garbage collection sizes according to available memory
    if neigh_gc_index ~= nil then
        execute(string.format("%s -w net.ipv4.neigh.default.gc_thresh1=%d >/dev/null",
            SYSCTL, neigh_gc_thresh1[neigh_gc_index]))
        execute(string.format("%s -w net.ipv4.neigh.default.gc_thresh2=%d >/dev/null",
            SYSCTL, neigh_gc_thresh2[neigh_gc_index]))
        execute(string.format("%s -w net.ipv4.neigh.default.gc_thresh3=%d >/dev/null",
            SYSCTL, neigh_gc_thresh3[neigh_gc_index]))
    end

    -- Tune connection tracker table size
    -- TODO: Perhaps this should also be set according to RAM size as above
    execute(SYSCTL .. " -w net.netfilter.nf_conntrack_max=524288 >/dev/null")

    -- Enable IP Forwarding
    execute(SYSCTL .. " -w net.ipv4.ip_forward=1 >/dev/null")

    -- Enable TCP SYN Cookie protection
    execute(SYSCTL .. " -w net.ipv4.tcp_syncookies=1 >/dev/null")

    -- Don't log spoofed, source-routed, or redirect packets
    execute(SYSCTL .. " -w net.ipv4.conf.all.log_martians=0 >/dev/null")

    -- Disable ICMP redirects
    execute(SYSCTL .. " -w net.ipv4.conf.all.accept_redirects=0 >/dev/null")
    execute(SYSCTL .. " -w net.ipv4.conf.all.send_redirects=0 >/dev/null")
    execute(SYSCTL .. " -w net.ipv4.conf.default.accept_redirects=0 >/dev/null")
    execute(SYSCTL .. " -w net.ipv4.conf.default.send_redirects=0 >/dev/null")

    -- Ensure that source-routed packets are dropped
    execute(SYSCTL .. " -w net.ipv4.conf.all.accept_source_route=0 >/dev/null")

    -- Disable ICMP broadcast echo protection
    execute(SYSCTL .. " -w net.ipv4.icmp_echo_ignore_broadcasts=1 >/dev/null")

    -- Enable bad error message protection
    execute(SYSCTL .. " -w net.ipv4.icmp_ignore_bogus_error_responses=1 >/dev/null")
end

------------------------------------------------------------------------------
--
-- SetPolicyToAccept
-- 
-- Sets default firewall policy to ACCEPT
--
------------------------------------------------------------------------------

function SetPolicyToAccept()
    local t

    echo("Setting default policy to " .. FW_ACCEPT)

    for _, t in pairs(TABLES) do
        -- Flush all previous rules
        iptc_flush_all_chains(t)
        -- Delete user-defined chains
        iptc_delete_user_chains(t)
    end

    iptc_set_policy("filter", "INPUT", FW_ACCEPT)
    iptc_set_policy("filter", "OUTPUT", FW_ACCEPT)
    iptc_set_policy("filter", "FORWARD", FW_ACCEPT)
end

------------------------------------------------------------------------------
--
-- SetPolicyToDrop
-- 
-- Sets default firewall policy to DROP
--
------------------------------------------------------------------------------

function SetPolicyToDrop()
    local t

    echo("Setting default policy to " .. FW_DROP)

    for _, t in pairs(TABLES) do
        -- Flush all previous rules
        iptc_flush_all_chains(t)
        -- Delete user-defined chains
        iptc_delete_user_chains(t)
    end

    iptc_set_policy("filter", "INPUT", FW_DROP)
    iptc_set_policy("filter", "OUTPUT", FW_DROP)
    iptc_set_policy("filter", "FORWARD", FW_DROP)
end

------------------------------------------------------------------------------
--
-- DefineChains
-- 
-- Define any custom chains here.  Custom chains include:
-- + drop-lan      - for logging LAN traffic trying to escape the LAN
--
-- Use the FW_DROP and FW_ACCEPT variable to override DROP and ACCEPT.  This
-- can be handy for trouble-shooting.
--
------------------------------------------------------------------------------

function DefineChains()
    echo("Defining custom chains")

    if FW_LOG_DROPS == "yes" then
        FW_DROP = "DROP-log"
    end

    -- Create a default DROP chain for debugging
    if FW_DROP ~= "DROP" then
        for _, t in pairs(TABLES) do
            iptc_create_chain(t, FW_DROP)
            if FW_LOG_DROPS == "yes" then
                iptables(t, "-A " .. FW_DROP .. " -j LOG --log-prefix \"Drop: \"")
            end
            iptables(t, "-A " .. FW_DROP .. " -j DROP")
        end
    end

    -- Create a default ACCEPT chain for debugging
    if FW_ACCEPT ~= "ACCEPT" then
        iptc_create_chain("filter", FW_ACCEPT)
        -- iptables("filter", "-A " .. FW_ACCEPT .. " -j LOG --log-prefix \"Accept: \"")
        iptables("filter", "-A " .. FW_ACCEPT .. " -j ACCEPT")
    end

    -- Create a chain for dropping services that shouldn't leave the LAN
    iptc_create_chain("filter", "drop-lan")
    -- iptables("filter", "-A drop-lan -j LOG --log-prefix \"Drop - LAN only: \"")
    iptables("filter", "-A drop-lan -j DROP")
end

------------------------------------------------------------------------------
--
-- LoadKernelModules
-- 
-- Loads kernel modules.  Most modules will automatically load... but some
-- require a little help :-)
--
------------------------------------------------------------------------------

function LoadKernelModules()
    local modules = {}

    echo("Loading kernel modules")

    -- Add LOG target
    table.insert(modules, "ipt_LOG")
    -- Add REJECT target
    table.insert(modules, "ipt_REJECT")
    -- Connection tracking for FTP
    table.insert(modules, "ip_conntrack_ftp")
    -- Connection tracking for IRC
    table.insert(modules, "ip_conntrack_irc")
    -- PPTP and dependencies
    table.insert(modules, "ppp_generic")
    table.insert(modules, "ppp_mppe")
    table.insert(modules, "ip_conntrack_proto_gre")
    table.insert(modules, "ip_conntrack_pptp")
    -- IMQ for bandwidth QoS
    if BANDWIDTH_QOS == "on" then
        table.insert(modules, "imq")
        table.insert(modules, "ipt_IMQ")
    end

    for _, m in pairs(modules) do
        execute(string.format("%s %s >/dev/null 2>&1", MODPROBE, m))
    end
end

------------------------------------------------------------------------------
--
-- LoadNatKernelModules
-- 
-- Loads kernel modules required on NAT boxes
--
------------------------------------------------------------------------------

function LoadNatKernelModules()
    local modules = {}

    echo("Loading kernel modules for NAT")

    -- MASQUERADE/NAT target
    table.insert(modules, "ipt_MASQUERADE")
    -- Active FTP
    table.insert(modules, "ip_nat_ftp")
    -- IRC stuff
    table.insert(modules, "ip_nat_irc")
    -- PPTP and dependancies don't always auto-load...
    table.insert(modules, "ip_nat_proto_gre")
    -- PPTP: requires special attention - see PPTP server section
    table.insert(modules, "ip_nat_pptp")
    -- H323
    table.insert(modules, "ip_nat_h323")

    for _, m in pairs(modules) do
        execute(string.format("%s %s >/dev/null 2>&1", MODPROBE, m))
    end
end

------------------------------------------------------------------------------
--
-- UnloadNatKernelModules
-- 
-- Unloads kernel modules required for NAT
--
------------------------------------------------------------------------------

function UnloadNatKernelModules()
    local modules = {}

    echo("Unloading unecessary NAT kernel modules")

    table.insert(modules, "ip_nat_ftp")
    table.insert(modules, "ip_nat_irc")
    table.insert(modules, "ip_nat_pptp")
    table.insert(modules, "ip_nat_h323")
    table.insert(modules, "ip_nat_proto_gre")
    table.insert(modules, "ipt_MASQUERADE")
    table.insert(modules, "iptable_nat")

    for _, m in pairs(modules) do
        execute(string.format("%s %s >/dev/null 2>&1", RMMOD, m))
    end
end

------------------------------------------------------------------------------
--
-- RunCommonRules
--
-- Rules that should be included in *all* firewall modes should go here.
--
-- This function:
-- + allows all traffic on the loopback (localhost) interface
-- + blocks invalid address ranges
-- + allows ICMP (RFC compliance)
-- + allows DHCP traffic
--
------------------------------------------------------------------------------

function RunCommonRules()
    local ip
    local netmask
    local network
    local prefix
    local ifn
    local ifn_hot
    local is_hot

    echo("Running common rules")

    -- SYN bit issues
    iptables("filter", "-A INPUT -m state --state INVALID -j DROP")
    iptables("filter",
        "-A INPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j REJECT --reject-with tcp-reset")
    iptables("filter", "-A INPUT -p tcp ! --syn -m state --state NEW -j DROP")

    -- Block addresses that should never show up on our WAN interface
    for _, ifn in pairs(WANIF_CONFIG) do
        iptables("filter", "-A INPUT -i " .. ifn .. " -s 127.0.0.0/8 -j DROP")
        iptables("filter", "-A INPUT -i " .. ifn .. " -s 169.254.0.0/16 -j DROP")
    end

    -- Allow everything on the loopback interface
    iptables("filter", "-A INPUT -i lo -j " .. FW_ACCEPT)
    iptables("filter", "-A OUTPUT -o lo -j " .. FW_ACCEPT)

    -- Allow everything VPN interfaces
    iptables("filter", "-A INPUT -i pptp+ -j " .. FW_ACCEPT)
    iptables("filter", "-A OUTPUT -o pptp+ -j " .. FW_ACCEPT)
    iptables("filter", "-A INPUT -i tun+ -j " .. FW_ACCEPT)
    iptables("filter", "-A OUTPUT -o tun+ -j " .. FW_ACCEPT)

    -- Allow everything trusted LAN interfaces
    for _, ifn in pairs(LANIF) do
        is_hot = false

        for __, ifn_hot in pairs(HOTIF) do
            if ifn == ifn_hot then is_hot = true; break end 
        end

        if is_hot == false then
            iptables("filter", "-A INPUT -i " .. ifn .. " -j " .. FW_ACCEPT)
            iptables("filter", "-A OUTPUT -o " .. ifn .. " -j " .. FW_ACCEPT)
        end
    end

    -- Allow DHCP and caching DNS on Hot LAN
    for _, ifn_hot in pairs(HOTIF) do
        ip, netmask, network, prefix = GetInterfaceInfo(ifn_hot)

        -- Allow hosts on Hot LAN to use DHCP
        iptables("filter", string.format("-A INPUT -i %s -p udp -d 255.255.255.255 --dport bootps --sport bootpc -j %s",
            ifn_hot, FW_ACCEPT))
        iptables("filter", string.format("-A INPUT -i %s -p tcp -d 255.255.255.255 --dport bootps --sport bootpc -j %s",
            ifn_hot, FW_ACCEPT))

        -- Allow hosts on Hot LAN to use caching DNS
        iptables("filter", string.format("-A INPUT -i %s -p udp -d %s --dport domain -s %s/%s -j %s",
            ifn_hot, if_address(ifn_hot), network, netmask, FW_ACCEPT))
        iptables("filter", string.format("-A INPUT -i %s -p tcp -d %s --dport domain -s %s/%s -j %s",
            ifn_hot, if_address(ifn_hot), network, netmask, FW_ACCEPT))

        -- Allow hosts on Hot LAN to ping
        iptables("filter", string.format("-A INPUT -i %s -p icmp --icmp-type 0 -j %s", ifn_hot, FW_ACCEPT))
        iptables("filter", string.format("-A INPUT -i %s -p icmp --icmp-type 3 -j %s", ifn_hot, FW_ACCEPT))
        iptables("filter", string.format("-A INPUT -i %s -p icmp --icmp-type 8 -j %s", ifn_hot, FW_ACCEPT))
        iptables("filter", string.format("-A INPUT -i %s -p icmp --icmp-type 11 -j %s", ifn_hot, FW_ACCEPT))

        -- Allow traffic from the LAN to the hot LAN, but not the other way
        for __, ifn in pairs(LANIF) do
            if ifn ~= ifn_hot then
                iptables("filter", string.format("-A FORWARD -i %s -o %s -m state --state ESTABLISHED,RELATED -j %s",
                    ifn_hot, ifn, FW_ACCEPT))
                iptables("filter", string.format("-A FORWARD -i %s -o %s -j %s", ifn_hot, ifn, FW_DROP))
                iptables("filter", string.format("-A FORWARD -i %s -o %s -j %s", ifn, ifn_hot, FW_ACCEPT))
            end
        end
    end

    -- Allow DHCP and caching DNS on DMZ
    if FW_MODE == "dmz" then
        for _, ifn in pairs(DMZIF) do
            ip, netmask, network, prefix = GetInterfaceInfo(ifn)

            -- Allow hosts on DMZ to use DHCP
            iptables("filter", string.format("-A INPUT -i %s -p udp -d %s --dport bootps --sport bootpc -j %s",
                ifn, if_address(ifn), FW_ACCEPT))
            iptables("filter", string.format("-A INPUT -i %s -p tcp -d %s --dport bootps --sport bootpc -j %s",
                ifn, if_address(ifn), FW_ACCEPT))

            -- Allow hosts on DMZ to use caching DNS
            iptables("filter", string.format("-A INPUT -i %s -p udp -d %s --dport domain -s %s/%s -j %s",
                ifn, if_address(ifn), network, netmask, FW_ACCEPT))
            iptables("filter", string.format("-A INPUT -i %s -p tcp -d %s --dport domain -s %s/%s -j %s",
                ifn, if_address(ifn), network, netmask, FW_ACCEPT))
        end
    end

    for _, ifn in pairs(WANIF_CONFIG) do
        -- Allow some ICMP (ping)
        --
        -- ICMP can be used for attacks.  We allow as little as possible.
        -- The following are necessary ports we *can't* do without:
        -- 0  Needed to ping hosts outside our network
        -- 3  Needed by all networks
        -- 8  Needed to ping this host (yes, it is an RFC requirement)
        -- 11 Needed by the traceroute application
        iptables("filter", string.format("-A INPUT -i %s -p icmp --icmp-type 0 -j %s", ifn, FW_ACCEPT))
        iptables("filter", string.format("-A INPUT -i %s -p icmp --icmp-type 3 -j %s", ifn, FW_ACCEPT))
        iptables("filter", string.format("-A INPUT -i %s -p icmp --icmp-type 8 -j %s", ifn, FW_ACCEPT))
        iptables("filter", string.format("-A INPUT -i %s -p icmp --icmp-type 11 -j %s", ifn, FW_ACCEPT))
        iptables("filter", string.format("-A OUTPUT -o %s -p icmp -j %s", ifn, FW_ACCEPT))

        -- Allow DHCP client to respond
        iptables("filter", "-A INPUT -i " .. ifn .. " -p udp --dport bootpc --sport bootps -j " .. FW_ACCEPT)
        iptables("filter", "-A INPUT -i " .. ifn .. " -p tcp --dport bootpc --sport bootps -j " .. FW_ACCEPT)
        iptables("filter", "-A OUTPUT -o " .. ifn .. " -p udp --sport bootpc --dport bootps -j " .. FW_ACCEPT)
        iptables("filter", "-A OUTPUT -o " .. ifn .. " -p tcp --sport bootpc --dport bootps -j " .. FW_ACCEPT)
    end
end

------------------------------------------------------------------------------
--
-- RunIncomingAllowedDefaults
--
------------------------------------------------------------------------------

function RunIncomingAllowedDefaults()
    local ifn

    echo("Running default incoming allowed rules")

    -- Allow all outbound and limited inbound on untrusted interfaces
    for _, ifn in pairs(GetUntrustedInterfaces(true)) do
        iptables("filter", "-A OUTPUT -o " .. ifn .. " -j " .. FW_ACCEPT)
        iptables("filter", "-A INPUT -i " .. ifn ..
            " -p udp --dport 1024:65535 -m state --state ESTABLISHED,RELATED -j " .. FW_ACCEPT)
        iptables("filter", "-A INPUT -i " .. ifn ..
            " -p tcp --dport 1024:65535 -m state --state ESTABLISHED,RELATED -j " .. FW_ACCEPT)
    end
end

------------------------------------------------------------------------------
--
-- RunIncomingAllowed
--
------------------------------------------------------------------------------

function RunIncomingAllowed()
    local r_type
    local r_proto
    local r_addr
    local r_port
    local r_param
    local input
    local output
    local ip
    local netmask
    local network
    local prefix
    local rule
    local ifn

    echo("Running user-defined incoming rules")

    -- Incoming ports and port ranges
    for _, rule in pairs(RULES) do
        r_type, r_proto, r_addr, r_port, r_param = ExpandRule(rule)

        if b_and(r_type, tonumber(os.getenv("FWR_ENABLED"))) ~= 0 and
            b_and(r_type, tonumber(os.getenv("FWR_INCOMING_ALLOW"))) ~= 0 and
            b_and(r_type, tonumber(os.getenv("FWR_CUSTOM"))) == 0 then

            echo("Allowing incoming " .. p_name(r_proto) .. " port/range " .. r_port)

            for __, ifn in pairs(GetUntrustedInterfaces(false)) do
                input = string.format("-A INPUT -p %d -d %s", r_proto, if_address(ifn))
                output = string.format("-A OUTPUT -p %d -o %s -s %s", r_proto, ifn, if_address(ifn))

                if r_addr == nil then
                    input = input .. " -s " .. r_addr
                    output = output .. " -d " .. r_addr
                end

                iptables("filter", input .. " --dport " .. r_port .. " -j " .. FW_ACCEPT)
                iptables("filter", output .. " --sport " .. r_port .. " -j " .. FW_ACCEPT)
            end
        end
    end

    -- PPTP server
    if PPTP_SERVER == "on" then
        -- ip_nat_pptp and PPTP servers do not mix
        if PPTP_PASSTHROUGH_FORCE == "yes" then
            echo("By-passing PPTP pass-through disable")
            execute(MODPROBE .. " ip_nat_pptp >/dev/null 2>&1")
        else
            echo("Disabling PPTP pass-through")
            execute(RMMOD .. " ip_nat_pptp >/dev/null 2>&1")
        end

        echo("Allowing incoming GRE (47) for PPTP")

        for _, ifn in pairs(GetUntrustedInterfaces(false)) do
            iptables("filter",
                string.format("-A INPUT -d %s -p 47 -j %s", if_address(ifn), FW_ACCEPT))
            iptables("filter",
                string.format("-A OUTPUT -o %s -s %s -p 47 -j %s", ifn, if_address(ifn), FW_ACCEPT))
        end

        echo("Allowing incoming TCP (6) port 1723 for PPTP")

        for _, ifn in pairs(GetUntrustedInterfaces(false)) do
            iptables("filter",
                string.format("-A INPUT -d %s -p tcp --dport 1723 -j %s", if_address(ifn), FW_ACCEPT))
            iptables("filter",
                string.format("-A OUTPUT -o %s -s %s -p tcp --sport 1723 -j %s", ifn, if_address(ifn), FW_ACCEPT))
        end
    end

    -- IPsec server
    if IPSEC_SERVER == "on" then
        echo("Allowing incoming " .. p_name(17) .. " port 500 for IPsec server")

        -- IKE negotiations
        for _, ifn in pairs(GetUntrustedInterfaces(false)) do
            iptables("filter",
                string.format("-A INPUT -d %s -p udp --sport 500 --dport 500 -j %s",
                if_address(ifn), FW_ACCEPT))
            iptables("filter",
                string.format("-A OUTPUT -o %s -s %s -p udp --sport 500 --dport 500 -j %s",
                ifn, if_address(ifn), FW_ACCEPT))
        end

        -- ESP/AH encryption and authentication
        echo(string.format("Allowing incoming %s/%s for IPsec server", p_name(50), p_name(51)))

        for _, ifn in pairs(GetUntrustedInterfaces(false)) do
            iptables("filter",
                string.format("-A INPUT -d %s -p 50 -j %s", if_address(ifn), FW_ACCEPT))
            iptables("filter",
                string.format("-A OUTPUT -o %s -s %s -p 50 -j %s", ifn, if_address(ifn), FW_ACCEPT))
            iptables("filter",
                string.format("-A INPUT -d %s -p 51 -j %s", if_address(ifn), FW_ACCEPT))
            iptables("filter",
                string.format("-A OUTPUT -o %s -s %s -p 51 -j %s", ifn, if_address(ifn), FW_ACCEPT))
        end

        -- Mark all incoming encrypted packets
        iptables("mangle", "-A PREROUTING -p esp -j MARK --set-mark 100")

        -- Direct un-encrypted (already authenticated) packets to the proper
        -- chain.  Packets destined for this box on any interface (LAN, WAN)
        -- are allowed.
        for _, ifn in pairs(GetUntrustedInterfaces(false)) do
            iptables("filter",
                string.format("-A INPUT -d %s --match mark --mark 100 -j %s", if_address(ifn), FW_ACCEPT))
        end

        for _, ifn in pairs(LANIF) do
            ip, netmask, network, prefix = GetInterfaceInfo(ifn)

            iptables("filter",
                string.format("-A INPUT -d %s --match mark --mark 100 -j %s", ip, FW_ACCEPT))
        end 

        -- Packets destined for the LAN are allowed
        iptables("filter", "-A FORWARD --match mark --mark 100 -j " .. FW_ACCEPT)

        -- Do not masquerade VPN traffic
        if FW_MODE == "gateway" or FW_MODE == "dmz" then
            for _, ifn in pairs(GetUntrustedInterfaces(false)) do
                iptables("nat", "-A POSTROUTING -o " .. ifn .. " -p esp -j " .. FW_ACCEPT)
                iptables("nat", "-A POSTROUTING -o " .. ifn .. " -p ah -j " .. FW_ACCEPT)
            end

            -- Include tunnel interfaces (OpenVPN)
            iptables("nat", "-A POSTROUTING -o tun+ -j " .. FW_ACCEPT)
        end
    end
end

------------------------------------------------------------------------------
--
-- RunBlockedHosts
--
------------------------------------------------------------------------------

function RunBlockedHosts()
    local t
    local s = ""
    local ifn
    local rule
    local r_type
    local r_proto
    local r_addr
    local r_port
    local r_param

    echo("Running blocked external rules")

    -- Block host rules
    for _, rule in pairs(RULES) do
        r_type, r_proto, r_addr, r_port, r_param = ExpandRule(rule)

        if b_and(r_type, tonumber(os.getenv("FWR_ENABLED"))) ~= 0 and
            b_and(r_type, tonumber(os.getenv("FWR_INCOMING_BLOCK"))) ~= 0 and
            b_and(r_type, tonumber(os.getenv("FWR_WIFI"))) == 0 and
            b_and(r_type, tonumber(os.getenv("FWR_CUSTOM"))) == 0 and
            string.len(r_addr) ~= 0 then

            echo("Blocking external host: " .. r_addr)

            for __, ifn in pairs(WANIF) do
                iptables("filter", string.format("-A FORWARD -s %s -j %s", r_addr, FW_DROP))
                iptables("filter", string.format("-A INPUT -s %s -j %s", r_addr, FW_DROP))
                iptables("filter", string.format("-A OUTPUT -d %s -j %s", r_addr, FW_DROP))
            end
        end
    end
end

------------------------------------------------------------------------------
--
-- RunIncomingDenied
--
------------------------------------------------------------------------------

function RunIncomingDenied()
    local t
    local s = ""
    local ifn
    local rule
    local r_type
    local r_proto
    local r_addr
    local r_port
    local r_param
    local mac_filter

    echo("Running incoming denied rules")

    -- MAC filter rules
    if string.len(WIFIF) ~= 0 then
        echo("Checking for wireless MAC filtering on: " .. WIFIF)

        for _, rule in pairs(RULES) do
            r_type, r_proto, r_addr, r_port, r_param = ExpandRule(rule)

            if b_and(r_type, tonumber(os.getenv("FWR_ENABLED"))) ~= 0 and
                b_and(r_type, tonumber(os.getenv("FWR_MAC_FILTER"))) ~= 0 and
                b_and(r_type, tonumber(os.getenv("FWR_WIFI"))) ~= 0 and
                b_and(r_type, tonumber(os.getenv("FWR_CUSTOM"))) == 0 then

                mac_filter = "yes"

                echo("Adding wireless MAC filtering for: " .. WIFIF)
                iptables("nat",
                    string.format("-A PREROUTING -i %s -m mac --mac-source %s -j %s",
                    WIFIF, r_addr, FW_ACCEPT))
            end

            if mac_filter ~= nil then
                iptables("nat", "-A PREROUTING -i " .. WIFIF .. " -j " .. FW_DROP)
            end
        end
    end

    -- Block configured l7-filter protocols (entire network)
    if PROTOCOL_FILTERING == "on" then
        local protocol
        local mark
        local config = LoadLayer7Config()
        local drop_target = "l7-filter-drop"

        iptc_create_chain("mangle", drop_target)
        iptables("mangle", "-A POSTROUTING -j " .. drop_target)
        for protocol, mark in pairs(config) do
            echo("Blocking l7-filter protocol across entire network: " .. protocol)
            iptables("mangle", string.format("-A %s -m mark --mark %d -j %s",
                drop_target, mark, FW_DROP))
        end
    end

    -- TODO:
    -- Block configured l7-filter protocols (by host)
end

------------------------------------------------------------------------------
--
-- RunOutgoingDenied
--
------------------------------------------------------------------------------

function RunOutgoingDenied()
    local ifn
    local rule
    local r_type
    local r_proto
    local r_addr
    local r_port
    local r_param
    local ip
    local netmask
    local network
    local prefix
    local action
    local target

    if EGRESS_FILTERING == "off" then
        echo("Running user-defined outgoing block rules")
        action = "Blocking"
        target = FW_DROP
    else
        echo("Running user-defined outgoing allow rules")
        action = "Allowing"
        target = FW_ACCEPT
    end

    for _, rule in pairs(RULES) do
        r_type, r_proto, r_addr, r_port, r_param = ExpandRule(rule)

        if b_and(r_type, tonumber(os.getenv("FWR_ENABLED"))) ~= 0 and
            b_and(r_type, tonumber(os.getenv("FWR_OUTGOING_BLOCK"))) ~= 0 and
            b_and(r_type, tonumber(os.getenv("FWR_CUSTOM"))) == 0 then

            if r_proto ~= 0 then
                echo(action .. " outgoing " .. p_name(r_proto) .. " port " .. r_port)

                for _, ifn in pairs(LANIF) do
                    ip, netmask, network, prefix = GetInterfaceInfo(ifn)

                    iptables("filter",
                        string.format("-A FORWARD -s %s/%s -p %d --dport %s -j %s",
                        network, netmask, r_proto, r_port, target))
                end
            else
                echo(action .. " outgoing traffic to: " .. r_addr)

                for _, ifn in pairs(LANIF) do
                    ip, netmask, network, prefix = GetInterfaceInfo(ifn)

                    iptables("filter",
                        string.format("-A FORWARD -s %s/%s -d %s -j %s",
                        network, netmask, r_addr, target))
                end
            end
        end
    end
end

------------------------------------------------------------------------------
--
-- RunPortForwardRules
--
------------------------------------------------------------------------------

function RunPortForwardRules()
    local ifn
    local ifn_wan
    local rule
    local r_type
    local r_proto
    local r_addr
    local r_port
    local r_param
    local ip
    local netmask
    local network
    local prefix
    local to
    local dport

    echo("Running user-defined port forward rules")

    -- Normal forward rules
    for _, rule in pairs(RULES) do
        r_type, r_proto, r_addr, r_port, r_param = ExpandRule(rule)
    
        if b_and(r_type, tonumber(os.getenv("FWR_ENABLED"))) ~= 0 and
            b_and(r_type, tonumber(os.getenv("FWR_FORWARD"))) ~= 0 and
            b_and(r_type, tonumber(os.getenv("FWR_CUSTOM"))) == 0 then

            echo(string.format("Port forwarding %s %s to %s %s",
                p_name(r_proto), r_param, r_addr, r_port))

            if string.len(r_port) == 0 then
                to = r_addr
                dport = r_param
            else
                to = r_addr .. ":" .. r_port
                dport = r_port
            end

            for __, ifn in pairs(WANIF) do
                iptables("nat",
                    string.format("-A PREROUTING -d %s -p %d --dport %s -j DNAT --to %s",
                    if_address(ifn), r_proto, r_param, to))
            end

            for __, ifn in pairs(LANIF) do
                ip, netmask, network, prefix = GetInterfaceInfo(ifn)

                iptables("nat",
                    string.format("-A POSTROUTING -d %s -p %d -s %s/%s --dport %s -j SNAT --to %s",
                    r_addr, r_proto, network, netmask, dport, ip))

                iptables("filter",
                    string.format("-A FORWARD -o %s -p %d -d %s --dport %s -j %s",
                    ifn, r_proto, r_addr, dport, FW_ACCEPT))
            end
        end
    end

    -- PPTP forwarding
    for _, rule in pairs(RULES) do
        r_type, r_proto, r_addr, r_port, r_param = ExpandRule(rule)
    
        if b_and(r_type, tonumber(os.getenv("FWR_ENABLED"))) ~= 0 and
            b_and(r_type, tonumber(os.getenv("FWR_PPTP_FORWARD"))) ~= 0 and
            b_and(r_type, tonumber(os.getenv("FWR_CUSTOM"))) == 0 then

            echo("Forwarding PPTP traffic to: " .. r_addr)

            for __, ifn in pairs(WANIF) do
                iptables("nat",
                    string.format("-A PREROUTING -d %s -p %d -j DNAT --to %s",
                    if_address(ifn), r_proto, r_addr))
                iptables("nat",
                    string.format("-A PREROUTING -d %s -p tcp --dport %s -j DNAT --to %s",
                    if_address(ifn), r_port, r_addr))
            end

            for __, ifn in pairs(LANIF) do
                ip, netmask, network, prefix = GetInterfaceInfo(ifn)

                for ___, ifn_wan in pairs(WANIF) do
                    iptables("filter",
                        string.format("-A FORWARD -i %s -o %s -p %d -d %s -j %s",
                        ifn_wan, ifn, r_proto, r_addr, FW_ACCEPT))
                    iptables("filter",
                        string.format("-A FORWARD -i %s -o %s -p tcp -d %s --dport %s -j %s",
                        ifn_wan, ifn, r_addr, r_port, FW_ACCEPT))
                end

                -- XXX: Can only have one of these...
                break
            end
        end
    end
end

------------------------------------------------------------------------------
--
-- RunProxyPorts
--
-- There are 3 variables the firewall needs to know to handle the web proxy:
--
-- 1) T/Transparent - state of transparent mode
-- 2) C/Content filter - state of the content filter
-- 3) U/User authentication - state of user authentication
--
-- The 8 possible combinations are described in the following table:
--
--  T   C   U  | see above for the meaning of these letters
-- ---------------------------------------------------
-- off off off | do nothing
-- off off  on | block port 80 and 443: forces users to authenticate via Squid on 3128
-- off  on off | block port 80, 443 and 3128: forces users through DansGuardian on 8080
-- off  on  on | block port 80, 443 and 3128: forces users through DansGuardian on 8080 (and indirectly, Squid)
--  on off off | redirect port 80 to 3128
--  on off  on | n/a
--  on  on off | redirect port 80 to 8080, block access to Squid on 3128
--  on  on  on | n/a
--
-- In standalone/trustedstandalone mode, we only have to worry about blocking
-- port 3128 when the content filter is enabled. 
--
--  T   C   U  | see above for the meaning of these letters
-- ---------------------------------------------------
-- off off off | do nothing
-- off off  on | do nothing
-- off  on off | block port 3128, forces users through DansGuardian on 8080
-- off  on  on | block port 3128, forces users through DansGuardian on 8080 (and indirectly, Squid)
--  on off off | 
--  on off  on | n/a
--  on  on off | 
--  on  on  on | n/a
------------------------------------------------------------------------------

function RunProxyPorts()
    local ifn
    local ifn_int
    local rule
    local r_type
    local r_proto
    local r_addr
    local r_port
    local r_param
    local bridge = false;

    echo("Running user-defined proxy rules")

    if FW_MODE == "trustedstandalone" and
        table.getn(WANIF_CONFIG) == 1 and
        string.find(WANIF_CONFIG[1], "^br%d+$") then
        bridge = true
        echo("Bridge mode detected")
    end

    if (FW_MODE == "standalone" or FW_MODE == "trustedstandalone") and bridge == false then
        if string.len(SQUID_FILTER_PORT) ~= 0 then
            echo("Blocking proxy port 3128 to force users through content filter")
            iptables("nat", "-A PREROUTING -p tcp ! -s 127.0.0.1 --dport 3128 -j REDIRECT --to-port 82")
        end

    elseif SQUID_TRANSPARENT == "on" and bridge == true then
        -- Do not proxy connections to LAN addresses
        _, netmask, network, __ = GetInterfaceInfo(WANIF_CONFIG[1])
        iptables("nat",
            string.format("-A PREROUTING -p tcp -d %s/%s --dport 80 -j ACCEPT",
            network, netmask))

        -- Insert any web proxy bypass rules for borked web servers (IIS for example)
        for _, rule in pairs(RULES) do
            r_type, r_proto, r_addr, r_port, r_param = ExpandRule(rule)

            if b_and(r_type, tonumber(os.getenv("FWR_ENABLED"))) ~= 0 and
                b_and(r_type, tonumber(os.getenv("FWR_PROXY_BYPASS"))) ~= 0 then

                echo("Enabling web proxy bypass for host: " .. r_addr)

                iptables("nat", "-A PREROUTING -p tcp -d " .. r_addr .. " --dport 80 -j " .. FW_ACCEPT)
            end
        end

        if string.len(SQUID_FILTER_PORT) ~= 0 then
            echo("Enabled proxy+filter transparent mode for filter port: " ..
                SQUID_FILTER_PORT)

            iptables("nat",
                string.format("-A PREROUTING -i %s -p tcp --dport 80 -j REDIRECT --to-port %d",
                WANIF_CONFIG[1], SQUID_FILTER_PORT))

            echo("Blocking proxy port 3128 to force users through content filter")
            iptables("nat", "-I PREROUTING -p tcp ! -s 127.0.0.1 --dport 3128 -j REDIRECT --to-port 82")

        else
            echo("Enabled proxy transparent mode")

            iptables("nat",
                string.format("-A PREROUTING -i %s -p tcp --dport 80 -j REDIRECT --to-port 3128",
                WANIF_CONFIG[1]))
        end

    elseif SQUID_TRANSPARENT == "on" and bridge == false then
        -- Do not proxy connections to local web server
        for _, ifn in pairs(GetTrustedInterfaces()) do
            iptables("nat",
                string.format("-A PREROUTING -p tcp -d %s --dport 80 -j ACCEPT",
                if_address(ifn)))
        end

        for _, ifn in pairs(WANIF) do
            iptables("nat",
                string.format("-A PREROUTING -p tcp -d %s --dport 80 -j ACCEPT",
                if_address(ifn)))
        end

        -- Insert any web proxy bypass rules for borked web servers (IIS for example)
        for _, rule in pairs(RULES) do
            r_type, r_proto, r_addr, r_port, r_param = ExpandRule(rule)

            if b_and(r_type, tonumber(os.getenv("FWR_ENABLED"))) ~= 0 and
                b_and(r_type, tonumber(os.getenv("FWR_PROXY_BYPASS"))) ~= 0 then

                echo("Enabling web proxy bypass for host: " .. r_addr)

                iptables("nat", "-A PREROUTING -p tcp -d " .. r_addr .. " --dport 80 -j " .. FW_ACCEPT)
            end
        end

        if string.len(SQUID_FILTER_PORT) ~= 0 then
            echo("Enabled proxy+filter transparent mode for filter port: " ..
                SQUID_FILTER_PORT)

            for _, ifn_int in pairs(GetTrustedInterfaces()) do
                iptables("nat",
                    string.format("-A PREROUTING -i %s -p tcp --dport 80 -j REDIRECT --to-port %d",
                    ifn_int, SQUID_FILTER_PORT))
            end

            for _, ifn in pairs(HOTIF) do
                iptables("filter", string.format("-A INPUT -i %s -p tcp --dport %d -j %s",
                    ifn, SQUID_FILTER_PORT, FW_ACCEPT))
                iptables("filter", string.format("-A OUTPUT -o %s -p tcp --sport %d -j %s",
                    ifn, SQUID_FILTER_PORT, FW_ACCEPT))
            end

            echo("Blocking proxy port 3128 to force users through content filter")
            iptables("nat", "-I PREROUTING -p tcp ! -s 127.0.0.1 --dport 3128 -j REDIRECT --to-port 82")
        else
            echo("Enabled proxy transparent mode")

            for _, ifn_int in pairs(GetTrustedInterfaces()) do
                iptables("nat",
                    string.format("-A PREROUTING -i %s -p tcp --dport 80 -j REDIRECT --to-port 3128",
                    ifn_int))
            end

            for _, ifn in pairs(HOTIF) do
                iptables("filter", string.format("-A INPUT -i %s -p tcp --dport %d -j %s",
                    ifn, 3128, FW_ACCEPT))
                iptables("filter", string.format("-A OUTPUT -o %s -p tcp --sport %d -j %s",
                    ifn, 3128, FW_ACCEPT))
            end

        end

    elseif bridge == true then
        if ((string.len(SQUID_FILTER_PORT) ~= 0) or (SQUID_USER_AUTHENTICATION == "on")) then

            -- Insert any web proxy bypass rules for borked web servers (IIS for example)
            for _, rule in pairs(RULES) do
                r_type, r_proto, r_addr, r_port, r_param = ExpandRule(rule)

                if b_and(r_type, tonumber(os.getenv("FWR_ENABLED"))) ~= 0 and
                    b_and(r_type, tonumber(os.getenv("FWR_PROXY_BYPASS"))) ~= 0 then

                    echo("Enabling web proxy bypass for host: " .. r_addr)

                    iptables("nat", "-A PREROUTING -p tcp -d " .. r_addr .. " --dport 80 -j " .. FW_ACCEPT)
                end
            end

            echo("Blocking port 80 and 443 to force users through proxy")
            iptables("nat", "-A PREROUTING -i " .. WANIF_CONFIG[1] .. " -p tcp --dport 80 -j REDIRECT --to-port 82")
            iptables("nat", "-A PREROUTING -i " .. WANIF_CONFIG[1] .. " -p tcp --dport 443 -j REDIRECT --to-port 82")

            if (string.len(SQUID_FILTER_PORT) ~= 0) then
                echo("Blocking proxy port 3128 to force users through content filter")
                iptables("nat", "-A PREROUTING -i " .. WANIF_CONFIG[1] .. " -p tcp --dport 3128 -j REDIRECT --to-port 82")
            end
        end

    else
        if ((string.len(SQUID_FILTER_PORT) ~= 0) or (SQUID_USER_AUTHENTICATION == "on")) then

            -- Insert any web proxy bypass rules for borked web servers (IIS for example)
            for _, rule in pairs(RULES) do
                r_type, r_proto, r_addr, r_port, r_param = ExpandRule(rule)

                if b_and(r_type, tonumber(os.getenv("FWR_ENABLED"))) ~= 0 and
                    b_and(r_type, tonumber(os.getenv("FWR_PROXY_BYPASS"))) ~= 0 then

                    echo("Enabling web proxy bypass for host: " .. r_addr)

                    iptables("nat", "-A PREROUTING -d " .. r_addr .. " -j " .. FW_ACCEPT)
                end
            end

            echo("Blocking port 80 and 443 to force users through proxy")
            for _, ifn in pairs(GetTrustedInterfaces()) do
                iptables("nat", "-A PREROUTING -i " .. ifn .. " -p tcp --dport 80 -j REDIRECT --to-port 82")
                iptables("nat", "-A PREROUTING -i " .. ifn .. " -p tcp --dport 443 -j REDIRECT --to-port 82")
            end

            if (string.len(SQUID_FILTER_PORT) ~= 0) then
                echo("Blocking proxy port 3128 to force users through content filter")
                for _, ifn in pairs(GetTrustedInterfaces()) do
                    iptables("nat", "-A PREROUTING -i " .. ifn .. " -p tcp --dport 3128 -j REDIRECT --to-port 82")
                end

                for _, ifn in pairs(HOTIF) do
                    iptables("filter", string.format("-A INPUT -i %s -p tcp --dport %d -j %s",
                        ifn, SQUID_FILTER_PORT, FW_ACCEPT))
                    iptables("filter", string.format("-A OUTPUT -o %s -p tcp --sport %d -j %s",
                        ifn, SQUID_FILTER_PORT, FW_ACCEPT))
                end
            else
                for _, ifn in pairs(HOTIF) do
                    iptables("filter", string.format("-A INPUT -i %s -p tcp --dport %d -j %s",
                        ifn, 3128, FW_ACCEPT))
                    iptables("filter", string.format("-A OUTPUT -o %s -p tcp --sport %d -j %s",
                        ifn, 3128, FW_ACCEPT))
                end
            end
        end
    end
end

------------------------------------------------------------------------------
--
-- RunCustomRules
--
------------------------------------------------------------------------------

function RunCustomRules()
    local ip
    local network
    local netmask
    local ifn
    local ifn_wan
    local rule
    local r_type
    local r_proto
    local r_addr
    local r_port
    local r_param
    local dst_addr
    local dst_port
    local input
    local output
    local forward
    local prerouting
    local postrouting

    echo("Running custom rules")

    for _, rule in pairs(RULES) do
        r_type, r_proto, r_addr, r_port, r_param = ExpandRule(rule)

        if b_and(r_type, tonumber(os.getenv("FWR_ENABLED"))) ~= 0 and
            b_and(r_type, tonumber(os.getenv("FWR_CUSTOM"))) ~= 0 then

            dst_addr = nil
            dst_port = nil

            if r_param ~= nil and string.len(r_param) ~= 0 then
                __ = string.find(r_param, "_")

                if __ == 1 then
                    dst_port = string.sub(r_param, 2)
                elseif __ ~= nil then
                    dst_addr = string.sub(r_param, 1, __ - 1)
                    dst_port = string.sub(r_param, __ + 1)
                else
                    dst_addr = r_param
                end
            end

            if b_and(r_type, tonumber(os.getenv("FWR_INCOMING_ALLOW"))) ~= 0 then
                -- INCOMING_ALLOW
                input = string.format("-A INPUT -p %s", r_proto)
                output = string.format("-A OUTPUT -p %s", r_proto)

                if r_addr ~= nil and string.len(r_addr) ~= 0 and
                    b_and(r_type, tonumber(os.getenv("FWR_MAC_SOURCE"))) == 0 then
                    input = input .. " -s " .. r_addr
                    output = output .. " -d " .. r_addr
                elseif r_addr ~= nil and string.len(r_addr) ~= 0 and
                    b_and(r_type, tonumber(os.getenv("FWR_MAC_SOURCE"))) ~= 0 then
                    output = output .. " -m mac --mac-source " .. r_addr
                end

                if dst_addr ~= nil and string.len(dst_addr) ~= 0 then
                    input = input .. " -d " .. dst_addr
                    output = output .. " -s " .. dst_addr
                end

                if r_port ~= nil and string.len(r_port) ~= 0 and
                    (tonumber(r_proto) == 6 or tonumber(r_proto) == 17) then
                    input = input .. " --sport " .. r_port
                    output = output .. " --dport " .. r_port
                end

                if dst_port ~= nil and string.len(dst_port) ~= 0 and
                    (tonumber(r_proto) == 6 or tonumber(r_proto) == 17) then
                    input = input .. " --dport " .. dst_port
                    output = output .. " --sport " .. dst_port
                end

                for __, ifn in pairs(WANIF) do
                    if string.find(ifn, ":") == nil then
                        -- Only if ifn is a non-virtual interface
                        if b_and(r_type, tonumber(os.getenv("FWR_MAC_SOURCE"))) == 0 then
                            iptables("filter",
                                string.format("%s -i %s -j %s", input, ifn, FW_ACCEPT))
                        end
                        iptables("filter",
                            string.format("%s -o %s -j %s", output, ifn, FW_ACCEPT))
                    end
                end
            elseif b_and(r_type, tonumber(os.getenv("FWR_INCOMING_BLOCK"))) ~= 0 then
                -- INCOMING_BLOCK
                input = string.format("-A INPUT -p %s", r_proto)
                output = string.format("-A OUTPUT -p %s", r_proto)

                if r_addr ~= nil and string.len(r_addr) ~= 0 and
                    b_and(r_type, tonumber(os.getenv("FWR_MAC_SOURCE"))) == 0 then
                    input = input .. " -s " .. r_addr
                    output = output .. " -d " .. r_addr
                elseif r_addr ~= nil and string.len(r_addr) ~= 0 and
                    b_and(r_type, tonumber(os.getenv("FWR_MAC_SOURCE"))) ~= 0 then
                    input = input .. " -m mac --mac-source " .. r_addr
                end

                if dst_addr ~= nil and string.len(dst_addr) ~= 0 then
                    input = input .. " -d " .. dst_addr
                    output = output .. " -s " .. dst_addr
                end

                if r_port ~= nil and string.len(r_port) ~= 0 and
                    (tonumber(r_proto) == 6 or tonumber(r_proto) == 17) then
                    input = input .. " --dport " .. r_port
                    output = output .. " --sport " .. r_port
                end

                if dst_port ~= nil and string.len(dst_port) ~= 0 and
                    (tonumber(r_proto) == 6 or tonumber(r_proto) == 17) then
                    input = input .. " --sport " .. dst_port
                    output = output .. " --dport " .. dst_port
                end

                for __, ifn in pairs(WANIF) do
                    if string.find(ifn, ":") == nil then
                        -- Only if ifn is a non-virtual interface
                        iptables("filter",
                            string.format("%s -i %s -j %s", input, ifn, FW_DROP))
                        if b_and(r_type, tonumber(os.getenv("FWR_MAC_SOURCE"))) == 0 then
                            iptables("filter",
                                string.format("%s -o %s -j %s", output, ifn, FW_DROP))
                        end
                    end
                end
            elseif b_and(r_type, tonumber(os.getenv("FWR_OUTGOING_BLOCK"))) ~= 0 then
                -- OUTGOING_BLOCK
                forward = "-A FORWARD -p " .. r_proto

                if r_addr ~= nil and string.len(r_addr) ~= 0 and
                    b_and(r_type, tonumber(os.getenv("FWR_MAC_SOURCE"))) == 0 then
                    forward = forward .. " -s " .. r_addr
                elseif r_addr ~= nil and string.len(r_addr) ~= 0 and
                    b_and(r_type, tonumber(os.getenv("FWR_MAC_SOURCE"))) ~= 0 then
                    forward = forward .. " -m mac --mac-source " .. r_addr
                end

                if dst_addr ~= nil and string.len(dst_addr) ~= 0 then
                    forward = forward .. " -d " .. dst_addr
                end

                if r_port ~= nil and string.len(r_port) ~= 0 and
                    (tonumber(r_proto) == 6 or tonumber(r_proto) == 17) then
                    forward = forward .. " --sport " .. r_port
                end

                if dst_port ~= nil and string.len(dst_port) ~= 0 and
                    (tonumber(r_proto) == 6 or tonumber(r_proto) == 17) then
                    forward = forward .. " --dport " .. dst_port
                end

                iptables("filter", forward .. " -j " .. FW_DROP)
            elseif b_and(r_type, tonumber(os.getenv("FWR_FORWARD"))) ~= 0 then
                -- FORWARD
                prerouting = "-A PREROUTING -p " .. r_proto

                if dst_port ~= nil and string.len(dst_port) ~= 0 and
                    (tonumber(r_proto) == 6 or tonumber(r_proto) == 17) then
                    prerouting = prerouting .. " --dport " .. dst_port
                end

                if r_addr ~= nil and string.len(r_addr) ~= 0 then
                    prerouting = prerouting .. " -s " .. r_addr
                end

                for __, ifn in pairs(WANIF) do
                    if dst_addr ~= nil and string.len(dst_addr) ~= 0 then
                        iptables("nat",
                            string.format("%s -d %s -j DNAT --to %s", prerouting, if_address(ifn), dst_addr)) 
                    else
                        iptables("nat",
                            string.format("%s -d %s", prerouting, if_address(ifn))) 
                    end
                end

                for __, ifn in pairs(LANIF) do
                    ip, netmask, network, ____ = GetInterfaceInfo(ifn)

                    postrouting = "-A POSTROUTING -p " .. r_proto

                    if dst_addr ~= nil and string.len(dst_addr) ~= 0 then
                        postrouting = postrouting .. " -d " .. dst_addr
                    end

                    postrouting = string.format("%s -s %s/%s",
                        postrouting, network, netmask)

                    if dst_port ~= nil and string.len(dst_port) ~= 0 and
                        (tonumber(r_proto) == 6 or tonumber(r_proto) == 17) then
                        postrouting = postrouting .. " --dport " .. dst_port
                    end

                    postrouting = postrouting .. " -j SNAT --to " .. ip

                    iptables("nat", postrouting)

                    forward = string.format("-A FORWARD -o %s -p %s", ifn, r_proto)

                    if r_addr ~= nil and string.len(r_addr) ~= 0 then
                        forward = forward .. " -s " .. r_addr
                    end

                    if dst_addr ~= nil and string.len(dst_addr) ~= 0 then
                        forward = forward .. " -d " .. dst_addr
                    end

                    if dst_port ~= nil and string.len(dst_port) ~= nil and
                        (tonumber(r_proto) == 6 or tonumber(r_proto) == 17) then
                        forward = forward .. " --dport " .. dst_port
                    end

                    for ___, ifn_wan in pairs(WANIF) do
                        iptables("filter",
                            string.format("%s -j %s", forward, FW_ACCEPT))
                    end
                end
            else
                error(string.format("Invalid custom firewall type: 0x%08x", r_type))
            end
        end
    end
end

------------------------------------------------------------------------------
--
-- AddBandwidthRule
--
------------------------------------------------------------------------------

function AddBandwidthClass(clsid, ifn, prio, rate, ceil, src_addr, src_port, dst_addr, dst_port)
    local src_text = ""
    local dst_text = ""
    local tc_filter = ""

    echo(string.format("HTB Class 1:%d, priority: %d, rate: %dkbit, ceil: %dkbit, interface: %s",
        clsid, prio, rate, ceil, ifn))

    -- Create class
    execute(string.format("%s class add dev %s parent 1:1 classid 1:%d htb rate %dkbit ceil %dkbit prio %d",
        TCBIN, ifn, clsid, rate, ceil, prio))

    -- Create tc filter for address and port
    if string.len(src_addr) ~= 0 then
        tc_filter = tc_filter .. " match ip src " .. src_addr
        src_text = src_addr
    end

    if string.len(dst_addr) ~= 0 then
        tc_filter = tc_filter .. " match ip dst " .. dst_addr
        dst_text = dst_addr
    end

    if string.len(src_port) ~= 0 and src_port ~= 0 then
        tc_filter = tc_filter .. " match ip sport " .. src_port .. " 0xffff"
        if string.len(src_text) ~= 0 then
            src_text = src_text .. ":" .. src_port
        else
            src_text = src_text .. src_port
        end
    end

    if string.len(dst_port) ~= 0 and dst_port ~= 0 then
        tc_filter = tc_filter .. " match ip dport " .. dst_port .. " 0xffff"
        if string.len(dst_text) ~= 0 then
            dst_text = dst_text .. ":" .. dst_port
        else
            dst_text = dst_text .. dst_port
        end
    end

    if string.len(tc_filter) == 0 then
        echo("Missing bandwidth match criteria")
    else
        if string.len(src_text) == 0 then
            src_text = "NONE"
        end
        if string.len(dst_text) == 0 then
            dst_text = "NONE"
        end
        echo(string.format("HTB Class 1:%d, source address: %s, destination address: %s",
            clsid, src_text, dst_text))

        -- Create tc filter
        execute(string.format("%s filter add dev %s protocol ip parent 1: " ..
            "pref 1 u32%s flowid 1:%d", TCBIN, ifn, tc_filter, clsid))
    end
end

------------------------------------------------------------------------------
--
-- ParseBandwidthVariable
-- Parse BANDWIDTH_XXX firewall configuration value
-- This expects to find entries of the syntax: ifn:value, eg: eth0:512
--
------------------------------------------------------------------------------

function ParseBandwidthVariable(v)
    local t = {}
    local entries = {}
    local cfg
    local ifn
    local value

    if v == nil or string.len(v) == 0 then return t end

    entries = Explode(" ", string.gsub(PackWhitespace(v), "\t", ""))

    for _, cfg in pairs(entries) do
        if cfg ~= nil and string.len(cfg) ~= 0 then
            __, __, ifn, value = string.find(cfg, "(%w+):(%d+)")

            if ifn == nil or value == nil then
                echo("Invalid bandwidth configuration syntax detected: " .. cfg)
                return nil
            end
            t[ifn] = value
        end
    end

    return t
end

------------------------------------------------------------------------------
--
-- RunBandwidthRules
--
------------------------------------------------------------------------------

function RunBandwidthRules()
    local ifn
    local ifn_wan
    local rule
    local clsid_up = 10
    local clsid_down = 10
    local r_type
    local r_proto
    local r_addr
    local r_port
    local r_param
    local bw_rule
    local bw_ifn
    local bw_addr_src
    local bw_port_src
    local bw_prio
    local bw_up_rate
    local bw_up_ceil
    local bw_down_rate
    local bw_down_ceil
    local bw_src_addr
    local bw_dst_addr
    local bw_src_port
    local bw_dst_port
    local addr
    local hi_addr
    local lo_addr
    local burst = ""
    local imq_devs = 0
    local IMQIF_UPSTREAM = {}
    local IMQIF_DOWNSTREAM = {}
    local WANIF_UPSTREAM = {}
    local WANIF_DOWNSTREAM = {}
    local WANIF_UPSTREAM_BURST = {}
    local WANIF_DOWNSTREAM_BURST = {}
    local WANIF_UPSTREAM_CBURST = {}
    local WANIF_DOWNSTREAM_CBURST = {}

    -- Sanity checks
    if BANDWIDTH_QOS ~= "on" then return end
    if table.getn(WANIF) == 0 then
        echo("No WAN interfaces up or configured, not starting bandwidth manager")
        return
    end

    echo("Initializing bandwidth manager")

    WANIF_UPSTREAM = ParseBandwidthVariable(BANDWIDTH_UPSTREAM)
    WANIF_DOWNSTREAM = ParseBandwidthVariable(BANDWIDTH_DOWNSTREAM)
    WANIF_UPSTREAM_BURST = ParseBandwidthVariable(BANDWIDTH_UPSTREAM_BURST)
    WANIF_DOWNSTREAM_BURST = ParseBandwidthVariable(BANDWIDTH_DOWNSTREAM_BURST)
    WANIF_UPSTREAM_CBURST = ParseBandwidthVariable(BANDWIDTH_UPSTREAM_CBURST)
    WANIF_DOWNSTREAM_CBURST = ParseBandwidthVariable(BANDWIDTH_DOWNSTREAM_CBURST)

    -- Setup IMQ interfaces...
    imq_devs = TableCount(WANIF_UPSTREAM) + TableCount(WANIF_DOWNSTREAM)
    if imq_devs == 0 then
        echo("Bandwidth manager is enabled but no WAN interfaces configured!")
        return
    end

    debug("Creating " .. imq_devs .. " IMQ interface(s)...")
    -- XXX: This is a hack.  For some reason, only after a fresh boot, we have to
    -- reload the imq kernel module to get the imqX hooks working... rather worrisome.
    if execute(string.format("%s %s >/dev/null 2>&1", RMMOD, "imq")) == 0 then
        execute(string.format("%s %s numdevs=%d >/dev/null 2>&1", MODPROBE, "imq", imq_devs))
        if execute(string.format("%s %s >/dev/null 2>&1", RMMOD, "imq")) == 0 then
            execute(string.format("%s %s numdevs=%d >/dev/null 2>&1", MODPROBE, "imq", imq_devs))
        end
    end

    __ = 0
    for ifn, _ in pairs(WANIF_UPSTREAM) do
        IMQIF_UPSTREAM[ifn] = "imq" .. __
        iptables("mangle", "-A POSTROUTING -o " .. ifn .. " -j IMQ --todev " .. __)
        __ = __ + 1
    end
    debug("Upstream WAN => IMQ interface map:")
    TablePrint(IMQIF_UPSTREAM)
    for ifn, _ in pairs(WANIF_DOWNSTREAM) do
        IMQIF_DOWNSTREAM[ifn] = "imq" .. __
        iptables("mangle", "-A PREROUTING -i " .. ifn .. " -j IMQ --todev " .. __)
        __ = __ + 1
    end
    debug("Downstream WAN => IMQ interface map:")
    TablePrint(IMQIF_DOWNSTREAM)

    for _, ifn in pairs(IMQIF_UPSTREAM) do
        execute(string.format("%s link set %s up 2>/dev/null", IPBIN, ifn))
        execute(TCBIN .. " qdisc del dev " .. ifn .. " root handle 1: htb >/dev/null 2>&1")
        execute(TCBIN .. " qdisc add dev " .. ifn .. " root handle 1: htb default 2 r2q 1")
    end

    for _, ifn in pairs(IMQIF_DOWNSTREAM) do
        execute(string.format("%s link set %s up 2>/dev/null", IPBIN, ifn))
        execute(TCBIN .. " qdisc del dev " .. ifn .. " root handle 1: htb >/dev/null 2>&1")
        execute(TCBIN .. " qdisc add dev " .. ifn .. " root handle 1: htb default 2 r2q 1")
    end

    -- Create root class 1:1
    for ifn_wan, ifn in pairs(IMQIF_UPSTREAM) do
        burst = ""
        if WANIF_UPSTREAM_BURST[ifn_wan] ~= nil then
            burst = burst .. " burst " .. WANIF_UPSTREAM_BURST[ifn_wan]
        end
        if WANIF_UPSTREAM_CBURST[ifn_wan] ~= nil then
            burst = burst .. " cburst " .. WANIF_UPSTREAM_CBURST[ifn_wan]
        end

        execute(string.format("%s class add dev %s parent 1: classid 1:1 htb rate %dkbit prio 0%s",
            TCBIN, ifn, WANIF_UPSTREAM[ifn_wan], burst));
    end
    for ifn_wan, ifn in pairs(IMQIF_DOWNSTREAM) do
        burst = ""
        if WANIF_DOWNSTREAM_BURST[ifn_wan] ~= nil then
            burst = burst .. " burst " .. WANIF_DOWNSTREAM_BURST[ifn_wan]
        end
        if WANIF_DOWNSTREAM_CBURST[ifn_wan] ~= nil then
            burst = burst .. " cburst " .. WANIF_DOWNSTREAM_CBURST[ifn_wan]
        end

        execute(string.format("%s class add dev %s parent 1: classid 1:1 htb rate %dkbit prio 0%s",
            TCBIN, ifn, WANIF_DOWNSTREAM[ifn_wan], burst));
    end

    -- Create class 1:2 which is used as the default low priority class for catch-all traffic
    -- TODO: This class is hard-coded to get at least 1/8th of the available up/downstream bandwidth.
    -- TODO: This should be configurable from /etc/firewall and/or webconfig.
    for ifn_wan, ifn in pairs(IMQIF_UPSTREAM) do
        execute(string.format("%s class add dev %s parent 1:1 classid 1:2 htb rate %dkbit ceil %dkbit prio 7",
            TCBIN, ifn, WANIF_UPSTREAM[ifn_wan] / 8, WANIF_UPSTREAM[ifn_wan]));
    end
    for ifn_wan, ifn in pairs(IMQIF_DOWNSTREAM) do
        execute(string.format("%s class add dev %s parent 1:1 classid 1:2 htb rate %dkbit ceil %dkbit prio 7",
            TCBIN, ifn, WANIF_DOWNSTREAM[ifn_wan] / 8, WANIF_DOWNSTREAM[ifn_wan]));
    end

    -- Attach a 'prio' qdisc 10:0 to the 1:2 default class for adjusting the IP TOS field
    for _, ifn in pairs(IMQIF_UPSTREAM) do
        execute(string.format("%s qdisc add dev %s parent 1:2 handle 10: prio",
            TCBIN, ifn));
    end
    for _, ifn in pairs(IMQIF_DOWNSTREAM) do
        execute(string.format("%s qdisc add dev %s parent 1:2 handle 10: prio",
            TCBIN, ifn));
    end

    -- Create up/downstream classes 100: 200: 300: (for band 0, 1, 2) sfq
    for _, ifn in pairs(IMQIF_UPSTREAM) do
        execute(string.format("%s qdisc add dev %s parent 10:1 handle 100: pfifo",
            TCBIN, ifn));
        execute(string.format("%s qdisc add dev %s parent 10:2 handle 200: sfq perturb 10",
            TCBIN, ifn));
        execute(string.format("%s qdisc add dev %s parent 10:3 handle 300: sfq perturb 10",
            TCBIN, ifn));
    end
    for _, ifn in pairs(IMQIF_DOWNSTREAM) do
        execute(string.format("%s qdisc add dev %s parent 10:1 handle 100: pfifo",
            TCBIN, ifn));
        execute(string.format("%s qdisc add dev %s parent 10:2 handle 200: sfq perturb 10",
            TCBIN, ifn));
        execute(string.format("%s qdisc add dev %s parent 10:3 handle 300: sfq perturb 10",
            TCBIN, ifn));
    end

    -- Convert bandwidth rate rules to classes and filters
    for _, rule in pairs(RULES) do
        r_type, r_proto, r_addr, r_port, r_param = ExpandRule(rule)

        if b_and(r_type, tonumber(os.getenv("FWR_ENABLED"))) ~= 0 and
            b_and(r_type, tonumber(os.getenv("FWR_BANDWIDTH_RATE"))) ~= 0 and
            b_and(r_type, tonumber(os.getenv("FWR_CUSTOM"))) == 0 then

            -- Rule parameter syntax:
            -- eth0:0:1:2:256:0:64:64
            -- wan_interface:src/dst addr:src/dst port:priority:up_rate:up_ceil:down_rate:down_ceil
            bw_rule = Explode(":", r_param)
            if table.getn(bw_rule) ~= 8 then
                echo("Bandwidth rule syntax error: " ..
                    "require 8 parameter fields, found " .. table.getn(bw_rule))
                error(rule)
            end

            bw_ifn = bw_rule[1]
            bw_addr_src = tonumber(bw_rule[2])
            bw_port_src = tonumber(bw_rule[3])
            bw_prio = tonumber(bw_rule[4])
            bw_up_rate = tonumber(bw_rule[5])
            bw_up_ceil = tonumber(bw_rule[6])
            bw_down_rate = tonumber(bw_rule[7])
            bw_down_ceil = tonumber(bw_rule[8])

            if bw_up_ceil == 0 then bw_up_ceil = WANIF_UPSTREAM[bw_ifn] end
            if bw_down_ceil == 0 then bw_down_ceil = WANIF_DOWNSTREAM[bw_ifn] end

            -- Create upstream rules
            if bw_up_rate ~= 0 then
                -- Handle IP range
                addr = Explode(":", r_addr)

                lo_addr = addr[1]
                hi_addr = addr[2]

                if hi_addr == nil then
                    -- Single IP
                    if bw_addr_src == 0 then
                        bw_src_addr = r_addr
                        bw_dst_addr = ""
                    else
                        bw_src_addr = ""
                        bw_dst_addr = r_addr
                    end
                    if bw_port_src == 0 then
                        bw_src_port = r_port
                        bw_dst_port = ""
                    else
                        bw_src_port = ""
                        bw_dst_port = r_port
                    end
                    AddBandwidthClass(clsid_up, IMQIF_UPSTREAM[bw_ifn], bw_prio,
                        bw_up_rate, bw_up_ceil,
                        bw_src_addr, bw_src_port, bw_dst_addr, bw_dst_port)
                    clsid_up = clsid_up + 1
                else
                    -- IP range
                    lo_addr = ip2bin(lo_addr)
                    hi_addr = ip2bin(hi_addr)

                    for i = lo_addr, hi_addr do
                        if bw_addr_src == 0 then
                            bw_src_addr = bin2ip(i)
                            bw_dst_addr = ""
                        else
                            bw_src_addr = ""
                            bw_dst_addr = bin2ip(i)
                        end
                        if bw_port_src == 0 then
                            bw_src_port = r_port
                            bw_dst_port = ""
                        else
                            bw_src_port = ""
                            bw_dst_port = r_port
                        end
                        AddBandwidthClass(clsid_up, IMQIF_UPSTREAM[bw_ifn], bw_prio,
                            bw_up_rate, bw_up_ceil,
                            bw_src_addr, bw_src_port, bw_dst_addr, bw_dst_port)
                        clsid_up = clsid_up + 1
                    end
                end
            end

            -- Create downstream rules
            if bw_down_rate ~= 0 then
                -- Handle IP range
                addr = Explode(":", r_addr)

                lo_addr = addr[1]
                hi_addr = addr[2]

                if hi_addr == nil then
                    -- Single IP
                    if bw_addr_src == 0 then
                        bw_src_addr = ""
                        bw_dst_addr = r_addr
                    else
                        bw_src_addr = r_addr
                        bw_dst_addr = ""
                    end
                    if bw_port_src == 0 then
                        bw_src_port = ""
                        bw_dst_port = r_port
                    else
                        bw_src_port = r_port
                        bw_dst_port = ""
                    end
                    AddBandwidthClass(clsid_down, IMQIF_DOWNSTREAM[bw_ifn], bw_prio,
                        bw_down_rate, bw_down_ceil,
                        bw_src_addr, bw_src_port, bw_dst_addr, bw_dst_port)
                    clsid_down = clsid_down + 1
                else
                    -- IP range
                    lo_addr = ip2bin(lo_addr)
                    hi_addr = ip2bin(hi_addr)

                    for i = lo_addr, hi_addr do
                        if bw_addr_src == 0 then
                            bw_src_addr = ""
                            bw_dst_addr = bin2ip(i)
                        else
                            bw_src_addr = bin2ip(i)
                            bw_dst_addr = ""
                        end
                        if bw_port_src == 0 then
                            bw_src_port = ""
                            bw_dst_port = r_port
                        else
                            bw_src_port = r_port
                            bw_dst_port = ""
                        end
                        AddBandwidthClass(clsid_down, IMQIF_DOWNSTREAM[bw_ifn], bw_prio,
                            bw_down_rate, bw_down_ceil,
                            bw_src_addr, bw_src_port, bw_dst_addr, bw_dst_port)
                        clsid_down = clsid_down + 1
                    end
                end
            end
        end
    end
end

------------------------------------------------------------------------------
--
-- RunDmzPinhole
--
------------------------------------------------------------------------------

function RunDmzPinhole()
    local lan
    local dmz
    local ifn_lan
    local ifn_dmz
    local rule
    local r_type
    local r_proto
    local r_addr
    local r_port
    local r_param
    local ip
    local netmask
    local network
    local prefix

    echo("Running DMZ pinhole rules")

    for _, rule in pairs(RULES) do
        r_type, r_proto, r_addr, r_port, r_param = ExpandRule(rule)
    
        if b_and(r_type, tonumber(os.getenv("FWR_ENABLED"))) ~= 0 and
            b_and(r_type, tonumber(os.getenv("FWR_DMZ_PINHOLE"))) ~= 0 and
            b_and(r_type, tonumber(os.getenv("FWR_CUSTOM"))) == 0 then

            for __, ifn_lan in pairs(LANIF) do
                for ___, ifn_dmz in pairs(DMZIF) do
                    ip, netmask, network, prefix = GetInterfaceInfo(ifn_dmz)

                    lan = string.format("-A FORWARD -i %s -o %s -p %d -s %s -d %s/%s -j %s",
                        ifn_lan, ifn_dmz, r_proto, r_addr, network, netmask, FW_ACCEPT)
                    dmz = string.format("-A FORWARD -i %s -o %s -p %d -d %s -s %s/%s -j %s",
                        ifn_dmz, ifn_lan, r_proto, r_addr, network, netmask, FW_ACCEPT)

                    if string.len(r_port) == 0 then
                        echo(string.format("Allowing DMZ pinhole %s -> %s: %s %s",
                            ifn_lan, ifn_dmz, p_name(r_proto), r_addr))

                        iptables("filter", lan)
                        iptables("filter", dmz)
                    else
                        echo(string.format("Allowing DMZ pinhole %s -> %s: %s %s:%s",
                            ifn_dmz, ifn_lan, p_name(r_proto), r_addr, r_port))

                        iptables("filter", lan .. " --sport " .. r_port)
                        iptables("filter", dmz .. " --dport " .. r_port)
                    end
                end
            end
        end
    end
end

------------------------------------------------------------------------------
--
-- RunDmzIncoming
--
------------------------------------------------------------------------------

function RunDmzIncoming()
    local ifn
    local ifn_wan
    local input
    local output
    local rule
    local r_type
    local r_proto
    local r_addr
    local r_port
    local r_param
    local ip
    local netmask
    local network
    local prefix

    echo("Running DMZ incoming rules")

    for _, rule in pairs(RULES) do
        r_type, r_proto, r_addr, r_port, r_param = ExpandRule(rule)
    
        if b_and(r_type, tonumber(os.getenv("FWR_ENABLED"))) ~= 0 and
            b_and(r_type, tonumber(os.getenv("FWR_DMZ_INCOMING"))) ~= 0 and
            b_and(r_type, tonumber(os.getenv("FWR_CUSTOM"))) == 0 then

            for __, ifn in pairs(DMZIF) do
                ip, netmask, network, prefix = GetInterfaceInfo(ifn)

                input = string.format("-p %d -s %s -j %s",
                    r_proto, r_addr, FW_ACCEPT)
                output = string.format("-p %d -d %s -j %s",
                    r_proto, r_addr, FW_ACCEPT)

                if string.len(r_port) == 0 then
                    echo(string.format("Allowing DMZ incoming %s: %s %s",
                        ifn, p_name(r_proto), r_addr))
                else
                    echo(string.format("Allowing DMZ incoming %s: %s %s:%s",
                        ifn, p_name(r_proto), r_addr, r_port))

                    input = input .. " --sport " .. r_port
                    output = output .. " --dport " .. r_port
                end

                for ___, ifn_wan in pairs(WANIF) do
                    iptables("filter", string.format("-A FORWARD -i %s -o %s %s",
                        ifn, ifn_wan, input))
                    iptables("filter", string.format("-A FORWARD -i %s -o %s %s",
                        ifn_wan, ifn, output))
                end
            end
        end
    end
end

------------------------------------------------------------------------------
--
-- RunOneToOneNat
--
-- This function enables 1:1 NAT for a particular host on your private network.
-- You will need to have one or more additional public IP addresses from you
-- ISP in order to use this feature.
--
-- Two types of 1-to-1 NAT are supported
--
-- Type 1:
-- + You do not require aliased IP addresses on your WAN interface
--
-- Type 2:
-- + You do require aliased IP addresses on your WAN interface
-- + Virtual IP addresses auto-configured (starting at ethX:200)
--
------------------------------------------------------------------------------

function RunOneToOneNat()
    local f
    local ip
    local ifn
    local ifn_lan
    local ifn_wan
    local rule
    local nat_addr = {}
    local r_type
    local r_proto
    local r_addr
    local r_port
    local r_param
    local toip
    local network
    local netmask
    local count = 200
    local t = {}

    if table.getn(WANIF) == 0 then
        echo("Skipping 1-to-1 NAT rules - no active WAN interfaces")
        return
    end

    echo("Running 1-to-1 NAT rules")

    -- Clear any existing IP address aliases above 200 (e.g. eth0:200)
    -- TODO: Investigate if this can be done using iproute2
    for _, ifn in pairs(if_list()) do
        for __, ifn_wan in pairs(WANIF) do
            if string.find(ifn, "^" .. ifn_wan .. ":2[0-9][0-9]$") then
                echo("Resetting 1-to-1 NAT alias: " .. ifn)
                execute(IFCONFIG .. " " .. ifn .. " down 2>/dev/null")
            end
        end
    end

    -- Create IP address aliases for type 2 1-to-1 NAT
    if string.lower(ONE_TO_ONE_NAT_MODE) == "type2" then
        -- Initialize NAT address WAN tables
        --for _, ifn_wan in pairs(WANIF) do
        for _, ifn_wan in pairs(WANIF_CONFIG) do
            nat_addr[ifn_wan] = {}
        end

        -- Multiple WAN IP addresses are listed.
        -- Determine unique IP addresses.
        for _, rule in pairs(RULES) do
            r_type, r_proto, r_addr, r_port, r_param = ExpandRule(rule)
    
            if b_and(r_type, tonumber(os.getenv("FWR_ENABLED"))) ~= 0 and
                b_and(r_type, tonumber(os.getenv("FWR_ONE_TO_ONE"))) ~= 0 and
                b_and(r_type, tonumber(os.getenv("FWR_CUSTOM"))) == 0 then

                ifn_wan = WANIF[1]

                __ = string.find(r_param, "_")

                if __ == 1 then
                    toip = string.sub(r_param, 2)
                elseif __ ~= nil then
                    ifn_wan = string.sub(r_param, 1, __ - 1)
                    toip = string.sub(r_param, __ + 1)
                end

                f = true
                for ___, ip in pairs(nat_addr[ifn_wan]) do
                    if ip == r_addr then
                        f = false; break
                    end
                end

                if f == true then
                    table.insert(nat_addr[ifn_wan], r_addr)
                end
            end
        end

        -- Create aliases
        for __, ifn_wan in pairs(WANIF) do
            count = 200
            ___, netmask, ___, ___ = GetInterfaceInfo(ifn_wan)
--          for ____, ip in pairs(nat_addr[ifn_wan]) do
--              echo("Creating alias IP address for 1-to-1 NAT: " .. ip)
--              execute(string.format("%s %s:%d %s netmask %s up",
--                  IFCONFIG, ifn_wan, count, ip, netmask))
--              count = count + 1
--          end
        end
    end

    -- Run 1-to-1 NAT rules - single port only
    nat_addr = {}

    for _, rule in pairs(RULES) do
        r_type, r_proto, r_addr, r_port, r_param = ExpandRule(rule)

        if b_and(r_type, tonumber(os.getenv("FWR_ENABLED"))) ~= 0 and
            b_and(r_type, tonumber(os.getenv("FWR_ONE_TO_ONE"))) ~= 0 and
            b_and(r_type, tonumber(os.getenv("FWR_CUSTOM"))) == 0 and
            string.len(r_port) ~= 0 then

            ifn_wan = WANIF[1]

            __ = string.find(r_param, "_")

            if __ == 1 then
                toip = string.sub(r_param, 2)
            elseif __ ~= nil then
                ifn_wan = string.sub(r_param, 1, __ - 1)
                toip = string.sub(r_param, __ + 1)
            else
                toip = r_param
            end

            if IsValidInterface(ifn_wan) then
                echo(string.format("Enabling 1:1 NAT %s %s - %s %s %s",
                    ifn_wan, toip, r_addr, p_name(r_proto), r_port))

                f = true
                for __, ip in pairs(nat_addr) do
                    if ip == toip then
                        f = false; break
                    end
                end

                if f == true then
                    table.insert(nat_addr, toip)

                    -- Allow certain ICMP services
                    iptables("nat",
                        string.format("-A POSTROUTING -s %s -j SNAT --to %s", toip, r_addr))
                    iptables("filter",
                        string.format("-A FORWARD -i %s -d %s -p icmp --icmp-type 0 -j %s", ifn_wan, toip, FW_ACCEPT))
                    iptables("filter",
                        string.format("-A FORWARD -i %s -d %s -p icmp --icmp-type 3 -j %s", ifn_wan, toip, FW_ACCEPT))
                    iptables("filter",
                        string.format("-A FORWARD -i %s -d %s -p icmp --icmp-type 8 -j %s", ifn_wan, toip, FW_ACCEPT))
                    iptables("filter",
                        string.format("-A FORWARD -i %s -d %s -p icmp --icmp-type 11 -j %s", ifn_wan, toip, FW_ACCEPT))
                    iptables("filter",
                        string.format("-A FORWARD -i %s -d %s -p icmp -j %s", ifn_wan, toip, FW_DROP))
                end

                -- Maps anything coming from LAN machine to the public IP
                iptables("nat", string.format("-A PREROUTING -p %d -d %s --dport %s -j DNAT --to %s",
                    r_proto, r_addr, r_port, toip))

                for __, ifn_lan in pairs(LANIF) do
                    ip, netmask, network, ___ = GetInterfaceInfo(ifn_lan)

                    -- Lets anything coming from LAN network to use public IP
                    iptables("nat",
                        string.format("-A POSTROUTING -p %d -s %s/%s -d %s --dport %s -j SNAT --to %s",
                            r_proto, network, netmask, toip, r_port, ip))
                end

                iptables("filter", string.format("-A FORWARD -i %s -p %d -d %s --dport %s -j %s",
                    ifn_wan, r_proto, toip, r_port, FW_ACCEPT))
            end
        end
    end

    -- Run 1-to-1 NAT rules - wide open
    for _, rule in pairs(RULES) do
        r_type, r_proto, r_addr, r_port, r_param = ExpandRule(rule)

        if b_and(r_type, tonumber(os.getenv("FWR_ENABLED"))) ~= 0 and
            b_and(r_type, tonumber(os.getenv("FWR_ONE_TO_ONE"))) ~= 0 and
            b_and(r_type, tonumber(os.getenv("FWR_CUSTOM"))) == 0 and
            string.len(r_port) == 0 then

            ifn_wan = WANIF[1]

            __ = string.find(r_param, "_")

            if __ == 1 then
                toip = string.sub(r_param, 2)
            elseif __ ~= nil then
                ifn_wan = string.sub(r_param, 1, __ - 1)
                toip = string.sub(r_param, __ + 1)
            else
                toip = r_param
            end

            if IsValidInterface(ifn_wan) then
                echo(string.format("Enabling 1:1 NAT %s %s - %s", ifn_wan, toip, r_addr))

                iptables("nat", string.format("-A PREROUTING -d %s -j DNAT --to %s",
                    r_addr, toip))

                -- Maps anything coming from LAN machine to the public IP
                iptables("nat", string.format("-A POSTROUTING -s %s -j SNAT --to %s",
                    toip, r_addr))

                for __, ifn_lan in pairs(LANIF) do
                    ip, netmask, network, ___ = GetInterfaceInfo(ifn_lan)

                    -- Lets anything coming from LAN network to use public IP
                    iptables("nat",
                        string.format("-A POSTROUTING -s %s/%s -d %s -j SNAT --to %s",
                            network, netmask, toip, ip))
                end

                iptables("filter", string.format("-A FORWARD -i %s -d %s -j %s", ifn_wan, toip, FW_ACCEPT))
            end
        end
    end
end

------------------------------------------------------------------------------
--
-- RunMasquerading
--
-- Run masquerading for LAN interfaces
--
------------------------------------------------------------------------------

function RunMasquerading()
    local ifn
    local ifn_wan
    local network
    local prefix

    -- Do not masquerade traffic originating from DMZ networks
    -- TODO: This will only catch traffic for the immediate DMZ network,
    -- traffic from other networks behind a DMZ for example, will end up being
    -- masqueraded.
    for _, ifn in pairs(DMZIF) do
        __, __, network, prefix = GetInterfaceInfo(ifn)
        iptables("nat", string.format("-A POSTROUTING -s %s/%s -j ACCEPT",
            network, prefix))
    end

    for _, ifn in pairs(LANIF) do
        if table.getn(WANIF) == 0 then
            if table.getn(WANIF_CONFIG) == 0 then
                echo("Disabling NAT - no active WANS")
            else
                echo(string.format("Enabling standby NAT on WAN/LAN interface %s/%s", WANIF_CONFIG[1], ifn))
                iptables("nat",
                    string.format("-A POSTROUTING -o %s -j MASQUERADE", WANIF_CONFIG[1]))
            end
        elseif MULTIPATH == "off" or table.getn(WANIF) == 1 then
            echo(string.format("Enabling NAT on WAN/LAN interface %s/%s", WANIF[1], ifn))
            iptables("nat",
                string.format("-A POSTROUTING -o %s -j MASQUERADE", WANIF[1]))
        elseif MULTIPATH == "on" then
            for _, ifn_wan in pairs(WANIF) do
                echo(string.format("Enabling NAT on WAN/LAN interface %s/%s", ifn_wan, ifn))
                iptables("nat", string.format("-A POSTROUTING -o %s -j MASQUERADE", ifn_wan))
            end
        end
    end
end

------------------------------------------------------------------------------
--
-- RunForwardingDefaults()
--
-- Run default forwarding rules
--
------------------------------------------------------------------------------

function RunForwardingDefaults()
    local rule
    local r_type
    local r_addr
    local accept_target = FW_ACCEPT

    echo("Running default forwarding rules")

    -- Pass all accepted traffic to the protocol filter (l7-filter)
    if PROTOCOL_FILTERING == "on" then
        accept_target = "l7-filter"
        iptc_create_chain("filter", accept_target)

        for _, rule in pairs(RULES) do
            r_type, __, r_addr, __, __= ExpandRule(rule)

            if b_and(r_type, tonumber(os.getenv("FWR_ENABLED"))) ~= 0 and
                b_and(r_type, tonumber(os.getenv("FWR_L7FILTER_BYPASS"))) ~= 0 then
                iptables("filter", string.format("-A %s -s %s -j %s",
                    accept_target, r_addr, FW_ACCEPT))
                iptables("filter", string.format("-A %s -d %s -j %s",
                    accept_target, r_addr, FW_ACCEPT))
            end
        end

        iptables("filter", string.format("-A %s -j NFQUEUE", accept_target))
    end

    -- Allow already established connections
    iptables("filter", "-A FORWARD -m state --state ESTABLISHED,RELATED -j " .. accept_target)

    -- Allow forwarding on trusted interfaces (! WANIF)
    for _, ifn in pairs(DMZIF) do
        iptables("filter", "-A FORWARD -i " .. ifn .. " -j " .. accept_target)
    end

    for _, ifn in pairs(LANIF) do
        if EGRESS_FILTERING == "off" then
            iptables("filter", "-A FORWARD -i " .. ifn .. " -j " .. accept_target)
        else
            echo("Egress filter enabled, blocking all outgoing traffic (except ICMP) by default")

            __, netmask, network, __= GetInterfaceInfo(ifn)

            iptables("filter",
                string.format("-A FORWARD -p icmp --icmp-type 0 -s %s/%s -j %s", network, netmask, FW_ACCEPT))
            iptables("filter",
                string.format("-A FORWARD -p icmp --icmp-type 8 -s %s/%s -j %s", network, netmask, FW_ACCEPT))
            iptables("filter",
                string.format("-A FORWARD -p icmp --icmp-type 11 -s %s/%s -j %s", network, netmask, FW_ACCEPT))
            iptables("filter",
                string.format("-A FORWARD -s %s/%s -j %s", network, netmask, FW_DROP))
        end
    end

    -- Allow VPN interfaces
    iptables("filter", "-A FORWARD -i pptp+ -j " .. accept_target)
    iptables("filter", "-A FORWARD -i tun+ -j " .. accept_target)
end

------------------------------------------------------------------------------
--
-- RunForwardingDmz()
--
-- Run default forwarding rules for a DMZ
--
------------------------------------------------------------------------------

function RunForwardingDmz()
    echo("Running default DMZ rules")

    for _, ifn in pairs(DMZIF) do
        __, __, network, prefix = GetInterfaceInfo(ifn)

        -- Proxy ARP mode - only 1 DMZ interface supported!
        for ___, ifn_wan in pairs(WANIF) do
            ____, ____, xnetwork, xprefix = GetInterfaceInfo(ifn_wan)

            if xnetwork == network and xprefix == prefix then
                echo("Detected proxy ARP mode")

                execute(SYSCTL .. " -w net.ipv4.conf." .. ifn_wan .. ".proxy_arp=1 >/dev/null")
                execute(SYSCTL .. " -w net.ipv4.conf." .. ifn .. ".proxy_arp=1 >/dev/null")

                -- Add route to proxy-arped interfaces
                execute(string.format("%s route add %s/%s dev %s 2>/dev/null",
                    IPBIN, network, prefix, ifn))
                execute(string.format("%s route add %s/%s dev %s 2>/dev/null",
                    IPBIN, network, prefix, ifn_wan))

                -- Add IP route
                execute(string.format("%s route add %s dev %s 2>/dev/null",
                    IPBIN, if_address(ifn_wan), ifn_wan))
                execute(string.format("%s route add %s dev %s 2>/dev/null",
                    IPBIN, if_address(ifn_wan), ifn))

                -- Add gateway route
                execute(string.format("%s route add %s dev %s 2>/dev/null",
                    IPBIN, GetInterfaceGateway(ifn_wan), ifn_wan))
            end
        end

        -- Allow ICMP from DMZ to anywhere and anywhere to DMZ
        iptables("filter",
            string.format("-A FORWARD -s %s/%s -p icmp --icmp-type 0 -j %s",
            network, prefix, FW_ACCEPT))
        iptables("filter",
            string.format("-A FORWARD -d %s/%s -p icmp --icmp-type 0 -j %s",
            network, prefix, FW_ACCEPT))
        iptables("filter",
            string.format("-A FORWARD -s %s/%s -p icmp --icmp-type 3 -j %s",
            network, prefix, FW_ACCEPT))
        iptables("filter",
            string.format("-A FORWARD -d %s/%s -p icmp --icmp-type 3 -j %s",
            network, prefix, FW_ACCEPT))
        -- This allows any host on the DMZ to ping anyone (including hosts on the LAN)
        iptables("filter",
            string.format("-A FORWARD -s %s/%s -p icmp --icmp-type 8 -j %s",
            network, prefix, FW_ACCEPT))
        -- This allows any host (from anywhere) to ping hosts on the DMZ
        iptables("filter",
            string.format("-A FORWARD -d %s/%s -p icmp --icmp-type 8 -j %s",
            network, prefix, FW_ACCEPT))
        iptables("filter",
            string.format("-A FORWARD -s %s/%s -p icmp --icmp-type 11 -j %s",
            network, prefix, FW_ACCEPT))
        iptables("filter",
            string.format("-A FORWARD -d %s/%s -p icmp --icmp-type 11 -j %s",
            network, prefix, FW_ACCEPT))
        iptables("filter",
            string.format("-A FORWARD -s %s/%s -p icmp -j %s", network, prefix, FW_DROP))
        iptables("filter",
            string.format("-A FORWARD -d %s/%s -p icmp -j %s", network, prefix, FW_DROP))

        -- Allow traffic from the LAN to the DMZ, but not the other way
        -- Add DMZ pinhole rules to allow specific traffic the other way
        dnetwork = network
        dprefix = prefix

        for ___, ifn in pairs(LANIF) do
            ____, ____, network, prefix = GetInterfaceInfo(ifn)

            iptables("filter",
                string.format("-A FORWARD -s %s/%s -d %s/%s -m state --state ESTABLISHED,RELATED -j %s",
                dnetwork, dprefix, network, prefix, FW_ACCEPT))
            iptables("filter",
                string.format("-A FORWARD -s %s/%s -d %s/%s -j %s", dnetwork, dprefix, network, prefix,
                FW_DROP))
            iptables("filter",
                string.format("-A FORWARD -s %s/%s -d %s/%s -j %s", network, prefix, dnetwork, dprefix,
                FW_ACCEPT))
        end 
    end
end

------------------------------------------------------------------------------
--
-- RunMultipath
--
-- Send outbound packets to more than one default route depending on the set
-- "weight".  Requires more than one external interface.  Also, we create any
-- source-based and destination port rules.
--
------------------------------------------------------------------------------

function RunMultipath()
    local ifn
    local i
    local t = 100
    local mark = tonumber("0x8000")
    local hops = ""
    local ip
    local netmask
    local network
    local prefix
    local ifn_weight
    local ifn_dmz
    local dmz_ip
    local dmz_prefix
    local dmz_network
    local weight
    local rule
    local r_type
    local r_proto
    local r_addr
    local r_port
    local r_param

    -- Remove rules
    execute(IPBIN .. " rule | grep -Ev '(local|main|default)' | " ..
        "while read PRIO RULE; do " .. IPBIN .. " rule del prio ${PRIO%%:*} 2>/dev/null; done")
    execute(IPBIN .. " rule | grep -Ev '(local|main|default)' | " ..
        "while read PRIO RULE; do " .. IPBIN .. " rule del $RULE prio ${PRIO%%:*} 2>/dev/null; done")
    execute(IPBIN .. " route flush table 50")

    if MULTIPATH ~= "on" or table.getn(WANIF) < 2 then
        -- Flush cached routes so our changes will take effect
        execute(IPBIN .. " route flush cache")
        return
    end

    echo("Running Multi-path routing")

    -- Sort WAN interfaces
    table.sort(WANIF)

    -- Create high-priority "main" rule
    execute(IPBIN .. " rule add prio 50 table 50")

    -- Create new marking rules
    for _, ifn in pairs(WANIF) do
        execute(string.format("%s rule add prio %d fwmark 0x%04x table %d",
            IPBIN, t, mark, t))

        t = t + 1
        mark = mark + 1
    end

    -- Setup multipath routing tables
    mr_init = assert(loadfile("/usr/clearos/apps/firewall/deploy/libmultipath.lua"))
    mr_init()
    RunMultipathRouting()

    -- Create new interface rules and tables
    t = 200
    for _, ifn in pairs(WANIF) do
        ip, netmask, network, prefix = GetInterfaceInfo(ifn)

        execute(string.format("%s route flush table %d", IPBIN, t))
        execute(string.format("%s rule add prio %d from %s/%s table %d",
            IPBIN, t, ip, prefix, t))
        execute(string.format("%s route add default via %s dev %s src %s proto static table %d",
            IPBIN, GetInterfaceGateway(ifn), ifn, ip, t))
        execute(string.format("%s route append prohibit default table %d metric 1 proto static",
            IPBIN, t))

        t = t + 1
    end

    -- Create multipath table
    t = 250
    execute(IPBIN .. " rule add prio " .. t .. " table " .. t)

    for _, ifn in pairs(WANIF) do
        for __, i in pairs(MULTIPATH_WEIGHTS) do
            ___, ___, ifn_weight, weight = string.find(i, "(%w+)|(%w+)")
            if ifn == ifn_weight then break else weight = 1 end
        end

        -- Add gateway to hop list
        hops = string.format("%s nexthop via %s dev %s weight %d",
            hops, GetInterfaceGateway(ifn), ifn, weight)
    end

    execute(IPBIN .. " route flush table " .. t)
    execute(IPBIN .. " route add default table " .. t .. " proto static " .. hops)

    -- Create interface chains
    mark = tonumber("0x8000")
    for _, ifn in pairs(WANIF) do
        iptc_create_chain("mangle", string.format("MULTIWAN_%s", ifn))
        iptables("mangle", string.format("-A MULTIWAN_%s -j MARK --set-mark 0x%04x",
            ifn, mark))
        iptables("mangle", string.format("-A POSTROUTING -o %s -j CONNMARK --set-mark 0x%04x",
            ifn, mark))

        -- TODO: This is a temporary fix for DMZ networks on MultiWAN systems.
        -- Because this is a hack, it will interfer with the bandwidth shaper!
        -- See old bug #626
        if FW_MODE == "dmz" then
            iptables("mangle", string.format("-A PREROUTING -i %s -m state --state NEW -j CONNMARK --set-mark 0x%04x",
                ifn, mark))
        end

        mark = mark + 1
    end

    iptc_create_chain("mangle", "MULTIWAN_MARK")
    iptc_create_chain("mangle", "MULTIWAN_RESTORE")

    iptables("mangle", "-A MULTIWAN_RESTORE -j CONNMARK --restore-mark")

    for _, ifn in pairs(LANIF) do
        iptables("mangle",
            string.format("-A PREROUTING -i %s -m state --state NEW -j MULTIWAN_MARK", ifn))
        iptables("mangle",
            string.format("-A PREROUTING -i %s -m state --state RELATED,ESTABLISHED -j MULTIWAN_RESTORE", ifn))
    end

    for _, ifn in pairs(DMZIF) do
        iptables("mangle",
            string.format("-A PREROUTING -i %s -m state --state NEW -j MULTIWAN_MARK", ifn))
        iptables("mangle",
            string.format("-A PREROUTING -i %s -m state --state RELATED,ESTABLISHED -j MULTIWAN_RESTORE", ifn))
    end

    -- Add MultiWAN routing rules
    for _, rule in pairs(RULES) do
        r_type, r_proto, r_addr, r_port, r_param = ExpandRule(rule)

        if b_and(r_type, tonumber(os.getenv("FWR_ENABLED"))) ~= 0 and
            (b_and(r_type, tonumber(os.getenv("FWR_SBR_PORT"))) ~= 0 or
            b_and(r_type, tonumber(os.getenv("FWR_SBR_HOST"))) ~= 0) and
            IsValidInterface(r_param) ~= false then

            -- Destination port rule
            if b_and(r_type, tonumber(os.getenv("FWR_SBR_PORT"))) ~= 0 then
                echo(string.format("Adding destination port rule: %s %s -> %s (%s)",
                    r_port, p_name(r_proto), if_address(r_param), r_param))

                for __, ifn in pairs(LANIF) do
                    ____, ____, network, prefix = GetInterfaceInfo(ifn)

                    if table.getn(DMZIF) == 0 then
                        iptables("mangle",
                            string.format("-A MULTIWAN_MARK -s %s/%s -p %d --dport %s -j MULTIWAN_%s",
                            network, prefix, r_proto, r_port, r_param))
                    else
                        for ___, ifn_dmz in pairs(DMZIF) do
                            ____, ____, dmz_network, dmz_prefix = GetInterfaceInfo(ifn_dmz)

                            iptables("mangle",
                                string.format("-A MULTIWAN_MARK -s %s/%s ! -d %s/%s -p %d --dport %s -j MULTIWAN_%s",
                                network, prefix, dmz_network, dmz_prefix, r_proto, r_port, r_param))
                        end
                    end
                end
            -- Source-based route rule
            else
                echo(string.format("Adding source-based route rule: %s -> %s (%s)",
                    r_addr, if_address(r_param), r_param))

                if table.getn(DMZIF) == 0 then
                    iptables("mangle",
                        string.format("-A MULTIWAN_MARK -s %s -j MULTIWAN_%s", r_addr, r_param))
                else
                    for __, ifn_dmz in pairs(DMZIF) do
                        ___, ___, dmz_network, dmz_prefix = GetInterfaceInfo(ifn_dmz)

                        iptables("mangle",
                            string.format("-A MULTIWAN_MARK -s %s ! -d %s/%s -j MULTIWAN_%s",
                            r_addr, dmz_network, dmz_prefix, r_param))
                    end
                end
            end
        end
    end

    -- Flush cached routes so our changes take effect immediately
    execute(IPBIN .. " route flush cache")
end

------------------------------------------------------------------------------
--
-- F I R E W A L L S
--
------------------------------------------------------------------------------

------------------------------------------------------------------------------
--
-- T R U S T E D  S T A N D A L O N E
--
-- A "trusted standalone" firewall isn't a firewall at all.  All traffic is
-- allowed in and out of the machine.  Use this mode for machines runnong on
-- a local network.
--
------------------------------------------------------------------------------

function TrustedStandAlone()
    echo("Using trusted standalone mode (no firewall)")

    UnloadNatKernelModules()
    LoadKernelModules()
    SetPolicyToAccept()
    DefineChains()
    RunCustomRules()
    RunProxyPorts()
end

------------------------------------------------------------------------------
--
-- S T A N D A L O N E
--
-- A "standalone" firewall is designed for a server that sits on the Internet
-- (or an untrusted LAN).  Allowed ports must be defined in: /etc/firewall
--
------------------------------------------------------------------------------

function StandAlone()
    echo("Using standalone mode")

    UnloadNatKernelModules()
    LoadKernelModules()
    SetPolicyToDrop()
    DefineChains()
    RunBlockedHosts()
    RunCustomRules()
    RunCommonRules()
    RunIncomingDenied()
    RunIncomingAllowed()
    RunIncomingAllowedDefaults()
    RunProxyPorts()
end

------------------------------------------------------------------------------
--
-- G A T E W A Y
--
------------------------------------------------------------------------------

function Gateway()
    local ifn
    local ifn_lan
    local network
    local prefix

    echo("Using gateway mode")

    LoadKernelModules()
    LoadNatKernelModules()
    SetPolicyToDrop()
    DefineChains()
    RunBlockedHosts()
    RunCustomRules()
    RunCommonRules()
    RunIncomingDenied()
    RunIncomingAllowed()
    RunIncomingAllowedDefaults()
    RunPortForwardRules()
    RunBandwidthRules()
    RunOneToOneNat()
    RunProxyPorts()
    RunMultipath()
    RunMasquerading()
    RunOutgoingDenied()
    RunForwardingDefaults()
end

------------------------------------------------------------------------------
--
-- T R U S T E D  G A T E W A Y
--
------------------------------------------------------------------------------

function TrustedGateway()
    local ifn
    local ifn_lan
    local network
    local prefix

    echo("Using trusted gateway mode")

    UnloadNatKernelModules()
    LoadKernelModules()
    SetPolicyToAccept()
    DefineChains()
    RunCustomRules()
    RunBandwidthRules()
    RunMultipath()
end

------------------------------------------------------------------------------
--
-- D M Z
--
------------------------------------------------------------------------------

function Dmz()
    local f
    local ifn
    local ifn_wan
    local ip
    local line
    local ip_gw
    local network
    local prefix
    local xnetwork
    local xprefix
    local dnetwork
    local dprefix

    echo("Using dmz mode")

    LoadKernelModules()
    -- TODO: NAT may not be required on a DMZ sans LAN
    LoadNatKernelModules()
    SetPolicyToDrop()
    DefineChains()
    RunBlockedHosts()
    RunCustomRules()
    RunCommonRules()
    RunIncomingDenied()
    RunIncomingAllowed()
    RunIncomingAllowedDefaults()
    RunPortForwardRules()
    RunBandwidthRules()
    RunDmzPinhole()
    RunDmzIncoming()
    RunOneToOneNat()
    RunProxyPorts()
    RunMultipath()
    RunMasquerading()
    RunForwardingDmz()
    RunOutgoingDenied()
    RunForwardingDefaults()
end

------------------------------------------------------------------------------
--
-- ShowFirewallMode
--
------------------------------------------------------------------------------

function ShowFirewallMode()
    local ifn
    local ip, netmask, network, prefix

    -- WAN info
    for _, ifn in pairs(WANIF) do
        ip, netmask, network, prefix = GetInterfaceInfo(ifn)

        echo(string.format("Detected WAN info - %s %s on network %s/%s",
            ifn, ip, network, prefix))
    end

    -- LAN info
    if FW_MODE ~= "standalone" and FW_MODE ~= "trustedstandalone" then
        for _, ifn in pairs(LANIF) do
            ip, netmask, network, prefix = GetInterfaceInfo(ifn)

            echo(string.format("Detected LAN info - %s %s on network %s/%s",
                ifn, ip, network, prefix))
        end
    end

    -- DMZ info
    for _, ifn in pairs(DMZIF) do
        ip, netmask, network, prefix = GetInterfaceInfo(ifn)

        echo(string.format("Detected DMZ info - %s %s on network %s/%s",
            ifn, ip, network, prefix))
    end
end

------------------------------------------------------------------------------
--
-- M A I N
--
-- Start the firewall
--
------------------------------------------------------------------------------

echo("Starting firewall...")

-- Initialize IP tables
iptc_init()

-- Load external firewall initialization routines
firewall_init = assert(loadfile("/usr/clearos/apps/firewall/deploy/libfirewall.lua"))
firewall_init();

LoadEnvironment()
NetworkInterfaces()
ResolveRules()
SetKernelSettings()
ShowFirewallMode()

if FW_MODE == "gateway" then Gateway()
elseif FW_MODE == "trustedgateway" then TrustedGateway()
elseif FW_MODE == "standalone" then StandAlone()
elseif FW_MODE == "trustedstandalone" then TrustedStandAlone()
elseif FW_MODE == "dmz" then Dmz()
else error("Invalid firewall mode: " .. FW_MODE) end

-- Commit changes
for _, t in pairs(TABLES) do iptc_commit(t) end

-- vi: syntax=lua ts=4
