<?php

/**
 * Firewall rule class.
 *
 * @category   Apps
 * @package    Firewall
 * @subpackage Libraries
 * @author     ClearFoundation <developer@clearfoundation.com>
 * @copyright  2004-2011 ClearFoundation
 * @license    http://www.gnu.org/copyleft/lgpl.html GNU Lesser General Public License version 3 or later
 * @link       http://www.clearfoundation.com/docs/developer/apps/firewall/
 */

///////////////////////////////////////////////////////////////////////////////
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
///////////////////////////////////////////////////////////////////////////////
//
// TODO: many of the methods use ConvertProtocolName().  That's fine, but it
// is now possible to create a firewall with protocol GRE and port 123.  That
// is non-sensical.  Handle this validation issue in a sane way.
//
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// N A M E S P A C E
///////////////////////////////////////////////////////////////////////////////

namespace clearos\apps\firewall;

///////////////////////////////////////////////////////////////////////////////
// B O O T S T R A P
///////////////////////////////////////////////////////////////////////////////

$bootstrap = getenv('CLEAROS_BOOTSTRAP') ? getenv('CLEAROS_BOOTSTRAP') : '/usr/clearos/framework/shared';
require_once $bootstrap . '/bootstrap.php';

///////////////////////////////////////////////////////////////////////////////
// T R A N S L A T I O N S
///////////////////////////////////////////////////////////////////////////////

clearos_load_language('firewall');

///////////////////////////////////////////////////////////////////////////////
// D E P E N D E N C I E S
///////////////////////////////////////////////////////////////////////////////

// Classes
//--------

use \clearos\apps\base\Engine as Engine;
use \clearos\apps\firewall\Firewall as Firewall;
use \clearos\apps\firewall\Rule as Rule;

clearos_load_library('base/Engine');
clearos_load_library('firewall/Firewall');
clearos_load_library('firewall/Rule');

// Exceptions
//-----------

use \clearos\apps\base\Validation_Exception as Validation_Exception;
use \clearos\apps\firewall\Firewall_Invalid_Rule_Exception as Firewall_Invalid_Rule_Exception;

clearos_load_library('base/Validation_Exception');
clearos_load_library('firewall/Firewall_Invalid_Rule_Exception');

///////////////////////////////////////////////////////////////////////////////
// C L A S S
///////////////////////////////////////////////////////////////////////////////

/**
 * Firewall rule class.
 *
 * @category   Apps
 * @package    Firewall
 * @subpackage Libraries
 * @author     ClearFoundation <developer@clearfoundation.com>
 * @copyright  2004-2011 ClearFoundation
 * @license    http://www.gnu.org/copyleft/lgpl.html GNU Lesser General Public License version 3 or later
 * @link       http://www.clearfoundation.com/docs/developer/apps/firewall/
 */

class Rule extends Engine
{
    ///////////////////////////////////////////////////////////////////////////
    // C O N S T A N T S
    ///////////////////////////////////////////////////////////////////////////

    const INCOMING_ALLOW    = 0x00000001;    // Incoming allow; port/port range
    const INCOMING_BLOCK    = 0x00000002;    // Incoming block; host
    const OUTGOING_BLOCK    = 0x00000004;    // Outgoing block; host, port/range
    const FORWARD           = 0x00000008;    // Forward; port/port range
    const DMZ_PINHOLE       = 0x00000010;    // DMZ pinhole; host/port
    const DMZ_INCOMING      = 0x00000020;    // DMZ incoming; host/port
    const RESERVED_0        = 0x00000040;    // Reserved
    const ONE_TO_ONE        = 0x00000080;    // One-to-one NAT
    const PPTP_FORWARD      = 0x00000100;    // PPTP forward rule
    const MAC_FILTER        = 0x00000200;    // HW/MAC filter rule
    const SBR_PORT          = 0x00000400;    // SBR: by port
    const SBR_HOST          = 0x00000800;    // SBR: by host
    const BANDWIDTH_RATE    = 0x00001000;    // Bandwidth rate rule
    const BANDWIDTH_PRIO    = 0x00002000;    // Bandwidth priority rule
    const BANDWIDTH_BASIC   = 0x00004000;    // "Basic" bandwidth rule
    const RESERVED_1        = 0x00008000;    // Reserved
    const RESERVED_2        = 0x00010000;    // Reserved
    const RESERVED_3        = 0x00020000;    // Reserved
    const RESERVED_4        = 0x00040000;    // Reserved
    const RESERVED_5        = 0x00080000;    // Reserved
    const LOCAL_NETWORK     = 0x00100000;    // Create rule for local networks
    const EXTERNAL_ADDR     = 0x00200000;    // Create rule for external addr
    const PROXY_BYPASS      = 0x00400000;    // Web Proxy Bypass
    const L7FILTER_BYPASS   = 0x00800000;    // Layer7 Filter Bypass
    const MAC_SOURCE        = 0x01000000;    // HW/MAC source address
    const WIFI              = 0x02000000;    // Wireless rule
    const IFADDRESS         = 0x04000000;    // Interface address 'addr' field
    const IFNETWORK         = 0x08000000;    // Interface network 'addr' field
    const ENABLED           = 0x10000000;    // Rule is enabled
    const CUSTOM            = 0x20000000;    // Custom rule
    const RESERVED_6        = 0x40000000;    // Reserved
    const RESERVED_7        = 0x80000000;    // Do not use this bit!

    ///////////////////////////////////////////////////////////////////////////
    // V A R I A B L E S
    ///////////////////////////////////////////////////////////////////////////

    protected $name = NULL;
    protected $group = NULL;
    protected $flags = NULL;
    protected $proto = NULL;
    protected $addr = NULL;
    protected $port = NULL;
    protected $param = NULL;

    ///////////////////////////////////////////////////////////////////////////
    // M E T H O D S
    ///////////////////////////////////////////////////////////////////////////

    public function __construct()
    {
        clearos_profile(__METHOD__, __LINE__);

        $this->reset();
    }

    /**
     * resets class field members to default state.
     *
     * @return void
     */

    public function reset()
    {
        clearos_profile(__METHOD__, __LINE__);

        $this->name = '';
        $this->group = '';
        $this->flags = 0;
        $this->proto = Firewall::PROTOCOL_IP;
        $this->addr = '';
        $this->port = '';
        $this->param = '';
    }

    /**
     * Return validated rule in packed format.
     *
     * Rule format, 7 fields with a pipe '|' delimiter:
     * name|group|flags|proto|addr|port|param
     *
     * @return string valid rule in packed format
     */

    public function get_rule()
    {
        clearos_profile(__METHOD__, __LINE__);

        $rule = new Rule();

        // Validate member data
        $rule->set_rule(sprintf("%s|%s|0x%08x|%d|%s|%s|%s",
            $this->name, $this->group, $this->flags, $this->proto,
            $this->addr, $this->port, $this->param));

        return sprintf("%s|%s|0x%08x|%d|%s|%s|%s",
            $this->name, $this->group, $this->flags,
            $this->proto, $this->addr, $this->port, $this->param);
    }

    /**
     * Set class members from packed format input.
     *
     * Rule format, 7 fields seperated by a pipe '|' delimiter:
     * name|group|flags|proto|addr|port|param
     *
     * @param string $input Packed firewall rule
     *
     * @return void
     * @throws Firewall_Invalid_Rule_Exception
     */

    public function set_rule($input)
    {
        clearos_profile(__METHOD__, __LINE__);

        $this->reset();

        $parts = explode("|", $input);

        // Check field count
        if (sizeof($parts) != 7)
            throw new Firewall_Invalid_Rule_Exception();

        // Name
        if (strlen($parts[0])) $this->set_name($parts[0]);

        // Group name
        if (strlen($parts[1])) $this->set_group($parts[1]);

        // Flags (4-byte bitmask)
        $flags = 0;
        if (!sscanf($parts[2], "0x%08x", $flags))
            throw new Firewall_Invalid_Rule_Exception();

        $this->set_flags($flags);

        // Protocol (integer, see /etc/protocols)
        $this->set_protocol($parts[3]);

        // Address (Hostname, IPv4, IPv6(at some point), MAC/HW)
        if (strlen($parts[4])) $this->set_address($parts[4]);

        // Port address - TCP/UDP protocols only
        if (strlen($parts[5])) {
            if (strstr($parts[5], ":")) {
                list($from, $to) = explode(":", $parts[5]);
                $this->set_port_range($from, $to);
            } else {
                $this->set_port($parts[5]);
            }
        }

        // Optional rule parameter
        if (strlen($parts[6])) $this->set_parameter($parts[6]);
    }

    /**
     * Get rule name.
     *
     *
     * @return string Rule name
     */

    public function get_name()
    {
        clearos_profile(__METHOD__, __LINE__);

        return $this->name;
    }

    /**
     * Set rule name.
     *
     * @param string $name firewall name value
     *
     * @return void
     */

    public function set_name($name)
    {
        clearos_profile(__METHOD__, __LINE__);

        Validation_Exception::is_valid($this->validate_name($name));

        $this->name = $name;
    }

    /**
     * Returns rule group name.
     *
     * @return string firewall group name
     */

    public function get_group()
    {
        clearos_profile(__METHOD__, __LINE__);

        return $this->group;
    }

    /**
     * Sets rule group name.
     *
     * @param string $group firewall group name
     *
     * @return void
     */

    public function set_group($group)
    {
        clearos_profile(__METHOD__, __LINE__);

        Validation_Exception::is_valid($this->validate_group($group));

        $this->group = $group;
    }

    /**
     * Returns type description.
     *
     * @return string a description of the type of rule
     */

    public function get_type_text()
    {
        clearos_profile(__METHOD__, __LINE__);

        // TODO: This is a temporary workaround - an end user will see 
        // something that makes sense for "outgoing" rules when egress mode
        // is enabled.

        $egressstate = FALSE;

        if (file_exists(COMMON_CORE_DIR . "/api/FirewallOutgoing.class.php")) {
            require_once(COMMON_CORE_DIR . "/api/FirewallOutgoing.class.php");
            $outgoingfw = new FirewallOutgoing();
            $egressstate = $outgoingfw->GetEgressState();
        }

        if ($this->flags & Rule::INCOMING_ALLOW)
            $type = FIREWALLRULE_LANG_TYPE_INCOMING_ALLOW;
        else if ($this->flags & Rule::INCOMING_BLOCK)
            $type = FIREWALLRULE_LANG_TYPE_INCOMING_BLOCK;
        else if ($this->flags & Rule::OUTGOING_BLOCK)
            $type = ($egressstate) ? FIREWALLRULE_LANG_TYPE_OUTGOING_ALLOW : FIREWALLRULE_LANG_TYPE_OUTGOING_BLOCK;
        else if ($this->flags & Rule::FORWARD)
            $type = FIREWALLRULE_LANG_TYPE_PORT_FORWARD;
        else if ($this->flags & Rule::DMZ_PINHOLE)
            $type = FIREWALLRULE_LANG_TYPE_DMZ_PINHOLE;
        else if ($this->flags & Rule::DMZ_INCOMING)
            $type = FIREWALLRULE_LANG_TYPE_DMZ_INCOMING;
        else if ($this->flags & Rule::ONE_TO_ONE)
            $type = FIREWALLRULE_LANG_TYPE_ONE_TO_ONE_NAT;
        else if ($this->flags & Rule::PPTP_FORWARD)
            $type = FIREWALLRULE_LANG_TYPE_PORT_FORWARD;
        else if ($this->flags & Rule::MAC_FILTER)
            $type = FIREWALLRULE_LANG_TYPE_MAC_FILTER_ALLOW;
        else if ($this->flags & Rule::SBR_PORT)
            $type = FIREWALLRULE_LANG_TYPE_MULTIWAN_SOURCE_BASE_ROUTE;
        else if ($this->flags & Rule::SBR_HOST)
            $type = FIREWALLRULE_LANG_TYPE_MULTIWAN_DESTINATION_PORT;
        else if ($this->flags & Rule::BANDWIDTH_RATE)
            $type = FIREWALLRULE_LANG_TYPE_BANDWIDTH;
        else if ($this->flags & Rule::BANDWIDTH_PRIO)
            $type = FIREWALLRULE_LANG_TYPE_BANDWIDTH;
        else if ($this->flags & Rule::PROXY_BYPASS)
            $type = FIREWALLRULE_LANG_TYPE_PROXY_BYPASS;
        else if ($this->flags & Rule::L7FILTER_BYPASS)
            $type = FIREWALLRULE_LANG_TYPE_L7FILTER_BYPASS;
        else
            $type = LOCALE_LANG_UNKNOWN;

        return $type;
    }

    /**
     * Is rule enabled?
     *
     * @return boolean TRUE if rule is enabled, FALSE otherwise
     */

    public function is_enabled()
    {
        clearos_profile(__METHOD__, __LINE__);

        return $this->flags & Rule::ENABLED;
    }

    /**
     * Enables rule.
     *
     * @return boolean previous rule state
     */

    public function enable()
    {
        clearos_profile(__METHOD__, __LINE__);

        $was = ($this->flags & Rule::ENABLED) ? TRUE : FALSE;
        $this->flags |= Rule::ENABLED;

        return $was;
    }

    /**
     * Disables rule.
     *
     * @return boolean previous rule state
     */

    public function disable()
    {
        clearos_profile(__METHOD__, __LINE__);

        $was = ($this->flags & Rule::ENABLED) ? TRUE : FALSE;
        $this->flags &= ~Rule::ENABLED;

        return $was;
    }

    /**
     * Returns rule type and flags.
     *
     * @return integer rule flags
     */

    public function get_flags()
    {
        clearos_profile(__METHOD__, __LINE__);

        return $this->flags;
    }

    /**
     * Sets rule type and flags.
     *
     * @param int $flags rule flags
     *
     * @return void
     */

    public function set_flags($flags)
    {
        clearos_profile(__METHOD__, __LINE__);

        Validation_Exception::is_valid($this->validate_flags($flags));

        $this->flags = $flags;
    }

    /**
     * Returns rule protocol.
     *
     * @return integer protocol
     */

    public function get_protocol()
    {
        clearos_profile(__METHOD__, __LINE__);

        return $this->proto;
    }

    /**
     * Returns rule protocol.
     *
     * @return integer protocol
     */

    public function get_protocol_name()
    {
        clearos_profile(__METHOD__, __LINE__);

        $firewall = new Firewall();

        $protocols = $firewall->get_protocols();

        return $protocols[$this->proto];
    }

    /**
     * Set rule protocol.
     *
     * @param integer $protocol protocol number
     *
     * @return void
     */

    public function set_protocol($protocol)
    {
        clearos_profile(__METHOD__, __LINE__);

        Validation_Exception::is_valid($this->validate_protocol($protocol));

        if ($protocol == Firewall::PROTOCOL_ALL)
            return;

        $this->proto = $protocol;
    }

    /**
     * Get rule address.
     *
     * return string address Rule address
     */

    public function get_address()
    {
        clearos_profile(__METHOD__, __LINE__);

        return $this->addr;
    }

    /**
     * Set rule address.
     *
     * @param string $address rule address
     *
     * @return void
     */

    public function set_address($address)
    {
        clearos_profile(__METHOD__, __LINE__);

        Validation_Exception::is_valid($this->validate_address($address));

        $this->addr = $address;
    }

    /**
     * Returns rule port.
     *
     * @return integer port address
     */

    public function get_port()
    {
        clearos_profile(__METHOD__, __LINE__);

        return $this->port;
    }


    /**
     * Sets rule port.
     *
     * @param integer $port port address
     *
     * @return void
     */

    public function set_port($port)
    {
        clearos_profile(__METHOD__, __LINE__);

        Validation_Exception::is_valid($this->validate_port($port));

        if (gettype($port == "integer") && $port == Firewall::CONSTANT_ALL_PORTS)
            $this->port = '';
        else
            $this->port = trim($port);
    }

    /**
     * Sets rule port range.
     *
     * @param integer $from from port
     * @param integer $to   to port
     *
     * @return void
     */

    public function set_port_range($from, $to)
    {
        clearos_profile(__METHOD__, __LINE__);

        // Validation_Exception::is_valid($this->validate_port_rnage($from, $to));

        $this->port = trim($from) . ":" . trim($to);
    }

    /**
     * Returns rule parameter value.
     *
     * @return mixed param Rule parameter field
     */

    public function get_parameter()
    {
        clearos_profile(__METHOD__, __LINE__);

        return $this->param;
    }

    /**
     * Sets rule parameter value.
     *
     * @param mixed $val Rule parameter value
     *
     * @return void
     */

    public function set_parameter($val)
    {
        clearos_profile(__METHOD__, __LINE__);

        $this->param = $val;

        // TODO: Is this required somewhere?
        return TRUE;
    }

    /**
     * Returns protocol flag for given protocol name.
     *
     * @param string $protocol protocol name
     *
     * @return flag protocol flag
     */

    public function convert_protocol_name($protocol)
    {
        clearos_profile(__METHOD__, __LINE__);

        $firewall = new Firewall();

        return $firewall->convert_protocol_name($protocol);
    }

    ///////////////////////////////////////////////////////////////////////////
    // C O M P A R I S O N
    ///////////////////////////////////////////////////////////////////////////

    /**
     * Compare this object with another, return TRUE if equal.
     *
     * @param object $val Rule object to compare against
     *
     * @return boolean True if objects are equal
     */

    public function is_equal($val)
    {
        clearos_profile(__METHOD__, __LINE__);

        if (!($val instanceof Rule)) return FALSE;

        $equal = TRUE;
        $flags = $val->flags;

        if ($this->flags & Rule::ENABLED)
            $val->flags |= Rule::ENABLED;
        else
            $val->flags &= ~Rule::ENABLED;

        if ($this->flags & Rule::CUSTOM)
            $val->flags |= Rule::CUSTOM;
        else
            $val->flags &= ~Rule::CUSTOM;

        if ($val->flags != $this->flags) $equal = FALSE;
        if ($val->proto != $this->proto) $equal = FALSE;
        if ($val->addr != $this->addr) $equal = FALSE;
        if ($val->port != $this->port) $equal = FALSE;
        if ($val->param != $this->param) $equal = FALSE;

        $val->flags = $flags;

        return $equal;
    }

    ///////////////////////////////////////////////////////////////////////////
    // V A L I D A T I O N
    ///////////////////////////////////////////////////////////////////////////

    /**
     * Validates rule group.
     *
     * @param string $group rule group
     *
     * @return error message if rule group is invalid
     */

    public function validate_group($group)
    {
        clearos_profile(__METHOD__, __LINE__);

        if (! preg_match('/^[a-zA-Z0-9_\-\.]*$/', $name))
            return lang('firewall_group_invalid');
    }

    /**
     * Validates rule name.
     *
     * @param string $name rule name
     *
     * @return error message if rule name is invalid
     */

    public function validate_name($name)
    {
        clearos_profile(__METHOD__, __LINE__);

        if (! preg_match('/^[a-zA-Z0-9_\-\.]*$/', $name))
            return lang('firewall_name_invalid');
    }

    /**
     * Validates rule flags.
     *
     * @param integer $flags rule flags
     *
     * @return error message if rule flags is invalid
     */

    public function validate_flags($flags)
    {
        clearos_profile(__METHOD__, __LINE__);

        if (!$flags) return FALSE;

        $ex_flag = FALSE;

        if ($flags & Rule::INCOMING_ALLOW) {
            $ex_flag = TRUE;
            $flags &= ~Rule::INCOMING_ALLOW;
        } else if ($flags & Rule::INCOMING_BLOCK) {
            if ($ex_flag) return FALSE; $ex_flag = TRUE;
            $flags &= ~Rule::INCOMING_BLOCK;
        } else if ($flags & Rule::OUTGOING_BLOCK) {
            if ($ex_flag) return FALSE; $ex_flag = TRUE;
            $flags &= ~Rule::OUTGOING_BLOCK;
        } else if ($flags & Rule::FORWARD) {
            if ($ex_flag) return FALSE; $ex_flag = TRUE;
            $flags &= ~Rule::FORWARD;
        } else if ($flags & Rule::DMZ_PINHOLE) {
            if ($ex_flag) return FALSE; $ex_flag = TRUE;
            $flags &= ~Rule::DMZ_PINHOLE;
        } else if ($flags & Rule::DMZ_INCOMING) {
            if ($ex_flag) return FALSE; $ex_flag = TRUE;
            $flags &= ~Rule::DMZ_INCOMING;
        } else if ($flags & Rule::ONE_TO_ONE) {
            if ($ex_flag) return FALSE; $ex_flag = TRUE;
            $flags &= ~Rule::ONE_TO_ONE;
        } else if ($flags & Rule::PPTP_FORWARD) {
            if ($ex_flag) return FALSE; $ex_flag = TRUE;
            $flags &= ~Rule::PPTP_FORWARD;
        } else if ($flags & Rule::MAC_FILTER) {
            if ($ex_flag) return FALSE; $ex_flag = TRUE;
            $flags &= ~Rule::MAC_FILTER;
        } else if ($flags & Rule::SBR_PORT) {
            if ($ex_flag) return FALSE; $ex_flag = TRUE;
            $flags &= ~Rule::SBR_PORT;
        } else if ($flags & Rule::SBR_HOST) {
            if ($ex_flag) return FALSE; $ex_flag = TRUE;
            $flags &= ~Rule::SBR_HOST;
        } else if ($flags & Rule::BANDWIDTH_RATE) {
            if ($ex_flag) return FALSE; $ex_flag = TRUE;
            $flags &= ~Rule::BANDWIDTH_RATE;
        } else if ($flags & Rule::BANDWIDTH_PRIO) {
            if ($ex_flag) return FALSE; $ex_flag = TRUE;
            $flags &= ~Rule::BANDWIDTH_PRIO;
        } else if ($flags & Rule::PROXY_BYPASS) {
            if ($ex_flag) return FALSE; $ex_flag = TRUE;
            $flags &= ~Rule::PROXY_BYPASS;
        } else if ($flags & Rule::L7FILTER_BYPASS) {
            if ($ex_flag) return FALSE; $ex_flag = TRUE;
            $flags &= ~Rule::L7FILTER_BYPASS;
        }

        $flags &= ~Rule::MAC_SOURCE;
        $flags &= ~Rule::WIFI;
        $flags &= ~Rule::ENABLED;
        $flags &= ~Rule::CUSTOM;
        $flags &= ~Rule::BANDWIDTH_BASIC;
        $flags &= ~Rule::LOCAL_NETWORK;
        $flags &= ~Rule::EXTERNAL_ADDR;
        $flags &= ~Rule::IFADDRESS;
        $flags &= ~Rule::IFNETWORK;

        if($flags != 0) return FALSE;

        return TRUE;
    }

    /**
     * Validates protocol.
     *
     * @param string $protocol protocol
     *
     * @return error message if protocol is invalid
     */

    public function validate_protocol($protocol)
    {
        clearos_profile(__METHOD__, __LINE__);

        $firewall = new Firewall();

        return $firewall->validate_protocol($protocol);
    }

    /**
     * Validates address.
     *
     * Is this (hostname, IPv4, and soon IPv6) address valid?
     * localhost || 192.168.0.1 || 192.168.0.1/24 || 192.168.0.1/255.255.255.0 || 192.168.0.1:192.168.1.1
     *
     * TODO: hostname validation should be moved to IsValidHostname
     * TODO: network validation should be moved to IsValidNetwork
     * TODO: this class should extend Network() and use the standard validation
     *
     * @param string $ip hostname, IPv4 address to validate
     *
     * @return error message if address is invalid
     */

    public function validate_address($address)
    {
        clearos_profile(__METHOD__, __LINE__);

        $firewall = new Firewall();

        return $firewall->validate_address($address);
    }

    /**
     * Validates port.
     *
     * @param integer $port port address
     *
     * @return string error message if port is invalid
     */

    public function validate_port($port)
    {
        clearos_profile(__METHOD__, __LINE__);

        $firewall = new Firewall();

        return $firewall->validate_port($port);
    }
}
